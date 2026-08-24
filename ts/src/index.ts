/**
 * Library for decrypting/encrypting RPG Maker MV/MZ audio and image assets.
 *
 * TypeScript port of the `rpgm-asset-decrypter-lib` Rust crate, kept behaviorally identical to that reference
 * implementation. Operates on `Uint8Array` buffers in place wherever possible.
 *
 * @module
 */

const HEX_CHARS = "0123456789abcdef";

export const HEADER_LENGTH = 16;

export const KEY_LENGTH = 16;
export const KEY_STR_LENGTH = 32;

/** Key used in RPG Maker encrypted files when "Encryption key" is left unfilled. */
export const DEFAULT_KEY = "d41d8cd98f00b204e9800998ecf8427e";

// RPG Maker's encoding is essentially taking the source file's header (16 bytes) and xor'ing it with an MD5 key
// produced from the encryption key string. Most projects leave the encryption key string empty, so the resulting
// "encryption" is just the header xor'd with the default MD5 key.

// For PNG, the header is always the same, so we can expect valid decryption.
const PNG_HEADER = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
]);

// 0 - 3 - OggS
// 4 - version, always 0
// 5 - header type, always 0x02, since the first page always announces the beginning of the stream
// 6 - 13 - granule position, always 0, since the first page has no actual data
// 14 - 15 - part of the 4-byte bitstream serial number, which actually differs between files
const OGG_HEADER_TEMPLATE = new Uint8Array([79, 103, 103, 83, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

// 0 - 3 - type box size, actually differs between files
// 4 - 7 - ftyp, always the same
// 8 - 11 - M4A_, always the same, may be different 4 characters, but extremely unlikely
// 12 - 15 - minor version, mostly junk, doesn't matter
const M4A_HEADER_TEMPLATE = new Uint8Array([0, 0, 0, 28, 102, 116, 121, 112, 77, 52, 65, 32, 0, 0, 2, 0]);

// For finding the type box size
const M4A_POST_HEADER_BOXES = ["moov", "mdat", "free", "skip", "wide", "pnot"];

/** Every encrypted file includes this header. */
export const RPGM_HEADER = new Uint8Array([
    0x52, 0x50, 0x47, 0x4d, 0x56, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

export const MV_PNG_EXT = "rpgmvp";
export const MZ_PNG_EXT = "png_";
export const MV_OGG_EXT = "rpgmvo";
export const MZ_OGG_EXT = "ogg_";
export const MV_M4A_EXT = "rpgmvm";
export const MZ_M4A_EXT = "m4a_";

export const PNG_EXT = "png";
export const OGG_EXT = "ogg";
export const M4A_EXT = "m4a";

export const ENCRYPTED_ASSET_EXTS = [MV_PNG_EXT, MV_OGG_EXT, MV_M4A_EXT, MZ_PNG_EXT, MZ_OGG_EXT, MZ_M4A_EXT];
export const DECRYPTED_ASSET_EXTS = [PNG_EXT, OGG_EXT, M4A_EXT];

/** The original, decrypted asset kind. */
export type FileType = "png" | "ogg" | "m4a";

/**
 * Deduces a {@link FileType} from a file extension (with or without a leading dot), accepting both the
 * MV (`rpgmvp`/`rpgmvo`/`rpgmvm`) and MZ (`png_`/`ogg_`/`m4a_`) encrypted extensions.
 *
 * @throws {Error} if `extension` is not a recognized encrypted asset extension.
 */
export function fileTypeFromExtension(extension: string): FileType {
    const ext = extension.startsWith(".") ? extension.slice(1) : extension;

    switch (ext) {
        case MV_PNG_EXT:
        case MZ_PNG_EXT:
            return "png";
        case MV_OGG_EXT:
        case MZ_OGG_EXT:
            return "ogg";
        case MV_M4A_EXT:
        case MZ_M4A_EXT:
            return "m4a";
        default:
            throw new Error("Extension not supported");
    }
}

/** Thrown by {@link Decrypter.encrypt}/{@link Decrypter.encryptInPlace} when no key has been set. */
export class KeyNotSetError extends Error {
    constructor() {
        super("Key must be set using any of `setKey` methods before calling `encrypt` function.");
        this.name = "KeyNotSetError";
    }
}

/** Thrown by {@link Decrypter.setKeyFromStr} when the provided key string isn't 32 characters long. */
export class InvalidKeyLengthError extends Error {
    constructor() {
        super("Key must have a fixed length of 32 characters.");
        this.name = "InvalidKeyLengthError";
    }
}

/** Thrown when passed data doesn't start with {@link RPGM_HEADER}. */
export class InvalidHeaderError extends Error {
    constructor() {
        super(
            "Passed data has invalid header. RPG Maker encrypted files should always start with RPGMV header. " +
                "Either passed data is not RPG Maker data or it's corrupted.",
        );
        this.name = "InvalidHeaderError";
    }
}

/** Thrown when passed data ends before all the bytes needed to determine the key could be read. */
export class UnexpectedEofError extends Error {
    constructor() {
        super("Unexpected end of file encountered. Either passed data is not RPG Maker data or it's corrupted.");
        this.name = "UnexpectedEofError";
    }
}

function bytesStartWith(data: Uint8Array, prefix: Uint8Array): boolean {
    if (data.length < prefix.length) {
        return false;
    }

    for (let i = 0; i < prefix.length; i++) {
        if (data[i] !== prefix[i]) {
            return false;
        }
    }

    return true;
}

function readOggPageSerialNumber(buf: Uint8Array, cursor: { pos: number }): number {
    const HEADER_SIZE = 27;
    const SERIALNO_POS = 14;

    const header = buf.subarray(cursor.pos, cursor.pos + HEADER_SIZE);
    cursor.pos += HEADER_SIZE;

    const segmentCount = header[26]!;

    const segmentTable = buf.subarray(cursor.pos, cursor.pos + 0xff);
    cursor.pos += 0xff;

    const overCount = 0xff - segmentCount;
    cursor.pos -= overCount;

    let bodyLength = 0;
    for (let i = 0; i < segmentCount; i++) {
        bodyLength += segmentTable[i]!;
    }

    cursor.pos += bodyLength;

    return new DataView(header.buffer, header.byteOffset + SERIALNO_POS, 4).getUint32(0, true);
}

/**
 * A struct responsible for decrypting and encrypting RPG Maker MV/MZ assets.
 *
 * `Decrypter` requires a key, which you can set from {@link Decrypter.setKeyFromStr} and
 * {@link Decrypter.setKeyFromFile}. You can get the key string from the `encryptionKey` field in `System.json`, or
 * from any encrypted RPG Maker file.
 *
 * {@link Decrypter.decrypt} will automatically determine the key from the input file, so you usually don't need to
 * set it manually.
 */
export class Decrypter {
    private keyHex = "";
    private keyBytes: Uint8Array = new Uint8Array(KEY_LENGTH);
    private hasKey = false;

    private setKeyFromHex(): void {
        for (let j = 0; j < KEY_LENGTH; j++) {
            this.keyBytes[j] = Number.parseInt(this.keyHex.slice(j * 2, j * 2 + 2), 16);
        }

        this.hasKey = true;
    }

    /** Decrypts or encrypts the passed buffer in place, depending on the caller's intent: xors up to the first 16 bytes with the key. */
    private xorBuffer(buffer: Uint8Array): void {
        const count = Math.min(HEADER_LENGTH, buffer.length);

        for (let i = 0; i < count; i++) {
            buffer[i]! ^= this.keyBytes[i]!;
        }
    }

    /** Returns the decrypter's key, or `undefined` if it's not set. */
    key(): string | undefined {
        return this.hasKey ? this.keyHex : undefined;
    }

    /**
     * Sets the decrypter's key to the provided hex string.
     *
     * @throws {InvalidKeyLengthError} if `key`'s length is not 32 characters.
     */
    setKeyFromStr(key: string): void {
        if (key.length !== KEY_STR_LENGTH) {
            throw new InvalidKeyLengthError();
        }

        this.keyHex = key;
        this.setKeyFromHex();
    }

    /**
     * Sets the key of the decrypter from encrypted `fileContent` data.
     *
     * @param fileContent - The data of an RPG Maker asset file.
     * @param fileType - Whether `fileContent` is a PNG, OGG, or M4A asset.
     * @returns The derived key string.
     * @throws {InvalidHeaderError} if `fileContent` doesn't start with {@link RPGM_HEADER}.
     * @throws {UnexpectedEofError} if `fileContent` ends unexpectedly.
     */
    setKeyFromFile(fileContent: Uint8Array, fileType: FileType): string {
        if (!bytesStartWith(fileContent, RPGM_HEADER)) {
            throw new InvalidHeaderError();
        }

        if (fileContent.length < HEADER_LENGTH * 2) {
            throw new UnexpectedEofError();
        }

        const postHeader = fileContent.subarray(HEADER_LENGTH, HEADER_LENGTH * 2);

        // Get the proper M4A header box size.
        // We don't care about anything else for M4A, since `ftypM4A_` in the M4A header can be easily replaced by
        // `ftypSHIT`, and FFmpeg will have ZERO complaints. The same goes for bytes 12-15 (inclusive) - they can be
        // overwritten with whatever integer.
        let m4aHeader: Uint8Array | undefined;
        if (fileType === "m4a") {
            if (fileContent.length < HEADER_LENGTH + 64) {
                throw new UnexpectedEofError();
            }

            m4aHeader = M4A_HEADER_TEMPLATE.slice();

            const fileStart = fileContent.subarray(HEADER_LENGTH, HEADER_LENGTH + 64);
            const decoder = new TextDecoder();
            const chunkSize = 4;

            for (let i = 0; i * chunkSize < fileStart.length; i++) {
                const chunk = fileStart.subarray(i * chunkSize, i * chunkSize + chunkSize);

                if (M4A_POST_HEADER_BOXES.includes(decoder.decode(chunk))) {
                    const headerTypeBoxSize = (i - 1) * chunkSize;
                    new DataView(m4aHeader.buffer).setUint32(0, headerTypeBoxSize, false);
                }
            }
        }

        // Since the stream serial number is incorrect in OGG_HEADER_TEMPLATE (it differs per file), we need to seek
        // to the second page of the stream and grab the serial number from there, then place it in the header.
        // The serial number is persistent across all pages of the stream, so we can grab it from the second page and
        // replace it in the first.
        let oggHeader: Uint8Array | undefined;
        if (fileType === "ogg") {
            oggHeader = OGG_HEADER_TEMPLATE.slice();

            const cursor = { pos: HEADER_LENGTH };
            readOggPageSerialNumber(fileContent, cursor);
            const serialno = readOggPageSerialNumber(fileContent, cursor);

            const serialnoBytes = new Uint8Array(4);
            new DataView(serialnoBytes.buffer).setUint32(0, serialno, true);
            oggHeader[14] = serialnoBytes[0]!;
            oggHeader[15] = serialnoBytes[1]!;
        }

        let keyHex = "";
        const keyBytes = new Uint8Array(KEY_LENGTH);

        for (let i = 0; i < HEADER_LENGTH; i++) {
            let signatureByte: number;

            switch (fileType) {
                case "png":
                    signatureByte = PNG_HEADER[i]!;
                    break;
                case "ogg":
                    signatureByte = oggHeader![i]!;
                    break;
                case "m4a":
                    signatureByte = m4aHeader![i]!;
                    break;
            }

            const value = signatureByte ^ postHeader[i]!;
            keyBytes[i] = value;
            keyHex += HEX_CHARS[value >> 4]! + HEX_CHARS[value & 0x0f]!;
        }

        this.keyHex = keyHex;
        this.keyBytes = keyBytes;
        this.hasKey = true;

        return keyHex;
    }

    /**
     * Decrypts RPG Maker file content. Auto-determines the key from the input file.
     *
     * This function copies the contents of the file and returns a decrypted copy. If you want to avoid copying, see
     * {@link Decrypter.decryptInPlace}.
     *
     * @throws {InvalidHeaderError} if `fileContent` doesn't start with {@link RPGM_HEADER}.
     * @throws {UnexpectedEofError} if `fileContent` ends unexpectedly.
     */
    decrypt(fileContent: Uint8Array, fileType: FileType): Uint8Array {
        if (!bytesStartWith(fileContent, RPGM_HEADER)) {
            throw new InvalidHeaderError();
        }

        if (!this.hasKey) {
            this.setKeyFromFile(fileContent, fileType);
        }

        const result = fileContent.slice(HEADER_LENGTH);
        this.xorBuffer(result);
        return result;
    }

    /**
     * Decrypts RPG Maker file content in place. Auto-determines the key from the input file.
     *
     * If you don't want to modify the passed data, see {@link Decrypter.decrypt}.
     *
     * Decrypted data is only valid starting at offset 16 - this function returns a view of that slice.
     *
     * @throws {InvalidHeaderError} if `fileContent` doesn't start with {@link RPGM_HEADER}.
     * @throws {UnexpectedEofError} if `fileContent` ends unexpectedly.
     */
    decryptInPlace(fileContent: Uint8Array, fileType: FileType): Uint8Array {
        if (!bytesStartWith(fileContent, RPGM_HEADER)) {
            throw new InvalidHeaderError();
        }

        if (!this.hasKey) {
            this.setKeyFromFile(fileContent, fileType);
        }

        const slice = fileContent.subarray(HEADER_LENGTH);
        this.xorBuffer(slice);
        return slice;
    }

    /**
     * Encrypts file content.
     *
     * Requires the decrypter to have a key - see {@link Decrypter.setKeyFromStr} or
     * {@link Decrypter.setKeyFromFile}.
     *
     * This function copies the contents of the file and returns an encrypted copy, prefixed with
     * {@link RPGM_HEADER}. If you want to avoid copying, see {@link Decrypter.encryptInPlace}.
     *
     * @throws {KeyNotSetError} if the decrypter's key is not set.
     */
    encrypt(fileContent: Uint8Array): Uint8Array {
        if (!this.hasKey) {
            throw new KeyNotSetError();
        }

        const data = fileContent.slice();
        this.xorBuffer(data);

        const output = new Uint8Array(HEADER_LENGTH + data.length);
        output.set(RPGM_HEADER, 0);
        output.set(data, HEADER_LENGTH);
        return output;
    }

    /**
     * Encrypts file content in place.
     *
     * Requires the decrypter to have a key - see {@link Decrypter.setKeyFromStr} or
     * {@link Decrypter.setKeyFromFile}.
     *
     * Encrypted data comes without the RPG Maker header, so you need to manually prepend it - see
     * {@link RPGM_HEADER}. If you don't want to modify the passed data, see {@link Decrypter.encrypt}.
     *
     * @throws {KeyNotSetError} if the decrypter's key is not set.
     */
    encryptInPlace(fileContent: Uint8Array): void {
        if (!this.hasKey) {
            throw new KeyNotSetError();
        }

        this.xorBuffer(fileContent);
    }
}

/**
 * Decrypts RPG Maker file content using a temporary {@link Decrypter} instance.
 *
 * This is a convenience wrapper around {@link Decrypter.decrypt}. The decryption key is auto-determined from the
 * provided file data. If you want to avoid copying, use {@link decryptInPlace} instead.
 */
export function decrypt(fileContent: Uint8Array, fileType: FileType): Uint8Array {
    return new Decrypter().decrypt(fileContent, fileType);
}

/**
 * Decrypts RPG Maker file content in place using a temporary {@link Decrypter} instance.
 *
 * This is a convenience wrapper around {@link Decrypter.decryptInPlace}. The decryption key is auto-determined from
 * the provided file data. After successful decryption, the decrypted data is valid starting at offset
 * {@link HEADER_LENGTH}. If you do not want to modify data in place, use {@link decrypt} instead.
 */
export function decryptInPlace(fileContent: Uint8Array, fileType: FileType): Uint8Array {
    return new Decrypter().decryptInPlace(fileContent, fileType);
}

/**
 * Encrypts file content using a key string and a temporary {@link Decrypter} instance.
 *
 * This is a convenience wrapper around {@link Decrypter.encrypt}. The output includes {@link RPGM_HEADER}. If you
 * want to avoid copying, use {@link encryptInPlace} instead.
 *
 * @throws {InvalidKeyLengthError} if `key`'s length is not 32 characters.
 */
export function encrypt(fileContent: Uint8Array, key: string): Uint8Array {
    const decrypter = new Decrypter();
    decrypter.setKeyFromStr(key);
    return decrypter.encrypt(fileContent);
}

/**
 * Encrypts file content in place using a key string and a temporary {@link Decrypter} instance.
 *
 * This is a convenience wrapper around {@link Decrypter.encryptInPlace}. This function modifies the file data
 * directly and produces *only* the encrypted payload - the RPG Maker encryption header is **not** added
 * automatically, it must be prepended manually (see {@link RPGM_HEADER}) to produce a complete `.rpgmvp`,
 * `.rpgmvo`, or `.rpgmvm` file. If you do not want to modify data in place, use {@link encrypt} instead.
 *
 * @throws {InvalidKeyLengthError} if `key`'s length is not 32 characters.
 */
export function encryptInPlace(fileContent: Uint8Array, key: string): void {
    const decrypter = new Decrypter();
    decrypter.setKeyFromStr(key);
    decrypter.encryptInPlace(fileContent);
}
