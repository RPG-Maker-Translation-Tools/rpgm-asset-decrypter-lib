// Regenerates the variant fixtures: real PNG, OGG and M4A files from ImageMagick and ffmpeg, encrypted here.
//
//   node tests/assets/variants/generate.ts
//
// The encryption below is a separate implementation of the RPG Maker format, not the Rust crate, so the tests check the
// crate against it rather than against itself. Each plain file is written next to its encrypted counterpart.
import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const DIR = new URL(".", import.meta.url).pathname.replace(/^\/(\w:)/, "$1");
const RPGM_HEADER = [0x52, 0x50, 0x47, 0x4d, 0x56, 0, 0, 0, 0, 3, 1, 0, 0, 0, 0, 0];
const DEFAULT_KEY = "d41d8cd98f00b204e9800998ecf8427e";

async function run(command: string, args: string[]): Promise<void> {
    try {
        await execFileAsync(command, args);
    } catch (error) {
        throw new Error(`${command} failed: ${(error as { stderr: string }).stderr}`);
    }
}

// XORs the first 16 bytes of the content with the key, after the header. Same operation as the decrypter's.
function encrypt(plain: Uint8Array, keyHex: string): Uint8Array {
    const key = Uint8Array.from(keyHex.match(/../g)!, (pair) => parseInt(pair, 16));
    const out = new Uint8Array(RPGM_HEADER.length + plain.length);
    out.set(RPGM_HEADER, 0);
    out.set(plain, RPGM_HEADER.length);
    for (let i = 0; i < key.length; i++) {
        out[RPGM_HEADER.length + i] ^= key[i];
    }
    return out;
}

interface Variant {
    // Plain file, made by the encoder below, and the encrypted file written from it.
    plain: string;
    encrypted: string;
    key: string;
    make: (path: string) => Promise<void>;
}

const tone = ["-f", "lavfi", "-i", "sine=frequency=440:duration=3"];

const variants: Variant[] = [
    {
        // Adam7-interlaced, 4-bit palette: the IHDR combinations the checker accepts beyond the usual 8-bit RGBA.
        plain: "png-interlaced-palette.png",
        encrypted: "png-interlaced-palette.rpgmvp",
        key: DEFAULT_KEY,
        make: (path) =>
            run("magick", ["-size", "96x64", "gradient:red-blue", "-type", "Palette", "-colors", "16", "-depth", "4", "-interlace", "PNG", `PNG:${path}`]),
    },
    {
        // 16-bit RGBA, not interlaced, with a non-default key.
        plain: "png-rgba16.png",
        encrypted: "png-rgba16.png_",
        key: "00112233445566778899aabbccddeeff",
        make: (path) => run("magick", ["-size", "48x32", "gradient:blue-green", "-alpha", "on", `PNG64:${path}`]),
    },
    {
        // Several pages, so the OGG page walk runs more than once.
        plain: "ogg-multipage.ogg",
        encrypted: "ogg-multipage.ogg_",
        key: "0123456789abcdef0123456789abcdef",
        make: (path) => run("ffmpeg", ["-y", ...tone, "-c:a", "libvorbis", "-b:a", "64k", path]),
    },
    {
        // The ftyp box is followed by mdat, with moov at the end of the file.
        plain: "m4a-moov-last.m4a",
        encrypted: "m4a-moov-last.rpgmvm",
        key: DEFAULT_KEY,
        make: (path) => run("ffmpeg", ["-y", ...tone, "-c:a", "aac", "-b:a", "64k", "-f", "ipod", path]),
    },
    {
        // The moov box comes right after ftyp.
        plain: "m4a-moov-first.m4a",
        encrypted: "m4a-moov-first.rpgmvm",
        key: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        make: (path) => run("ffmpeg", ["-y", ...tone, "-c:a", "aac", "-b:a", "64k", "-f", "ipod", "-movflags", "+faststart", path]),
    },
];

for (const variant of variants) {
    const plainPath = join(DIR, variant.plain);
    await variant.make(plainPath);

    const plain = await readFile(plainPath);
    await writeFile(join(DIR, variant.encrypted), encrypt(plain, variant.key));
    console.log(`${variant.encrypted}: ${plain.length} plain bytes, key ${variant.key}`);
}
