import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
    DEFAULT_KEY,
    Decrypter,
    InvalidHeaderError,
    InvalidKeyLengthError,
    KeyNotSetError,
    RPGM_HEADER,
    fileTypeFromExtension,
} from "../src/index.ts";
import type { FileType } from "../src/index.ts";

const assetsDir = fileURLToPath(new URL("./assets", import.meta.url));

function isValidOgg(buf: Uint8Array): boolean {
    return buf[0] === 0x4f && buf[1] === 0x67 && buf[2] === 0x67 && buf[3] === 0x53; // "OggS"
}

function isValidM4a(buf: Uint8Array): boolean {
    return new TextDecoder().decode(buf.subarray(4, 12)) === "ftypM4A ";
}

function isValidPng(buf: Uint8Array): boolean {
    const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    return PNG_SIGNATURE.every((byte, i) => buf[i] === byte);
}

interface TestCase {
    path: string;
    fileType: FileType;
    validator: (buf: Uint8Array) => boolean;
}

const oggCases: TestCase[] = [
    { path: `${assetsDir}/mv/test-default.rpgmvo`, fileType: "ogg", validator: isValidOgg },
    { path: `${assetsDir}/mv/test-aboba.rpgmvo`, fileType: "ogg", validator: isValidOgg },
    { path: `${assetsDir}/mz/test-default.ogg_`, fileType: "ogg", validator: isValidOgg },
    { path: `${assetsDir}/mz/test-aboba.ogg_`, fileType: "ogg", validator: isValidOgg },
];

const m4aCases: TestCase[] = [
    { path: `${assetsDir}/mz/test-default.m4a_`, fileType: "m4a", validator: isValidM4a },
    { path: `${assetsDir}/mz/test-aboba.m4a_`, fileType: "m4a", validator: isValidM4a },
];

const pngCases: TestCase[] = [
    { path: `${assetsDir}/mv/test-default.rpgmvp`, fileType: "png", validator: isValidPng },
    { path: `${assetsDir}/mv/test-aboba.rpgmvp`, fileType: "png", validator: isValidPng },
    { path: `${assetsDir}/mz/test-default.png_`, fileType: "png", validator: isValidPng },
    { path: `${assetsDir}/mz/test-aboba.png_`, fileType: "png", validator: isValidPng },
];

async function runDecrypt(testCase: TestCase): Promise<void> {
    const decrypter = new Decrypter();
    const decrypted = decrypter.decrypt(new Uint8Array(await readFile(testCase.path)), testCase.fileType);
    assert.ok(testCase.validator(decrypted));
}

async function runEncryptRoundtrip(testCase: TestCase): Promise<void> {
    const decrypter = new Decrypter();
    const original = decrypter.decrypt(new Uint8Array(await readFile(testCase.path)), testCase.fileType);

    const encrypted = decrypter.encrypt(original);
    const decrypted = decrypter.decrypt(encrypted, testCase.fileType);

    assert.ok(testCase.validator(decrypted));
}

async function runDecryptInPlace(testCase: TestCase): Promise<void> {
    const decrypter = new Decrypter();
    const buf = new Uint8Array(await readFile(testCase.path));

    const decrypted = decrypter.decryptInPlace(buf, testCase.fileType);

    assert.ok(testCase.validator(decrypted));
}

async function runEncryptInPlaceRoundtrip(testCase: TestCase): Promise<void> {
    const decrypter = new Decrypter();

    const clean = decrypter.decrypt(new Uint8Array(await readFile(testCase.path)), testCase.fileType);
    const buf = clean.slice();

    decrypter.encryptInPlace(buf);

    const withHeader = new Uint8Array(RPGM_HEADER.length + buf.length);
    withHeader.set(RPGM_HEADER, 0);
    withHeader.set(buf, RPGM_HEADER.length);

    const decrypted = decrypter.decrypt(withHeader, testCase.fileType);
    assert.ok(testCase.validator(decrypted));
}

function generateTests(group: string, cases: TestCase[]): void {
    test(`${group} > decrypt`, async () => {
        for (const c of cases) await runDecrypt(c);
    });

    test(`${group} > encrypt roundtrip`, async () => {
        for (const c of cases) await runEncryptRoundtrip(c);
    });

    test(`${group} > decrypt in place`, async () => {
        for (const c of cases) await runDecryptInPlace(c);
    });

    test(`${group} > encrypt in place roundtrip`, async () => {
        for (const c of cases) await runEncryptInPlaceRoundtrip(c);
    });
}

generateTests("ogg", oggCases);
generateTests("m4a", m4aCases);
generateTests("png", pngCases);

test("fileTypeFromExtension deduces both MV and MZ extensions", () => {
    assert.equal(fileTypeFromExtension("rpgmvp"), "png");
    assert.equal(fileTypeFromExtension("png_"), "png");
    assert.equal(fileTypeFromExtension(".ogg_"), "ogg");
    assert.equal(fileTypeFromExtension("m4a_"), "m4a");
    assert.throws(() => fileTypeFromExtension("txt"));
});

test("rejects an invalid header", () => {
    const decrypter = new Decrypter();
    assert.throws(() => decrypter.decrypt(new Uint8Array(32), "png"), InvalidHeaderError);
});

test("encrypt throws when no key is set", () => {
    const decrypter = new Decrypter();
    assert.throws(() => decrypter.encrypt(new Uint8Array(16)), KeyNotSetError);
});

test("setKeyFromStr rejects a key with the wrong length", () => {
    const decrypter = new Decrypter();
    assert.throws(() => decrypter.setKeyFromStr("too-short"), InvalidKeyLengthError);
});

test("encrypt with the default key round-trips through decrypt", () => {
    const decrypter = new Decrypter();
    decrypter.setKeyFromStr(DEFAULT_KEY);

    const payload = new Uint8Array(64).map((_, i) => i);
    const encrypted = decrypter.encrypt(payload);

    const roundTripDecrypter = new Decrypter();
    roundTripDecrypter.setKeyFromStr(DEFAULT_KEY);
    const decrypted = roundTripDecrypter.decrypt(encrypted, "png");

    assert.deepEqual(decrypted, payload);
});
