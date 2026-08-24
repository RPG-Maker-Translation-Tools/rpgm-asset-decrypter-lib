# rpgm-asset-decrypter-lib

**BLAZINGLY** :fire: fast and tiny library for decrypting RPG Maker MV/MZ `rpgmvp`/`png_`, `rpgmvo`/`ogg_`, `rpgmvm`/`m4a_` assets.

TypeScript port of the [`rpgm-asset-decrypter-lib`](https://github.com/savannstm/rpgm-asset-decrypter-lib) Rust crate, kept behaviorally identical to that reference implementation. Operates on `Uint8Array` buffers in place wherever possible.

Pure `Uint8Array`/`DataView`, no runtime-specific APIs — works the same under Node, Bun, and Deno.

Used in my [rpgm-asset-decrypter-rs](https://github.com/savannstm/rpgm-asset-decrypter-rs) CLI tool.

## Install

```bash
npm install rpgm-asset-decrypter-lib
# or
bun add rpgm-asset-decrypter-lib
# or
deno add npm:rpgm-asset-decrypter-lib
```

## Usage

### Decrypting Assets

#### Decrypt with copying

```ts
import { Decrypter } from "rpgm-asset-decrypter-lib";
import { readFile, writeFile } from "node:fs/promises";

const decrypter = new Decrypter();

const buf = new Uint8Array(await readFile("./image.rpgmvp"));

// Decrypter automatically extracts the RPG Maker encryption key from the file
// but you must specify the original asset type.
const decrypted = decrypter.decrypt(buf, "png");

await writeFile("./image.png", decrypted);
```

#### Decrypt in place

```ts
import { Decrypter } from "rpgm-asset-decrypter-lib";
import { readFile, writeFile } from "node:fs/promises";

const decrypter = new Decrypter();

const buf = new Uint8Array(await readFile("./image.rpgmvp"));

// decrypt in place; returns a view into `buf` without reallocating
const decryptedSlice = decrypter.decryptInPlace(buf, "png");

await writeFile("./image.png", decryptedSlice);
```

#### Deducing FileType from extension

```ts
import { Decrypter, fileTypeFromExtension } from "rpgm-asset-decrypter-lib";
import { readFile, writeFile } from "node:fs/promises";

const decrypter = new Decrypter();

const buf = new Uint8Array(await readFile("./image.rpgmvp"));

const fileType = fileTypeFromExtension("rpgmvp");

const decrypted = decrypter.decryptInPlace(buf, fileType);

await writeFile("./image.png", decrypted);
```

### Encrypting Assets

#### Encrypt with copying

```ts
import { Decrypter, DEFAULT_KEY } from "rpgm-asset-decrypter-lib";
import { readFile, writeFile } from "node:fs/promises";

const decrypter = new Decrypter();

// You can set a custom key (recommended):
//
// 1. From an existing encrypted file:
// const encrypted = new Uint8Array(await readFile("./image.rpgmvp"));
// decrypter.setKeyFromFile(encrypted, "png");
//
// 2. Or use the default key (not recommended)
decrypter.setKeyFromStr(DEFAULT_KEY);

const buf = new Uint8Array(await readFile("./picture.png"));
const encrypted = decrypter.encrypt(buf);

await writeFile("./image.rpgmvp", encrypted);
```

#### Encrypt in place

`encryptInPlace` produces the **raw encrypted payload**, without the RPG Maker header.
To write a valid `.rpgmvp`, prepend `RPGM_HEADER`.

```ts
import { Decrypter, DEFAULT_KEY, RPGM_HEADER } from "rpgm-asset-decrypter-lib";
import { readFile, writeFile } from "node:fs/promises";

const decrypter = new Decrypter();
decrypter.setKeyFromStr(DEFAULT_KEY);

const buf = new Uint8Array(await readFile("./image.png"));
decrypter.encryptInPlace(buf);

const out = new Uint8Array(RPGM_HEADER.length + buf.length);
out.set(RPGM_HEADER, 0);
out.set(buf, RPGM_HEADER.length);

await writeFile("./image.rpgmvp", out);
```

### Using convenience wrappers

The package exposes wrapper functions for quick encrypt/decrypt without manually instantiating `Decrypter`.

```ts
import { decrypt, decryptInPlace, encrypt, encryptInPlace, DEFAULT_KEY } from "rpgm-asset-decrypter-lib";
import { readFile, writeFile } from "node:fs/promises";

const encryptedPng = new Uint8Array(await readFile("./image.rpgmvp"));
await writeFile("./image.png", decrypt(encryptedPng, "png"));

const png = new Uint8Array(await readFile("./image.png"));
await writeFile("./image.rpgmvp", encrypt(png, DEFAULT_KEY));
```

## Support

[Me](https://github.com/savannstm), the maintainer of this project, is a poor college student from Eastern Europe.

If you could, please consider supporting us through:

- [Ko-fi](https://ko-fi.com/savannstm)
- [Patreon](https://www.patreon.com/cw/savannstm)
- [Boosty](https://boosty.to/mcdeimos)

Even if you don't, it's fine. We'll continue to do as we right now.

## License

Project is licensed under WTFPL.
