# rpgmasd-wasm

WebAssembly bindings for [`rpgm-asset-decrypter-lib`](https://github.com/RPG-Maker-Translation-Tools/rpgm-asset-decrypter-lib): decrypt and encrypt RPG Maker MV/MZ audio and image assets.

> **I won't be continuing to publish this package on NPM.** NPM has made their 2FA completely unbearable, and I don't want to participate in this logging-in shitshow anymore. I'm looking for the first person I meet to whom I'll pass the ownership of this package on NPM, if they're willing to maintain it. Until then, you can always [build from source](#build-from-source).

## Install

```bash
npm install rpgmasd-wasm
```

## API

```ts
class Decrypter {
    constructor();
    key(): string | undefined;
    setKeyFromStr(key: string): void;
    setKeyFromFile(fileContent: Uint8Array, fileType: FileType): string;
    decrypt(fileContent: Uint8Array, fileType: FileType): Uint8Array;
    decryptInPlace(fileContent: Uint8Array, fileType: FileType): void;
    encrypt(fileContent: Uint8Array): Uint8Array;
    encryptInPlace(fileContent: Uint8Array): void;
}
```

Plus the `FileType` enum (`Png`, `Ogg`, `M4a`) and one-shot functions that use a throwaway `Decrypter`: `decryptAsset`, `decryptAssetInPlace`, `encryptAsset`, `encryptAssetInPlace`. The `*InPlace` variants mutate the `Uint8Array` you pass.

## Usage

```ts
import init, { Decrypter, FileType } from "rpgmasd-wasm";

await init(); // instantiates the wasm module - do this once, before first use

const fileContent = new Uint8Array(await Deno.readFile("./image.rpgmvp"));

const decrypter = new Decrypter();
const decrypted = decrypter.decrypt(fileContent, FileType.Png); // key is auto-derived from the file
```

Without a reusable `Decrypter`: `decryptAsset(fileContent, FileType.Png)`.

Under Node/Bun, pass the `.wasm` bytes to `init()` explicitly:

```ts
import { readFile } from "node:fs/promises";
import init, { Decrypter } from "rpgmasd-wasm";

await init(
  await readFile(new URL("./rpgmasd_wasm_bg.wasm", import.meta.resolve("rpgmasd-wasm"))),
);
```

## Build from source

```bash
wasm-pack build --release --target web   # output in pkg/
```
