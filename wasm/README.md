# rpgmasd-wasm

WebAssembly bindings for [`rpgm-asset-decrypter-lib`](https://github.com/RPG-Maker-Translation-Tools/rpgm-asset-decrypter-lib): decrypt and encrypt RPG Maker MV/MZ audio and image assets.

> **I won't be continuing to publish this package on NPM.** NPM has made their 2FA completely unbearable, and I don't want to participate in this logging-in shitshow anymore. I'm looking for the first person I meet to whom I'll pass the ownership of this package on NPM, if they're willing to maintain it. Until then, you can always [build from source](#build-from-source).

## API

```ts
class Decrypter {
  constructor();
  key(): string | undefined;
  setKeyFromStr(key: string): void;
  setKeyFromFile(fileContent: Uint8Array, fileType: FileType): string;
  decrypt(fileContent: Uint8Array, fileType: FileType): Uint8Array;
  decryptKeyed(fileContent: Uint8Array, fileType: FileType): Uint8Array;
  encrypt(fileContent: Uint8Array, fileType: FileType): Uint8Array;
  free(): void;
}
```

Also exported: the `FileType` enum (`Png`, `Ogg`, `M4a`), `decryptAsset(fileContent, fileType)` and `encryptAsset(fileContent, fileType, key)`, which use a temporary `Decrypter`, `fileTypeFromExtension("rpgmvp")`, which accepts any case and a leading dot, and `defaultKey()`, the key RPG Maker uses when a project's encryption key is empty.

`encrypt` and `encryptAsset` return the complete file, header included. `decryptKeyed` works like `decrypt` with a key that is already set, and throws `KeyNotSet` without one.

A `Decrypter` derives its key from the first file it decrypts and rejects files encrypted with another key (`KeyMismatch`), so use one per project. Call `free()` when done, or declare it with `using` where supported.

## Errors

Failing calls throw a JS `Error`. Its `name` is one of `KeyNotSet`, `InvalidKeyLength`, `InvalidKey`, `InvalidHeader`, `UnexpectedEOF`, `KeyMismatch`, `InvalidContent` or `UnsupportedExtension`, or `Unknown` for a library error this package doesn't map yet (typed as `RpgmasdErrorName`):

```ts
try {
  decrypter.decrypt(fileContent, FileType.Png);
} catch (error) {
  if (error instanceof Error && error.name === "InvalidHeader") {
    // not an RPG Maker encrypted file
  }
}
```

## Usage

```ts
import { readFile } from "node:fs/promises";
import init, { Decrypter, FileType } from "rpgmasd-wasm";

await init({
  module_or_path: await readFile(
    new URL("./rpgmasd_wasm_bg.wasm", import.meta.resolve("rpgmasd-wasm")),
  ),
}); // call once before first use

const fileContent = new Uint8Array(await readFile("./image.rpgmvp"));

const decrypter = new Decrypter();
const decrypted = decrypter.decrypt(fileContent, FileType.Png);
```

Without a reusable `Decrypter`: `decryptAsset(fileContent, FileType.Png)`.

## Build from source

```bash
wasm-pack build --release --target web   # output in pkg/
```
