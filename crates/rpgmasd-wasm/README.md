# rpgmasd-wasm

WebAssembly bindings for [`rpgm-asset-decrypter-lib`](https://github.com/RPG-Maker-Translation-Tools/rpgm-asset-decrypter-lib), generated via [`wasm-bindgen`](https://github.com/rustwasm/wasm-bindgen). A thin wrapper around the Rust reference implementation - useful when you want behavior guaranteed identical to the Rust crate without a second, hand-maintained implementation.

## Install

```bash
npm install rpgmasd-wasm
```

## API

The `Decrypter` class mirrors the Rust API directly (see [`src/lib.rs`](https://github.com/RPG-Maker-Translation-Tools/rpgm-asset-decrypter-lib/blob/master/crates/rpgmasd-wasm/src/lib.rs) for full doc comments):

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

plus the `FileType` enum (`Png`, `Ogg`, `M4a`) and free-function equivalents of the Rust crate's convenience wrappers - `decryptAsset`, `decryptAssetInPlace`, `encryptAsset`, `encryptAssetInPlace` - each spinning up a throwaway `Decrypter` internally, for one-shot calls that don't need to hold onto a key.

The `*InPlace` methods take a `Uint8Array` and mutate it: `wasm-bindgen` copies the array's bytes into WASM memory, runs the call, and copies the (possibly mutated) bytes back out afterward - so the mutation is visible on your own `Uint8Array` once the call returns, same as the reference in-place methods.

## Usage

```ts
import init, { Decrypter, FileType } from "rpgmasd-wasm";

await init(); // instantiates the wasm module - do this once, before first use

const fileContent = new Uint8Array(await Deno.readFile("./image.rpgmvp"));

const decrypter = new Decrypter();
const decrypted = decrypter.decrypt(fileContent, FileType.Png); // key is auto-derived from the file
```

The free-function form is shorter when you don't need to reuse the derived key across multiple files:

```ts
import init, { decryptAsset, FileType } from "rpgmasd-wasm";

await init();
const decrypted = decryptAsset(fileContent, FileType.Png);
```

Under Node/Bun, `init()`'s default `fetch()`-based loading doesn't apply - pass the `.wasm` bytes explicitly instead:

```ts
import { readFile } from "node:fs/promises";
import init, { Decrypter } from "rpgmasd-wasm";

await init(
  await readFile(new URL("./rpgmasd_wasm_bg.wasm", import.meta.resolve("rpgmasd-wasm"))),
);
```

## Building

```bash
wasm-pack build --release --target web
```

Requires the `wasm32-unknown-unknown` rustup target (`rustup target add wasm32-unknown-unknown`) and `wasm-pack` (`cargo binstall wasm-pack`). Output goes to `pkg/` (gitignored): the compiled `.wasm`, a JS glue module, a `.d.ts`, and the `package.json` this crate publishes to npm from.
