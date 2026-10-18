# rpgm-asset-decrypter-lib

**BLAZINGLY** 🔥 fast and tiny library for decrypting and encrypting RPG Maker MV/MZ `rpgmvp`/`png_`, `rpgmvo`/`ogg_` and `rpgmvm`/`m4a_` assets.

A Rust rewrite of Petschko's [RPG-Maker-MV-Decrypter](https://gitlab.com/Petschko/RPG-Maker-MV-Decrypter). Unlike it, this crate also extracts the key from `ogg_` and `m4a_` files and works in `no_std` environments.

And since it's implemented in Rust 🦀🦀🦀, it's also very tiny, clean, and performant.

Used in the [rpgm-asset-decrypter-rs](https://github.com/savannstm/rpgm-asset-decrypter-rs) CLI.

Ports:

- [C API](https://github.com/RPG-Maker-Translation-Tools/rpgm-asset-decrypter-lib/tree/main/capi) - C bindings, installable via `cargo-c`.
- [WASM](https://github.com/RPG-Maker-Translation-Tools/rpgm-asset-decrypter-lib/tree/main/wasm) - WebAssembly bindings.

## Installation

`cargo add rpgm-asset-decrypter-lib`

## Usage

### Decrypting

```rust no_run
use rpgm_asset_decrypter_lib::{Decrypter, FileType};
use std::fs::{read, write};

fn main() {
    let mut decrypter = Decrypter::new();

    let buf = read("./image.rpgmvp").unwrap();

    // The key is extracted from the file; the asset type must be given explicitly.
    let decrypted = decrypter.decrypt(&buf, FileType::Png).unwrap();

    write("./image.png", decrypted).unwrap();
}
```

To avoid copying, use `decrypt_in_place`, which returns a slice into `buf` starting at offset 16:

```rust no_run
use rpgm_asset_decrypter_lib::{Decrypter, FileType};
use std::fs::{read, write};

fn main() {
    let mut decrypter = Decrypter::new();

    let mut buf = read("./image.rpgmvp").unwrap();
    let decrypted = decrypter.decrypt_in_place(&mut buf, FileType::Png).unwrap();

    write("./image.png", decrypted).unwrap();
}
```

`FileType` can be parsed from an encrypted extension (case-insensitive):

```rust no_run
use rpgm_asset_decrypter_lib::FileType;

fn main() {
    let filetype = FileType::try_from("rpgmvp").unwrap();
}
```

### Reusing a key

`Decrypter::decrypt` derives the key from the first file and reuses it for the following ones, returning `Error::KeyMismatch` if a file was encrypted with another key. Use one `Decrypter` per encryption key.

To decrypt on several threads, set the key once and use the `&self` methods `decrypt_keyed` and `decrypt_in_place_keyed`:

```rust no_run
use rpgm_asset_decrypter_lib::{Decrypter, FileType, DEFAULT_KEY};
use std::fs::read;

fn main() {
    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();

    std::thread::scope(|scope| {
        for path in ["./a.rpgmvp", "./b.rpgmvp"] {
            let decrypter = &decrypter;
            scope.spawn(move || {
                let decrypted = decrypter.decrypt_keyed(&read(path).unwrap(), FileType::Png).unwrap();
                println!("{path}: {} bytes", decrypted.len());
            });
        }
    });
}
```

### Encrypting

`encrypt` and `encrypt_in_place` check the data's magic bytes against the given `FileType`, so a wrong type fails with `Error::InvalidContent`. They need a key: set one from the game's `System.json` (`encryptionKey`) or from an existing encrypted file with `set_key_from_file`. `DEFAULT_KEY` works for projects that left the key empty.

```rust no_run
use rpgm_asset_decrypter_lib::{Decrypter, FileType, DEFAULT_KEY};
use std::fs::{read, write};

fn main() {
    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();

    let buf = read("./image.png").unwrap();
    let encrypted = decrypter.encrypt(&buf, FileType::Png).unwrap();

    write("./image.rpgmvp", encrypted).unwrap();
}
```

`encrypt_in_place` produces only the raw payload, without the header. Prepend `RPGM_HEADER` to get a valid `.rpgmvp`:

```rust no_run
use rpgm_asset_decrypter_lib::{Decrypter, FileType, DEFAULT_KEY, RPGM_HEADER};
use std::fs::{read, File};
use std::io::Write;

fn main() {
    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();

    let mut buf = read("./image.png").unwrap();
    decrypter.encrypt_in_place(&mut buf, FileType::Png).unwrap();

    let mut out = File::create("./image.rpgmvp").unwrap();
    out.write_all(RPGM_HEADER).unwrap();
    out.write_all(&buf).unwrap();
}
```

### Convenience wrappers

`decrypt`, `decrypt_in_place`, `encrypt` and `encrypt_in_place` do the same as the methods above with a temporary `Decrypter`:

```rust no_run
use rpgm_asset_decrypter_lib::{decrypt, FileType};
use std::fs::{read, write};

fn main() {
    let buf = read("./image.rpgmvp").unwrap();
    write("./image.png", decrypt(&buf, FileType::Png).unwrap()).unwrap();
}
```

`encrypt` and `encrypt_in_place` take the key as a string, like `DEFAULT_KEY`.

## Features

- `default` - enables `std`. Disable default features for `no_std`.
- `alloc` - enables the `Vec`-returning `encrypt`/`decrypt` functions (implied by `std`). The in-place functions need neither `alloc` nor `std`.
- `std` - implies `alloc`; adds the `TryFrom<&OsStr>` conversion for `FileType`.
- `serde` - serialization for `Error`.

## Support

[Me](https://github.com/savannstm), the maintainer of this project, is a poor college student from Eastern Europe.

If you could, please consider supporting us through:

- [Boosty](https://boosty.to/mcdeimos) (has lower fees)
- [Ko-fi](https://ko-fi.com/savannstm)

Even if you don't, we will still continue working on the project anyways.

## License

Licensed under [WTFPL](https://www.wtfpl.net/).
