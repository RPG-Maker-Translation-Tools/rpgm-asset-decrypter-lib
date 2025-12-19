# rpgm-asset-decrypter-lib

**BLAZINGLY** :fire: fast and tiny library for decrypting RPG Maker MV/MZ `rpgmvp`/`png_`, `rpgmvo`/`ogg_`, `rpgmvm`/`m4a_` assets.

This project essentially is a rewrite of Petschko's [RPG-Maker-MV-Decrypter](https://gitlab.com/Petschko/RPG-Maker-MV-Decrypter) in Rust, but it also implements encryption key extraction from non-image files, such as `rpgmvo`/`ogg_` and `rpgmvm`/`m4a_`.

And since it's implemented in Rust 🦀🦀🦀, it's also very tiny, clean, and performant.

Used in my [rpgm-asset-decrypter-rs](https://github.com/savannstm/rpgm-asset-decrypter-rs) CLI tool.

## Installation

`cargo add rpgm-asset-decrypter-lib`

## Usage

### Decrypting Assets

#### Decrypt with copying

```rust no_run
use rpgm_asset_decrypter_lib::{Decrypter, FileType};
use std::fs::{read, write};

fn main() {
    let mut decrypter = Decrypter::new();

    let encrypted_path = "./image.rpgmvp";
    let buf = read(encrypted_path).unwrap();

    // Decrypter automatically extracts the RPG Maker encryption key from the file
    // but you must specify the original asset type.
    let decrypted = decrypter.decrypt(&buf, FileType::PNG).unwrap();

    write("./image.png", decrypted).unwrap();
}
```

#### Decrypt in place

```rust no_run
use rpgm_asset_decrypter_lib::{Decrypter, FileType};
use std::fs::{read, write};

fn main() {
    let mut decrypter = Decrypter::new();

    let encrypted_path = "./image.rpgmvp";
    let mut buf = read(encrypted_path).unwrap();

    // decrypt in place; returns a slice into `buf` without reallocating
    let decrypted_slice = decrypter.decrypt_in_place(&mut buf, FileType::PNG).unwrap();

    write("./image.png", decrypted_slice).unwrap();
}
```

#### Deducing FileType from extension

```rust no_run
use rpgm_asset_decrypter_lib::{Decrypter, FileType};
use std::fs::{read, write};
use std::convert::TryFrom;

fn main() {
    let mut decrypter = Decrypter::new();

    let encrypted_path = "./image.rpgmvp";
    let mut buf = read(encrypted_path).unwrap();

    // Deduce from &str; &OsStr also works
    let filetype = FileType::try_from("rpgmvp").unwrap();

    let decrypted = decrypter.decrypt_in_place(&mut buf, filetype).unwrap();

    write("./image.png", decrypted).unwrap();
}
```

### Encrypting Assets

#### Encrypt with copying

```rust no_run
use rpgm_asset_decrypter_lib::{Decrypter, FileType, DEFAULT_KEY};
use std::fs::{read, write};

fn main() {
    let mut decrypter = Decrypter::new();

    // You can set a custom key (recommended):
    //
    // 1. From an existing encrypted file:
    // let encrypted = read("./image.rpgmvp").unwrap();
    // decrypter.set_key_from_file(&encrypted, FileType::PNG);
    //
    // 2. Or use the default key (not recommended)
    decrypter.set_key_from_str(DEFAULT_KEY);

    let png_path = "./picture.png";
    let buf = read(png_path).unwrap();

    let encrypted = decrypter.encrypt(&buf).unwrap();

    write("./image.rpgmvp", encrypted).unwrap();
}
```

#### Encrypt in place

`encrypt_in_place` produces the **raw encrypted payload**, without the RPG Maker header.
To write a valid `.rpgmvp`, prepend `RPGM_HEADER`.

```rust no_run
use rpgm_asset_decrypter_lib::{Decrypter, DEFAULT_KEY, RPGM_HEADER};
use std::fs::{read, File};
use std::io::{Write, IoSlice};

fn main() {
    let mut decrypter = Decrypter::new();

    // You can set a custom key (recommended):
    //
    // 1. From an existing encrypted file:
    // let encrypted = read("./image.rpgmvp").unwrap();
    // decrypter.set_key_from_file(&encrypted, FileType::PNG);
    //
    // 2. Or use the default key (not recommended)
    decrypter.set_key_from_str(DEFAULT_KEY);

    let png_path = "./image.png";
    let mut buf = read(png_path).unwrap();

    decrypter.encrypt_in_place(&mut buf).unwrap();

    // Write a proper RPG Maker encrypted file
    let mut out = File::create("./image.rpgmvp").unwrap();
    let segments = [
        IoSlice::new(RPGM_HEADER),
        IoSlice::new(&buf),
    ];

    out.write_vectored(&segments).unwrap();
}
```

### Using convenience wrappers

The crate exposes wrapper functions for quick encrypt/decrypt without manually instantiating `Decrypter`.

#### `decrypt` wrapper

```rust no_run
use rpgm_asset_decrypter_lib::{decrypt, FileType};
use std::fs::{read, write};

fn main() {
    let buf = read("./image.rpgmvp").unwrap();
    let out = decrypt(&buf, FileType::PNG).unwrap();
    write("./image.png", out).unwrap();
}
```

#### `decrypt_in_place` wrapper

```rust no_run
use rpgm_asset_decrypter_lib::{decrypt_in_place, FileType, HEADER_LENGTH};
use std::fs::{read, write};

fn main() {
    let mut buf = read("./image.rpgmvp").unwrap();
    // decrypt_in_place wrapper doesn't return a slice to the decrypted data, you must slice it manually.
    decrypt_in_place(&mut buf, FileType::PNG).unwrap();
    write("./image.png", &buf[HEADER_LENGTH..]).unwrap();
}
```

#### `encrypt` wrapper

```rust no_run
use rpgm_asset_decrypter_lib::{encrypt, DEFAULT_KEY};
use std::fs::{read, write};

fn main() {
    let buf = read("./image.png").unwrap();
    let encrypted = encrypt(&buf, DEFAULT_KEY).unwrap();

    write("./image.rpgmvp", encrypted).unwrap();
}
```

#### `encrypt_in_place` wrapper

```rust no_run
use rpgm_asset_decrypter_lib::{encrypt_in_place, DEFAULT_KEY, RPGM_HEADER};
use std::fs::{read, File};
use std::io::{Write, IoSlice};

fn main() {
    let mut buf = read("./image.png").unwrap();

    // encrypt_in_place does NOT write the header
    encrypt_in_place(&mut buf, DEFAULT_KEY).unwrap();

    let mut file = File::create("./image.rpgmvp").unwrap();
    let bufs = [IoSlice::new(RPGM_HEADER), IoSlice::new(&buf)];
    file.write_vectored(&bufs).unwrap();
}
```

## Features

-   `serde` - enables serde serialization/deserialization for `Error` type.

## Support

[Me](https://github.com/savannstm), the maintainer of this project, is a poor college student from Eastern Europe.

If you could, please consider supporting us through:

-   [Ko-fi](https://ko-fi.com/savannstm)
-   [Patreon](https://www.patreon.com/cw/savannstm)
-   [Boosty](https://boosty.to/mcdeimos)

Even if you don't, it's fine. We'll continue to do as we right now.

## License

Project is licensed under WTFPL.
