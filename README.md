# rpgm-asset-decrypter-lib

**BLAZINGLY** :fire: fast and tiny library for decrypting RPG Maker MV/MZ `rpgmvp`/`png_`, `rpgmvo`/`ogg_`, `rpgmvm`/`m4a_` assets.

This project essentially is a rewrite of Petschko's [RPG-Maker-MV-Decrypter](https://gitlab.com/Petschko/RPG-Maker-MV-Decrypter) in Rust, but it also implements encryption key extraction from non-image files, such as `rpgmvo`/`ogg_` (with `vorbis-key-extraction` feature) and `rpgmvm`/`m4a_`.

And since it's implemented in Rust 🦀🦀🦀, it's also very tiny, clean, and performant.

Used in my [rpgm-asset-decrypter-rs](https://github.com/savannstm/rpgm-asset-decrypter-rs) CLI tool.

## Installation

`cargo add rpgm-asset-decrypter-lib`

## Usage

Decrypt:

```rust
use rpgm_asset_decrypter_lib::{Decrypter, FileType};
use std::fs::{read, write};

let mut decrypter = Decrypter::new();
let file = "./picture.rpgmvp";

let buf = read(file).unwrap();

// Decrypter auto-determines the encryption key from data, but you also need to pass a file type.
let decrypted = decrypter.decrypt(&buf, FileType::PNG).unwrap();

// You can also auto-deduce FileType from extension:
// FileType::from("rpgmvp");
// It supports conversions from &str and &OsStr.

// Since [`Decrypter::decrypt`] copies the data, it's pretty much inefficient, and if you don't need to reuse the file data, you can decrypt it in-place:
// let mut buf = read(file).unwrap();
// [`Decrypter::decrypt_in_place`] returns a slice of the actual decrypted data, so use that.
// let sliced = decrypter.decrypt_in_place(&mut buf, FileType::PNG);
// write("./decrypted-picture.png", sliced).unwrap();

write("./decrypted-picture.png", decrypted).unwrap();
```

Encrypt:

```rust
use rpgm_asset_decrypter_lib::{Decrypter, DEFAULT_KEY};
use std::fs::{read, write};

let mut decrypter = Decrypter::new();

let file = "./picture.png";
let buf = read(file).unwrap();

// When encrypting, decrypter requires a key.
// You can grab the key from System.json file or use [`Decrypter::set_key_from_file`] with RPG Maker encrypted file content.
//
// let encrypted = read("./picture.rpgmvp").unwrap();
// decrypter.set_key_from_file(&encrypted, FileType::PNG);
//
// You can also use default key:
// decrypter.set_key_from_str(DEFAULT_KEY);
// but I don't recommend using that.
let encrypted = decrypter.encrypt(&buf).unwrap();

// You can also auto-deduce FileType from extension:
// FileType::from("rpgmvp");
// It supports conversions from &str and &OsStr.

// Since [`Decrypter::encrypt`] copies the data, it's pretty much inefficient, and if you don't need to reuse the file data, you can encrypt it in-place:
// let mut buf = read(file).unwrap();
// [`Decrypter::decrypt_in_place`] doesn't include the RPG Maker header in encrypted data,
// but we can write everything into a file more efficient with vectored I/O.
// use rpgm_asset_decrypter_lib::{RPGM_HEADER};
// use std::fs::File;
// use std::io::{self, Write, IoSlice};
// decrypter.encrypt_in_place(&mut buf);
// let mut file = File::create("./encrypted-picture.rpgmvp");
// let bufs = [IoSlice::new(RPGM_HEADER), IoSlice::new(buf)];
// file.write_vectored(&bufs).unwrap();

write("./encrypted-picture.rpgmvp", encrypted).unwrap();
```

## Features

-   `serde` - enables serde serialization/deserialization for `Error` type.
-   `vorbis-key-extraction` - enables key auto-extraction from `rpgmvo`/`ogg_` OGG files. This is made as a feature because it depends on `vorbis-rs` which pulls a handful of libraries.

## License

Project is licensed under WTFPL.
