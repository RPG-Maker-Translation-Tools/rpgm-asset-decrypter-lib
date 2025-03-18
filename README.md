# rpgm-asset-decrypter-lib

A library for decrypting/encrypting RPG Maker MV/MZ audio and image assets.

Used in my [rpgm-asset-decrypter-rs](https://github.com/savannstm/rpgm-asset-decrypter-rs) CLI tool.

## Installation

`cargo add rpgm-asset-decrypter-lib`

## Usage

Decrypt:

```rust
use rpgm_asset_decrypter_lib::Decrypter;
use std::fs::{read, write};

let mut decrypter = Decrypter::new(None);
let file = "./picture.rpgmvp";
let buf = read(file).unwrap();

// For images, decrypter automatically determines the key.
// For audio, read `encryptionKey` property from `System.json` and pass it to `Decrypter` constructor.
let decrypted = decrypter.decrypt(&buf);
write("./decrypted-pitcure.png", decrypted).unwrap();
```

Encrypt:

```rust
use rpgm_asset_decrypter_lib::Decrypter;
use std::fs::{read, write};

// When encrypting, decrypter requires a key.
// It can be read from `encryptionKey` property in `System.json`.
let decrypter = Decrypter::new(Some(String::from("d41d8cd98f00b204e9800998ecf8427e")));
let file = "./picture.png";
let buf = read(file).unwrap();

let encrypted = decrypter.encrypt(&buf);
write("./decrypted-pitcure.rpgmvp", encrypted).unwrap();
```

## License

Project is licensed under WTFPL.
