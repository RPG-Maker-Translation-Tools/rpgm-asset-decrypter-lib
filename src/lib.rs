//! # rpgm-asset-decrypter-lib
//!
//! A library for decrypting/encrypting RPG Maker MV/MZ audio and image assets.
//!
//! Used in [rpgm-asset-decrypter-rs](https://github.com/savannstm/rpgm-asset-decrypter-rs) CLI tool.
//!
//! ## Installation
//!
//! `cargo add rpgm-asset-decrypter-lib`
//!
//! ## Usage
//!
//! Decrypt:
//!
//! ```no_run
//! use rpgm_asset_decrypter_lib::Decrypter;
//! use std::fs::{read, write};
//!
//! let mut decrypter = Decrypter::new();
//! let file = "./picture.rpgmvp";
//! let buf = read(file).unwrap();
//!
//! // For images, decrypter automatically determines the key.
//! // For audio, read `encryptionKey` property from `System.json` and pass it to `Decrypter` constructor.
//! let decrypted = decrypter.decrypt(&buf);
//! write("./decrypted-pitcure.png", decrypted).unwrap();
//! ```
//!
//! Encrypt:
//!
//! ```no_run
//! use rpgm_asset_decrypter_lib::{Decrypter, DEFAULT_KEY};
//! use std::fs::{read, write};
//!
//! // When encrypting, decrypter requires a key.
//! // It can be read from `encryptionKey` property in `System.json`.
//! let mut decrypter = Decrypter::new();
//!
//! // The library provides default key, which most games use by default.
//! // It might not work for every game, so if you get bad output, grab the right one from `System.json`.
//! decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
//! let file = "./picture.png";
//! let buf = read(file).unwrap();
//!
//! let encrypted = decrypter.encrypt(&buf).unwrap();
//! write("./decrypted-pitcure.rpgmvp", encrypted).unwrap();
//! ```
//!
//! ## License
//!
//! Project is licensed under WTFPL.

mod decrypter;
pub use decrypter::{Decrypter, DEFAULT_KEY, KEY_LENGTH};
