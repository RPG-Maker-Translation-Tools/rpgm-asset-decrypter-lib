//! WASM bindings for `rpgm-asset-decrypter-lib`, generated via `wasm-bindgen`.
//!
//! Unlike the archive-decrypter crate's `Decrypter`, this library's `Decrypter` doesn't borrow its input - its
//! state (the key bytes) is fully owned - so it maps onto a stateful `wasm-bindgen` class directly. The in-place
//! methods take `&mut [u8]`: `wasm-bindgen` copies the passed `Uint8Array`'s bytes in, runs the call, and copies
//! the (possibly mutated) bytes back out afterward, so mutations are visible to the caller once the call returns,
//! same as the reference in-place methods.

use rpgm_asset_decrypter_lib::{Decrypter as InnerDecrypter, Error as InnerError, FileType as InnerFileType};
use wasm_bindgen::prelude::*;

/// The original, decrypted asset kind.
#[wasm_bindgen]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FileType {
    Png,
    Ogg,
    M4a,
}

impl From<FileType> for InnerFileType {
    fn from(file_type: FileType) -> Self {
        match file_type {
            FileType::Png => InnerFileType::PNG,
            FileType::Ogg => InnerFileType::OGG,
            FileType::M4a => InnerFileType::M4A,
        }
    }
}

fn to_js_error(error: InnerError) -> JsError {
    JsError::new(&error.to_string())
}

/// A struct responsible for decrypting and encrypting RPG Maker MV/MZ assets.
#[wasm_bindgen]
pub struct Decrypter {
    inner: InnerDecrypter,
}

#[wasm_bindgen]
impl Decrypter {
    /// Creates a new `Decrypter` instance.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Decrypter {
        Decrypter {
            inner: InnerDecrypter::new(),
        }
    }

    /// Returns the decrypter's key, or `undefined` if it's not set.
    pub fn key(&self) -> Option<String> {
        self.inner.key().map(str::to_owned)
    }

    /// Sets the decrypter's key to the provided hex string.
    #[wasm_bindgen(js_name = setKeyFromStr)]
    pub fn set_key_from_str(&mut self, key: &str) -> Result<(), JsError> {
        self.inner.set_key_from_str(key).map_err(to_js_error)
    }

    /// Sets the key of the decrypter from encrypted `fileContent` data, returning the derived key string.
    #[wasm_bindgen(js_name = setKeyFromFile)]
    pub fn set_key_from_file(&mut self, file_content: &[u8], file_type: FileType) -> Result<String, JsError> {
        self.inner
            .set_key_from_file(file_content, file_type.into())
            .map(str::to_owned)
            .map_err(to_js_error)
    }

    /// Decrypts RPG Maker file content, returning a decrypted copy. Auto-determines the key from the input file.
    pub fn decrypt(&mut self, file_content: &[u8], file_type: FileType) -> Result<Vec<u8>, JsError> {
        self.inner.decrypt(file_content, file_type.into()).map_err(to_js_error)
    }

    /// Decrypts RPG Maker file content in place. Auto-determines the key from the input file.
    #[wasm_bindgen(js_name = decryptInPlace)]
    pub fn decrypt_in_place(&mut self, file_content: &mut [u8], file_type: FileType) -> Result<(), JsError> {
        self.inner
            .decrypt_in_place(file_content, file_type.into())
            .map_err(to_js_error)?;

        Ok(())
    }

    /// Encrypts file content, returning an encrypted copy prefixed with the RPG Maker header.
    pub fn encrypt(&self, file_content: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner.encrypt(file_content).map_err(to_js_error)
    }

    /// Encrypts file content in place. Produces the raw encrypted payload, without the RPG Maker header.
    #[wasm_bindgen(js_name = encryptInPlace)]
    pub fn encrypt_in_place(&self, file_content: &mut [u8]) -> Result<(), JsError> {
        self.inner.encrypt_in_place(file_content).map_err(to_js_error)
    }
}

impl Default for Decrypter {
    fn default() -> Self {
        Self::new()
    }
}

/// Decrypts RPG Maker file content using a temporary `Decrypter` instance.
#[wasm_bindgen(js_name = decryptAsset)]
pub fn decrypt_asset(file_content: &[u8], file_type: FileType) -> Result<Vec<u8>, JsError> {
    InnerDecrypter::new()
        .decrypt(file_content, file_type.into())
        .map_err(to_js_error)
}

/// Decrypts RPG Maker file content in place using a temporary `Decrypter` instance.
#[wasm_bindgen(js_name = decryptAssetInPlace)]
pub fn decrypt_asset_in_place(file_content: &mut [u8], file_type: FileType) -> Result<(), JsError> {
    InnerDecrypter::new()
        .decrypt_in_place(file_content, file_type.into())
        .map_err(to_js_error)?;

    Ok(())
}

/// Encrypts file content using a key string and a temporary `Decrypter` instance.
#[wasm_bindgen(js_name = encryptAsset)]
pub fn encrypt_asset(file_content: &[u8], key: &str) -> Result<Vec<u8>, JsError> {
    let mut decrypter = InnerDecrypter::new();
    decrypter.set_key_from_str(key).map_err(to_js_error)?;
    decrypter.encrypt(file_content).map_err(to_js_error)
}

/// Encrypts file content in place using a key string and a temporary `Decrypter` instance.
#[wasm_bindgen(js_name = encryptAssetInPlace)]
pub fn encrypt_asset_in_place(file_content: &mut [u8], key: &str) -> Result<(), JsError> {
    let mut decrypter = InnerDecrypter::new();
    decrypter.set_key_from_str(key).map_err(to_js_error)?;
    decrypter.encrypt_in_place(file_content).map_err(to_js_error)
}
