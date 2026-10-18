//! WASM bindings for `rpgm-asset-decrypter-lib` via `wasm-bindgen`.
//!
//! No in-place variants: `wasm-bindgen` copies `Uint8Array`s in and out of wasm memory anyway.
//! Errors are thrown as JS `Error`s whose `name` is the library error variant (see [`error_name`]).
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use rpgm_asset_decrypter_lib::{
    DEFAULT_KEY, Decrypter as InnerDecrypter, Error as InnerError, FileType as InnerFileType,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const ERROR_NAME_TYPE: &str = r#"
/** The `name` of every `Error` thrown by this package. */
export type RpgmasdErrorName =
    | "KeyNotSet"
    | "InvalidKeyLength"
    | "InvalidKey"
    | "InvalidHeader"
    | "UnexpectedEOF"
    | "KeyMismatch"
    | "InvalidContent"
    | "UnsupportedExtension"
    | "Unknown";
"#;

#[wasm_bindgen]
extern "C" {
    /// The global JS `Error`, used to set `name` on thrown errors.
    #[wasm_bindgen(js_name = Error)]
    type JsErrorObject;

    #[wasm_bindgen(constructor, js_class = "Error")]
    fn new(message: &str) -> JsErrorObject;

    #[wasm_bindgen(method, setter = name, js_class = "Error")]
    fn set_name(this: &JsErrorObject, name: &str);
}

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
            FileType::Png => Self::Png,
            FileType::Ogg => Self::Ogg,
            FileType::M4a => Self::M4a,
        }
    }
}

impl From<InnerFileType> for FileType {
    fn from(file_type: InnerFileType) -> Self {
        match file_type {
            InnerFileType::Png => Self::Png,
            InnerFileType::Ogg => Self::Ogg,
            InnerFileType::M4a => Self::M4a,
            // `FileType` is non-exhaustive; a type this package doesn't know yet would be a bug in the bindings.
            _ => unreachable!("unsupported file type"),
        }
    }
}

/// The `name` of the JS `Error` thrown for each library error.
#[must_use]
pub const fn error_name(error: &InnerError) -> &'static str {
    match error {
        InnerError::KeyNotSet => "KeyNotSet",
        InnerError::InvalidKeyLength => "InvalidKeyLength",
        InnerError::InvalidKey => "InvalidKey",
        InnerError::InvalidHeader => "InvalidHeader",
        InnerError::UnexpectedEOF => "UnexpectedEOF",
        InnerError::KeyMismatch => "KeyMismatch",
        InnerError::InvalidContent => "InvalidContent",
        InnerError::UnsupportedExtension => "UnsupportedExtension",
        _ => "Unknown",
    }
}

// Passed to map_err by value.
#[allow(clippy::needless_pass_by_value)]
fn to_js_error(error: InnerError) -> JsValue {
    let object = JsErrorObject::new(&error.to_string());
    object.set_name(error_name(&error));
    object.into()
}

/// Deduces the `FileType` from an encrypted asset's extension (`rpgmvp`, `png_`, ...), ignoring case and a leading dot.
///
/// # Errors
///
/// Throws if `extension` isn't a known asset extension.
#[wasm_bindgen(js_name = fileTypeFromExtension)]
pub fn file_type_from_extension(extension: &str) -> Result<FileType, JsValue> {
    extension
        .strip_prefix('.')
        .unwrap_or(extension)
        .parse::<InnerFileType>()
        .map(FileType::from)
        .map_err(to_js_error)
}

/// Decrypts and encrypts RPG Maker MV/MZ assets. Call `free()` (or use `using`) to release it early.
#[wasm_bindgen]
pub struct Decrypter {
    inner: InnerDecrypter,
}

#[wasm_bindgen]
impl Decrypter {
    /// Creates a new `Decrypter` instance.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: InnerDecrypter::new(),
        }
    }

    /// Returns the decrypter's key, or `undefined` if it's not set.
    #[must_use]
    pub fn key(&self) -> Option<String> {
        self.inner.key().map(str::to_owned)
    }

    /// Sets the decrypter's key to the provided hex string.
    ///
    /// # Errors
    ///
    /// Throws if `key` isn't a valid key string.
    #[wasm_bindgen(js_name = setKeyFromStr)]
    pub fn set_key_from_str(&mut self, key: &str) -> Result<(), JsValue> {
        self.inner.set_key_from_str(key).map_err(to_js_error)
    }

    /// Sets the key of the decrypter from encrypted `fileContent` data, returning the derived key string.
    ///
    /// # Errors
    ///
    /// Throws if `file_content` doesn't look like `file_type`, or no key can be derived from it.
    #[wasm_bindgen(js_name = setKeyFromFile)]
    pub fn set_key_from_file(&mut self, file_content: &[u8], file_type: FileType) -> Result<String, JsValue> {
        self.inner
            .set_key_from_file(file_content, file_type.into())
            .map(str::to_owned)
            .map_err(to_js_error)
    }

    /// Decrypts a file, returning a copy. The key is derived from the first file; a file encrypted with another key
    /// throws `KeyMismatch`, so use one `Decrypter` per encryption key.
    ///
    /// # Errors
    ///
    /// Throws if `file_content` doesn't look like `file_type`, or it was encrypted with another key.
    pub fn decrypt(&mut self, file_content: &[u8], file_type: FileType) -> Result<Vec<u8>, JsValue> {
        self.inner.decrypt(file_content, file_type.into()).map_err(to_js_error)
    }

    /// Decrypts a file with the key already set, without deriving one. Throws `KeyNotSet` if there is no key.
    ///
    /// # Errors
    ///
    /// Throws if there is no key, or `file_content` doesn't look like `file_type`.
    #[wasm_bindgen(js_name = decryptKeyed)]
    pub fn decrypt_keyed(&self, file_content: &[u8], file_type: FileType) -> Result<Vec<u8>, JsValue> {
        self.inner
            .decrypt_keyed(file_content, file_type.into())
            .map_err(to_js_error)
    }

    /// Encrypts a file of `fileType`, returning a copy with the RPG Maker header. Throws `KeyNotSet` without a key,
    /// and `InvalidContent` or `UnexpectedEOF` if the file doesn't look like `fileType`.
    ///
    /// # Errors
    ///
    /// Throws if there is no key, or `file_content` doesn't look like `file_type`.
    pub fn encrypt(&self, file_content: &[u8], file_type: FileType) -> Result<Vec<u8>, JsValue> {
        self.inner.encrypt(file_content, file_type.into()).map_err(to_js_error)
    }
}

impl Default for Decrypter {
    fn default() -> Self {
        Self::new()
    }
}

/// Decrypts RPG Maker file content using a temporary `Decrypter` instance.
///
/// # Errors
///
/// Throws if `file_content` doesn't look like `file_type`.
#[wasm_bindgen(js_name = decryptAsset)]
pub fn decrypt_asset(file_content: &[u8], file_type: FileType) -> Result<Vec<u8>, JsValue> {
    rpgm_asset_decrypter_lib::decrypt(file_content, file_type.into()).map_err(to_js_error)
}

/// Encrypts with a key string and a temporary `Decrypter`. The result includes the RPG Maker header.
///
/// # Errors
///
/// Throws if `key` is invalid, or `file_content` doesn't look like `file_type`.
#[wasm_bindgen(js_name = encryptAsset)]
pub fn encrypt_asset(file_content: &[u8], file_type: FileType, key: &str) -> Result<Vec<u8>, JsValue> {
    rpgm_asset_decrypter_lib::encrypt(file_content, file_type.into(), key).map_err(to_js_error)
}

/// The key RPG Maker uses when a project's encryption key is empty.
#[wasm_bindgen(js_name = defaultKey)]
#[must_use]
pub fn default_key() -> String {
    DEFAULT_KEY.to_owned()
}
