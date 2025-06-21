use thiserror::Error;

const HEADER_LENGTH: usize = 16;
const KEY_BYTES_LENGTH: usize = 16;
const PNG_HEADER: [u8; HEADER_LENGTH] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
];
const HEADER: [u8; HEADER_LENGTH] = [
    0x52, 0x50, 0x47, 0x4d, 0x56, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
pub const KEY_LENGTH: usize = 32;
pub const DEFAULT_KEY: &str = "d41d8cd98f00b204e9800998ecf8427e";

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Key must have a fixed length of 32 characters.")]
    InvalidLength,
}

#[derive(Error, Debug)]
pub enum EncryptError {
    #[error("Key must be set using any of `set_key*` methods before calling `encrypt` function.")]
    KeyNotSet,
}

pub struct Decrypter {
    key_hex: [u8; KEY_LENGTH],
    key_bytes: [u8; KEY_BYTES_LENGTH],
    key_set: bool,
}

impl Decrypter {
    /// Creates a new Decrypter instance.
    ///
    /// Decrypter requires a key, which you can set from `set_key_from_str()` and `set_key_from_image()` functions.
    /// You can get the key string from `encryptionKey` field in `System.json` file to set from string, or from any `rpgmvp`/`png_` image.
    ///
    /// `decrypt()` function will try to determine the key from input image files, so you don't need to manually set key for it.
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    fn set_key_bytes(&mut self) {
        for (j, i) in (0..self.key_hex.len()).step_by(2).enumerate() {
            let u8_hex: [u8; 2] = [self.key_hex[i], self.key_hex[i + 1]];
            let u8_hex_str: &str = unsafe { std::str::from_utf8_unchecked(&u8_hex) };
            self.key_bytes[j] = u8::from_str_radix(u8_hex_str, 16).unwrap();
        }
    }

    #[inline]
    fn process_buffer(&self, buffer: &mut [u8]) {
        for (i, item) in buffer.iter_mut().enumerate().take(HEADER_LENGTH) {
            *item ^= self.key_bytes[i];
        }
    }

    /// Returns the decrypter's key, or `None` if it's not set.
    #[inline]
    pub fn key(&self) -> Option<&str> {
        if !self.key_set {
            return None;
        }

        Some(unsafe { std::str::from_utf8_unchecked(&self.key_hex) })
    }

    /// Sets the decrypter's key to provided `&str`.
    /// If key's length is not 32 bytes, the function fails and returns `KeyError`.
    #[inline]
    pub fn set_key_from_str(&mut self, key: &str) -> Result<(), KeyError> {
        if key.len() != 32 {
            return Err(KeyError::InvalidLength);
        }

        self.key_hex = unsafe { *(key.as_bytes().as_ptr() as *const [u8; 32]) };
        self.set_key_bytes();

        self.key_set = true;
        Ok(())
    }

    /// Sets the key of decrypter from encrypted `file_content` image data.
    ///
    /// # Arguments
    ///
    /// - `file_content` - The data of RPG Maker file
    #[inline]
    pub fn set_key_from_image(&mut self, file_content: &[u8]) {
        let header: &[u8] = &file_content[HEADER_LENGTH..HEADER_LENGTH * 2];
        let mut key_hex: [u8; KEY_LENGTH] = [0; KEY_LENGTH];

        for i in (0..HEADER_LENGTH).step_by(2) {
            let value = PNG_HEADER[i] ^ header[i];

            let high = HEX_CHARS[(value >> 4) as usize];
            let low = HEX_CHARS[(value & 0x0F) as usize];

            key_hex[i] = high;
            key_hex[i + 1] = low;
        }

        let key_string = unsafe { std::str::from_utf8_unchecked(&key_hex) };
        let _ = self.set_key_from_str(key_string);
    }

    /// Decrypts RPG Maker file content.
    /// Auto-determines the key from the input file.
    ///
    /// # Arguments
    ///
    /// - `file_content` - The data of RPG Maker file.
    ///
    /// # Returns
    ///
    /// - `Vec<u8>` containing decrypted data.
    #[inline]
    pub fn decrypt(&mut self, file_content: &[u8]) -> Vec<u8> {
        if !self.key_set {
            self.set_key_from_image(file_content);
        }

        let mut result: Vec<u8> = file_content[HEADER_LENGTH..].to_vec();
        self.process_buffer(&mut result);
        result
    }

    /// Encrypts file content.
    ///
    /// This function requires decrypter to have a key, which you can fetch from `System.json` file
    /// or by calling `set_key_from_image()` with the data from encrypted image file.
    ///
    /// # Arguments
    ///
    /// - `file_content` - The data of `.png`, `.ogg` or `.m4a` file.
    ///
    /// # Returns
    ///
    /// - `Vec<u8>` containing encrypted data, or `KeyError` if key is not set.
    #[inline]
    #[track_caller]
    pub fn encrypt(&self, file_content: &[u8]) -> Result<Vec<u8>, EncryptError> {
        if !self.key_set {
            return Err(EncryptError::KeyNotSet);
        }

        let mut data: Vec<u8> = file_content.to_vec();
        self.process_buffer(&mut data);

        let mut output_data: Vec<u8> = Vec::with_capacity(HEADER.len() + data.len());
        output_data.extend(HEADER);
        output_data.extend(data);
        Ok(output_data)
    }
}

impl Default for Decrypter {
    fn default() -> Self {
        Self {
            key_hex: [0; KEY_LENGTH],
            key_bytes: [0; KEY_BYTES_LENGTH],
            key_set: false,
        }
    }
}
