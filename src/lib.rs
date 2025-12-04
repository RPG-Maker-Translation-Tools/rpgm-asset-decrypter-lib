#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::needless_doctest_main)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::deref_addrof)]
#![doc = include_str!("../README.md")]

use std::{
    convert::TryFrom,
    ffi::OsStr,
    fmt::Display,
    io::{Cursor, Read, Seek, SeekFrom},
};
use thiserror::Error;

macro_rules! sizeof {
    ($t:ty) => {{ size_of::<$t>() }};
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

pub const HEADER_LENGTH: usize = 16;

pub const KEY_LENGTH: usize = 16;
pub const KEY_STR_LENGTH: usize = 32;

// Key used in RPG Maker encrypted files when "Encryption key" is left unfilled.
pub const DEFAULT_KEY: &str = "d41d8cd98f00b204e9800998ecf8427e";

// RPG Maker's encoding is essentially taking source file's header (16 bytes) and xor'ing it upon a MD5 key produced from encryption key string. Most projects leave encryption key string empty, so resulting 'encryption' is just header xor'd with default MD5 key.

// For PNG, header is always the same, so we can expect valid decryption.
const PNG_HEADER: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
    0x49, 0x48, 0x44, 0x52,
];

// 0 - 3 - OggS
// 4 - version, always 0
// 5 - header type, always 0x02, since first page always announces the beginning of the stream
// 6 - 13 - granule position, always 0, since first page has no actual data
//* 14 - 15 - part of 4-byte bitstream serial number, that actually differs between files
static mut OGG_HEADER: [u8; HEADER_LENGTH] =
    [79, 103, 103, 83, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

//* 0 - 3 - type box size, actually differs between files
// 4 - 7 - ftyp, always the same
// 8 - 11 - M4A_, always the same, may be different 4 characters, but extremely unlikely
// 12 - 15 - minor version, mostly junk, doesn't matter
static mut M4A_HEADER: [u8; HEADER_LENGTH] =
    [0, 0, 0, 28, 102, 116, 121, 112, 77, 52, 65, 32, 0, 0, 2, 0];

// For finding type box size
const M4A_POST_HEADER_BOXES: &[&[u8]] =
    &[b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot"];

// Every encrypted file includes this header.
pub const RPGM_HEADER: &[u8] = &[
    0x52, 0x50, 0x47, 0x4d, 0x56, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

pub const MV_PNG_EXT: &str = "rpgmvp";
pub const MZ_PNG_EXT: &str = "png_";
pub const MV_OGG_EXT: &str = "rpgmvo";
pub const MZ_OGG_EXT: &str = "ogg_";
pub const MV_M4A_EXT: &str = "rpgmvm";
pub const MZ_M4A_EXT: &str = "m4a_";

pub const PNG_EXT: &str = "png";
pub const OGG_EXT: &str = "ogg";
pub const M4A_EXT: &str = "m4a";

pub const ENCRYPTED_ASSET_EXTS: &[&str] = &[
    MV_PNG_EXT, MV_OGG_EXT, MV_M4A_EXT, MZ_PNG_EXT, MZ_OGG_EXT, MZ_M4A_EXT,
];
pub const DECRYPTED_ASSETS_EXTS: &[&str] = &[PNG_EXT, OGG_EXT, M4A_EXT];

#[derive(PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum FileType {
    PNG,
    OGG,
    M4A,
}

impl FileType {
    #[must_use]
    pub fn is_png(self) -> bool {
        matches!(self, Self::PNG)
    }

    #[must_use]
    pub fn is_ogg(self) -> bool {
        matches!(self, Self::OGG)
    }

    #[must_use]
    pub fn is_m4a(self) -> bool {
        matches!(self, Self::M4A)
    }
}

impl Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PNG => f.write_str("png"),
            Self::OGG => f.write_str("ogg"),
            Self::M4A => f.write_str("m4a"),
        }
    }
}

impl TryFrom<&str> for FileType {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            MV_PNG_EXT | MZ_PNG_EXT => Ok(FileType::PNG),
            MV_OGG_EXT | MZ_OGG_EXT => Ok(FileType::OGG),
            MV_M4A_EXT | MZ_M4A_EXT => Ok(FileType::M4A),
            _ => Err("Extension not supported"),
        }
    }
}

// [`PathBuf::extension`] returns &OsStr, so implement this for convenience.
impl TryFrom<&OsStr> for FileType {
    type Error = &'static str;

    fn try_from(value: &OsStr) -> Result<Self, Self::Error> {
        if value == MV_PNG_EXT || value == MZ_PNG_EXT {
            Ok(FileType::PNG)
        } else if value == MV_OGG_EXT || value == MZ_OGG_EXT {
            Ok(FileType::OGG)
        } else if value == MV_M4A_EXT || value == MZ_M4A_EXT {
            Ok(FileType::M4A)
        } else {
            Err("Extension not supported")
        }
    }
}

#[derive(Debug, Error)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum Error {
    #[error(
        "Key must be set using any of `set_key` methods before calling `encrypt` function."
    )]
    KeyNotSet,
    #[error("Key must have a fixed length of 32 characters.")]
    InvalidKeyLength,
    #[error(
        "Passed data has invalid header. RPG Maker encrypted files should always start with RPGMV header. Either passed data is not RPG Maker data or it's corrupted."
    )]
    InvalidHeader,
    #[error(
        "Unexpected end of file encountered. Either passed data is not RPG Maker data or it's corrupted."
    )]
    UnexpectedEOF,
}

#[derive(Default)]
pub struct Decrypter {
    key_hex: [u8; KEY_STR_LENGTH],
    key: [u8; KEY_LENGTH],
    has_key: bool,
}

impl Decrypter {
    /// Creates a new Decrypter instance.
    ///
    /// Decrypter requires a key, which you can set from [`Decrypter::set_key_from_str`] and [`Decrypter::set_key_from_file`] functions.
    /// You can get the key string from `encryptionKey` field in `System.json` file or from any encrypted RPG Maker file.
    ///
    /// [`Decrypter::decrypt`] function will automatically determine the key from the input file, so you usually don't need to set it manually.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    /// Converts human-readable hex to the real key bytes.
    fn set_key_from_hex(&mut self) {
        for (j, i) in (0..self.key_hex.len()).step_by(2).enumerate() {
            let u8_hex = [self.key_hex[i], self.key_hex[i + 1]];
            let u8_hex_str = unsafe { std::str::from_utf8_unchecked(&u8_hex) };
            self.key[j] = u8::from_str_radix(u8_hex_str, 16).unwrap();
        }

        self.has_key = true;
    }

    #[inline]
    /// Either decrypts or encrypts the passed buffer, depending on the place this function was invoked from.
    ///
    /// Actual encryption is just: xor buffer's first 16 bytes with key.
    fn xor_buffer(&self, buffer: &mut [u8]) {
        for (i, item) in buffer.iter_mut().enumerate().take(HEADER_LENGTH) {
            *item ^= self.key[i];
        }
    }

    fn read_ogg_page_serialno(file_content: &mut Cursor<&[u8]>) -> u32 {
        const HEADER_SIZE: usize = 27;
        const SERIALNO_POS: usize = 14;

        let mut header: [u8; HEADER_SIZE] = [0; HEADER_SIZE];

        file_content.read_exact(&mut header).unwrap();

        let segment_count: usize = header[26] as usize;
        let mut segment_table: [u8; u8::MAX as usize] = [0; u8::MAX as usize];

        file_content.read_exact(&mut segment_table).unwrap();

        let over_count = i64::from(u8::MAX) - segment_count as i64;

        file_content.seek(SeekFrom::Current(-over_count)).unwrap();

        let mut body_length: i64 = 0;

        for segment in segment_table.iter().take(segment_count) {
            body_length += i64::from(*segment);
        }

        file_content.seek(SeekFrom::Current(body_length)).unwrap();

        let header_serialno = unsafe {
            *header[SERIALNO_POS..SERIALNO_POS + sizeof!(u32)]
                .as_ptr()
                .cast::<[u8; sizeof!(u32)]>()
        };

        u32::from(header_serialno[0])
            | (u32::from(header_serialno[1]) << 8)
            | (u32::from(header_serialno[2]) << 16)
            | (u32::from(header_serialno[3]) << 24)
    }

    /// Returns the decrypter's key, or [`None`] if it's not set.
    #[inline]
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        if !self.has_key {
            return None;
        }

        Some(unsafe { std::str::from_utf8_unchecked(&self.key_hex) })
    }

    /// Sets the decrypter's key to provided `&str` hex string.
    ///
    /// # Returns
    ///
    /// If key's length is not 32 bytes, the function fails and returns [`Error`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKeyLength`] - if key's length is not 32 bytes.
    #[inline]
    pub fn set_key_from_str(&mut self, key: &str) -> Result<(), Error> {
        if key.len() != KEY_STR_LENGTH {
            return Err(Error::InvalidKeyLength);
        }

        self.key_hex =
            unsafe { *key.as_bytes().as_ptr().cast::<[u8; KEY_STR_LENGTH]>() };
        self.set_key_from_hex();

        Ok(())
    }

    /// Sets the key of decrypter from encrypted `file_content` data.
    ///
    /// # Parameters
    ///
    /// - `file_content` - The data of RPG Maker file.
    ///
    /// # Returns
    ///
    /// - Reference to the key string, if succeeded.
    /// - [`Error`] otherwise.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidHeader`] - if passed `file_content` data contains invalid header.
    /// - [`Error::UnexpectedEOF`] - if passed `file_content` data ends unexpectedly.
    #[inline]
    pub fn set_key_from_file(
        &mut self,
        file_content: &[u8],
        file_type: FileType,
    ) -> Result<&str, Error> {
        if !file_content.starts_with(RPGM_HEADER) {
            return Err(Error::InvalidHeader);
        }

        let Some(post_header) =
            file_content.get(HEADER_LENGTH..HEADER_LENGTH * 2)
        else {
            return Err(Error::UnexpectedEOF);
        };

        // Get proper M4A header box size
        //* We don't care about anything else for M4A, since `ftypM4A_` in M4A header can be easily replaced by `ftypSHIT`, and FFmpeg will have ZERO complains.
        //* The same goes for 12-15 bytes (inclusive), they can be overwritten with whatever integer.
        if file_type.is_m4a() {
            const CHUNK_SIZE: usize = sizeof!(u32);

            let Some(file_start) =
                file_content.get(HEADER_LENGTH..HEADER_LENGTH + 64)
            else {
                return Err(Error::UnexpectedEOF);
            };

            let file_start_chunks = file_start.chunks_exact(CHUNK_SIZE);

            for (i, chunk) in file_start_chunks.enumerate() {
                if M4A_POST_HEADER_BOXES.contains(&chunk) {
                    let prev_chunk_i = i - 1;
                    let header_type_box_size =
                        (prev_chunk_i * CHUNK_SIZE) as u32;

                    unsafe {
                        M4A_HEADER[..CHUNK_SIZE].copy_from_slice(
                            &header_type_box_size.to_be_bytes(),
                        );
                    }
                }
            }
        }

        // Since stream serial number is incorrect in OGG_HEADER because it's different for each file, we need to seek to the second page of the stream and grab the serial number from there, and then replace it in the header.
        // Serial number is persistent across all pages of the stream, so we can gan grab it from the second page and replace in the first.
        if file_type.is_ogg() {
            let mut file_content_cursor =
                Cursor::new(&file_content[HEADER_LENGTH..]);

            Decrypter::read_ogg_page_serialno(&mut file_content_cursor);

            let serialno =
                Decrypter::read_ogg_page_serialno(&mut file_content_cursor);

            unsafe {
                OGG_HEADER[14..16]
                    .clone_from_slice(&serialno.to_le_bytes()[0..2]);
            }
        }

        let mut j = 0;
        for i in 0..HEADER_LENGTH {
            let signature_byte = match file_type {
                FileType::PNG => PNG_HEADER[i],
                FileType::OGG => unsafe { OGG_HEADER[i] },
                FileType::M4A => unsafe { M4A_HEADER[i] },
            };

            let value = signature_byte ^ post_header[i];

            let high = HEX_CHARS[(value >> 4) as usize];
            let low = HEX_CHARS[(value & 0x0F) as usize];

            self.key_hex[j] = high;
            self.key_hex[j + 1] = low;
            j += 2;
        }

        self.set_key_from_hex();
        Ok(unsafe { std::str::from_utf8_unchecked(&self.key_hex) })
    }

    /// Decrypts RPG Maker file content.
    /// Auto-determines the key from the input file.
    ///
    /// This function copies the contents of the file and returns decrypted [`Vec<u8>`] copy.
    /// If you want to avoid copying, see [`Decrypter::decrypt_in_place`] function.
    ///
    /// # Parameters
    ///
    /// - `file_content` - The data of RPG Maker file.
    /// - `file_type` - [`FileType`], representing whether passed file content is PNG, OGG or M4A.
    ///
    /// # Returns
    ///
    /// - [`Error`], if passed `file_content` data has invalid header.
    /// - [`Vec<u8>`] containing decrypted data otherwise.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidHeader`] - if passed `file_content` data has invalid header.
    /// - [`Error::UnexpectedEOF`] - if passed `file_content` data ends unexpectedly.
    #[inline]
    pub fn decrypt(
        &mut self,
        file_content: &[u8],
        file_type: FileType,
    ) -> Result<Vec<u8>, Error> {
        if !file_content.starts_with(RPGM_HEADER) {
            return Err(Error::InvalidHeader);
        }

        if !self.has_key {
            self.set_key_from_file(file_content, file_type)?;
        }

        let mut result = file_content[HEADER_LENGTH..].to_vec();
        self.xor_buffer(&mut result);
        Ok(result)
    }

    /// Decrypts RPG Maker file content.
    /// Auto-determines the key from the input file.
    ///
    /// This function decrypts the passed file data in-place.
    /// If you don't want to modify passed data, see [`Decrypter::decrypt`] function.
    ///
    /// # Note
    ///
    /// Decrypted data is only valid starting at offset 16. This function returns the reference to the correct slice.
    ///
    /// # Parameters
    ///
    /// - `file_content` - The data of RPG Maker file.
    /// - `file_type` - [`FileType`], representing whether passed file content is PNG, OGG or M4A.
    ///
    /// # Returns
    ///
    /// - [`Error`], if passed `file_content` data has invalid header.
    /// - Reference to a slice of the passed `file_content` data starting at offset 16 otherwise.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidHeader`] - if passed `file_content` data has invalid header.
    /// - [`Error::UnexpectedEOF`] - if passed `file_content` data ends unexpectedly.
    #[inline]
    pub fn decrypt_in_place<'a>(
        &'a mut self,
        file_content: &'a mut [u8],
        file_type: FileType,
    ) -> Result<&'a [u8], Error> {
        if !file_content.starts_with(RPGM_HEADER) {
            return Err(Error::InvalidHeader);
        }

        if !self.has_key {
            self.set_key_from_file(file_content, file_type)?;
        }

        let sliced_past_header = &mut file_content[HEADER_LENGTH..];
        self.xor_buffer(sliced_past_header);
        Ok(sliced_past_header)
    }

    /// Encrypts file content.
    ///
    /// This function requires decrypter to have a key, which you can fetch from `System.json` file
    /// or by calling [`Decrypter::set_key_from_file`] with the data from encrypted file.
    ///
    /// This function copies the contents of the file and returns encrypted [`Vec<u8>`] copy.
    /// If you want to avoid copying, see [`Decrypter::encrypt_in_place`] function.
    ///
    /// # Parameters
    ///
    /// - `file_content` - The data of `.png`, `.ogg` or `.m4a` file.
    ///
    /// # Returns
    ///
    /// - [`Vec<u8>`] containing encrypted data if decrypter key is set.
    /// - [`Error`] otherwise.
    ///
    /// # Errors
    ///
    /// - [`Error::KeyNotSet`] - if decrypter's key is not set.
    #[inline]
    pub fn encrypt(&self, file_content: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.has_key {
            return Err(Error::KeyNotSet);
        }

        let mut data = file_content.to_vec();
        self.xor_buffer(&mut data);

        let mut output_data = Vec::with_capacity(HEADER_LENGTH + data.len());
        output_data.extend(RPGM_HEADER);
        output_data.extend(data);
        Ok(output_data)
    }

    /// Encrypts file content in-place.
    ///
    /// This function requires decrypter to have a key, which you can fetch from `System.json` file
    /// or by calling [`Decrypter::set_key_from_file`] with the data from encrypted file.
    ///
    /// This function encrypts the passed file data in-place.
    /// If you don't want to modify passed data, see [`Decrypter::encrypt`] function.
    ///
    /// # Note
    ///
    /// Encrypted data comes without the RPG Maker header, so you need to manually prepend it - but you can decide where and how to do it most efficient.
    /// The header is exported as [`RPGM_HEADER`].
    ///
    /// # Parameters
    ///
    /// - `file_content` - The data of `.png`, `.ogg` or `.m4a` file.
    ///
    /// # Returns
    ///
    /// - Nothing, if decrypter key is set.
    /// - [`Error`] otherwise.
    ///
    /// # Errors
    ///
    /// - [`Error::KeyNotSet`] - if decrypter's key is not set.
    #[inline]
    pub fn encrypt_in_place(
        &self,
        file_content: &mut [u8],
    ) -> Result<(), Error> {
        if !self.has_key {
            return Err(Error::KeyNotSet);
        }

        self.xor_buffer(file_content);
        Ok(())
    }
}

/// Decrypts RPG Maker file content using a temporary [`Decrypter`] instance.
///
/// This is a convenience wrapper around [`Decrypter::decrypt`].
/// A new [`Decrypter`] is created internally, and the decryption key is
/// auto-determined from the provided file data.
///
/// This function copies the contents of the file and returns a decrypted [`Vec<u8>`].
/// If you want to avoid copying, use [`decrypt_in_place`] instead.
///
/// # Parameters
///
/// - `file_content` - The data of RPG Maker file.
/// - `file_type` - [`FileType`], representing whether passed file content is PNG, OGG or M4A.
///
/// # Returns
///
/// - [`Error`] if the passed data has an invalid header or ends unexpectedly.
/// - Decrypted [`Vec<u8>`] otherwise.
///
/// # Errors
///
/// - [`Error::InvalidHeader`] – if the provided `file_content` does not start with the RPG Maker header.
/// - [`Error::UnexpectedEOF`] – if the data ends unexpectedly.
pub fn decrypt(
    file_content: &[u8],
    file_type: FileType,
) -> Result<Vec<u8>, Error> {
    Decrypter::new().decrypt(file_content, file_type)
}

/// Decrypts RPG Maker file content in-place using a temporary [`Decrypter`] instance.
///
/// This is a convenience wrapper around [`Decrypter::decrypt_in_place`].
/// A new [`Decrypter`] is created internally, and the decryption key is
/// auto-determined from the provided file data.
///
/// This function modifies the provided buffer directly.
/// After successful decryption, the decrypted data is valid starting at offset 16.
///
/// If you do not want to modify data in-place, use [`decrypt`] instead.
///
/// # Parameters
///
/// - `file_content` - The data of RPG Maker file.
/// - `file_type` - [`FileType`], representing whether passed file content is PNG, OGG or M4A.
///
/// # Returns
///
/// - [`Error`] if the passed data has an invalid header or ends unexpectedly.
/// - Nothing otherwise.
///
/// # Errors
///
/// - [`Error::InvalidHeader`] – if the provided `file_content` does not start with the RPG Maker header.
/// - [`Error::UnexpectedEOF`] – if the data ends unexpectedly.
pub fn decrypt_in_place(
    file_content: &mut [u8],
    file_type: FileType,
) -> Result<(), Error> {
    Decrypter::new().decrypt_in_place(file_content, file_type)?;
    Ok(())
}

/// Encrypts file content using a key string and a temporary [`Decrypter`] instance.
///
/// This is a convenience wrapper around [`Decrypter::encrypt`].
/// A new [`Decrypter`] is created internally, and the key is set from the provided string.
///
/// This function copies the file contents and returns an encrypted [`Vec<u8>`].
/// The output includes the RPG Maker encryption header (`RPGM_HEADER`).
///
/// If you want to avoid copying, use [`encrypt_in_place`] instead.
///
/// # Parameters
///
/// - `file_content` - The data of `.png`, `.ogg` or `.m4a` file.
/// - `key` - Encryption key string.
///
/// # Returns
///
/// - Encrypted [`Vec<u8>`] if the key is valid.
/// - [`Error`] otherwise.
///
/// # Errors
///
/// - [`Error::InvalidKeyLength`] - if key's length is not 32 bytes.
/// - [`Error::KeyNotSet`] – if key initialization fails.
pub fn encrypt(file_content: &[u8], key: &str) -> Result<Vec<u8>, Error> {
    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(key)?;
    decrypter.encrypt(file_content)
}

/// Encrypts file content in-place using a key string and a temporary [`Decrypter`] instance.
///
/// This is a convenience wrapper around [`Decrypter::encrypt_in_place`].
/// A new [`Decrypter`] is created internally, and the key is set from the provided string.
///
/// This function modifies the file data directly and produces *only* the encrypted payload.
/// The RPG Maker encryption header is **not** added automatically; it must be prepended manually
/// if producing a complete `.rpgmvp`, `.rpgmvo`, or `.rpgmvw` file.
///
/// If you do not want to modify data in-place, use [`encrypt`] instead.
///
/// # Parameters
///
/// - `file_content` - The data of `.png`, `.ogg` or `.m4a` file.
/// - `key` - Encryption key string.
///
/// # Returns
///
/// - [`Error`] if key's length is not 32 bytes.
/// - Nothing otherwise.
///
/// # Errors
///
/// - [`Error::InvalidKeyLength`] - if key's length is not 32 bytes.
pub fn encrypt_in_place(
    file_content: &mut [u8],
    key: &str,
) -> Result<(), Error> {
    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(key)?;
    decrypter.encrypt_in_place(file_content)?;
    Ok(())
}
