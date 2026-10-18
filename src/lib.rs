#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::cast_possible_truncation)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Length of the RPG Maker encryption header, in bytes.
pub const HEADER_LENGTH: usize = 16;

/// Length of the key, in bytes.
pub const KEY_LENGTH: usize = 16;
/// Length of the key as a hex string, in characters.
pub const KEY_STR_LENGTH: usize = 32;

/// Key RPG Maker uses when a project's "Encryption key" is left empty, as a hex string.
pub const DEFAULT_KEY: &str = "d41d8cd98f00b204e9800998ecf8427e";

// The 16-byte header is XORed with an MD5-derived key. Most projects leave the encryption key empty, so the default key applies.

// For PNG, header is always the same, so we can expect valid decryption.
const PNG_HEADER: [u8; HEADER_LENGTH] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
];

// 0 - 3 - OggS
// 4 - version, always 0
// 5 - header type, always 0x02, since first page always announces the beginning of the stream
// 6 - 13 - granule position, always 0, since first page has no actual data
//* 14 - 15 - part of 4-byte bitstream serial number, that actually differs between files
const OGG_HEADER: [u8; HEADER_LENGTH] = [79, 103, 103, 83, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

//* 0 - 3 - type box size, actually differs between files
// 4 - 7 - ftyp, always the same
// 8 - 11 - M4A_, always the same, may be different 4 characters, but extremely unlikely
// 12 - 15 - minor version, mostly junk, doesn't matter
const M4A_HEADER: [u8; HEADER_LENGTH] = [0, 0, 0, 0, 102, 116, 121, 112, 77, 52, 65, 32, 0, 0, 2, 0];

// The bytes every file of a type starts with, at a fixed offset: all that can be checked without knowing anything else.
const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";
const OGG_MAGIC: &[u8] = b"OggS";
const M4A_MAGIC: (usize, &[u8]) = (4, b"ftyp");

// For finding type box size
const M4A_POST_HEADER_BOXES: &[&[u8]] = &[b"moov", b"mdat", b"free", b"skip", b"wide", b"pnot"];

/// Header every RPG Maker encrypted file starts with. [`Decrypter::encrypt`] includes it; the `*_encrypt_in_place`
/// output needs it prepended.
pub const RPGM_HEADER: &[u8] = &[
    0x52, 0x50, 0x47, 0x4d, 0x56, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Encrypted extension of a PNG asset in RPG Maker MV.
pub const MV_PNG_EXT: &str = "rpgmvp";
/// Encrypted extension of a PNG asset in RPG Maker MZ.
pub const MZ_PNG_EXT: &str = "png_";
/// Encrypted extension of an OGG asset in RPG Maker MV.
pub const MV_OGG_EXT: &str = "rpgmvo";
/// Encrypted extension of an OGG asset in RPG Maker MZ.
pub const MZ_OGG_EXT: &str = "ogg_";
/// Encrypted extension of an M4A asset in RPG Maker MV.
pub const MV_M4A_EXT: &str = "rpgmvm";
/// Encrypted extension of an M4A asset in RPG Maker MZ.
pub const MZ_M4A_EXT: &str = "m4a_";

/// Decrypted extension of a PNG asset.
pub const PNG_EXT: &str = "png";
/// Decrypted extension of an OGG asset.
pub const OGG_EXT: &str = "ogg";
/// Decrypted extension of an M4A asset.
pub const M4A_EXT: &str = "m4a";

/// Every encrypted asset extension, MV and MZ.
pub const ENCRYPTED_ASSET_EXTS: &[&str] = &[MV_PNG_EXT, MV_OGG_EXT, MV_M4A_EXT, MZ_PNG_EXT, MZ_OGG_EXT, MZ_M4A_EXT];
/// Every decrypted asset extension.
pub const DECRYPTED_ASSET_EXTS: &[&str] = &[PNG_EXT, OGG_EXT, M4A_EXT];

/// The kind of the original, decrypted asset.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum FileType {
    /// PNG image (`rpgmvp`/`png_`).
    Png,
    /// OGG audio (`rpgmvo`/`ogg_`).
    Ogg,
    /// M4A audio (`rpgmvm`/`m4a_`).
    M4a,
}

impl FileType {
    /// Whether this is [`FileType::Png`].
    #[must_use]
    pub const fn is_png(self) -> bool {
        matches!(self, Self::Png)
    }

    /// Whether this is [`FileType::Ogg`].
    #[must_use]
    pub const fn is_ogg(self) -> bool {
        matches!(self, Self::Ogg)
    }

    /// Whether this is [`FileType::M4a`].
    #[must_use]
    pub const fn is_m4a(self) -> bool {
        matches!(self, Self::M4a)
    }

    /// The extension of the decrypted file: `png`, `ogg` or `m4a`.
    #[must_use]
    pub const fn decrypted_extension(self) -> &'static str {
        match self {
            Self::Png => PNG_EXT,
            Self::Ogg => OGG_EXT,
            Self::M4a => M4A_EXT,
        }
    }

    /// The encrypted extension: MZ (`png_`, `ogg_`, `m4a_`) if `mz`, otherwise MV (`rpgmvp`, `rpgmvo`, `rpgmvm`).
    #[must_use]
    pub const fn encrypted_extension(self, mz: bool) -> &'static str {
        match (self, mz) {
            (Self::Png, true) => MZ_PNG_EXT,
            (Self::Png, false) => MV_PNG_EXT,
            (Self::Ogg, true) => MZ_OGG_EXT,
            (Self::Ogg, false) => MV_OGG_EXT,
            (Self::M4a, true) => MZ_M4A_EXT,
            (Self::M4a, false) => MV_M4A_EXT,
        }
    }

    /// The offset and the bytes that every file of this type starts with.
    const fn magic(self) -> (usize, &'static [u8]) {
        match self {
            Self::Png => (0, PNG_MAGIC),
            Self::Ogg => (0, OGG_MAGIC),
            Self::M4a => M4A_MAGIC,
        }
    }

    /// Whether `plain` (decrypted file content) starts with this type's magic bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEOF`] if `plain` is shorter than the magic, or [`Error::InvalidContent`] if it differs.
    pub fn check_plain(self, plain: &[u8]) -> Result<(), Error> {
        let (offset, magic) = self.magic();
        let start = plain.get(offset..offset + magic.len()).ok_or(Error::UnexpectedEOF)?;

        if start == magic {
            Ok(())
        } else {
            Err(Error::InvalidContent)
        }
    }
}

impl core::fmt::Display for FileType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.decrypted_extension())
    }
}

/// Parses an encrypted asset extension (`rpgmvp`, `png_`, ...), ignoring case.
impl core::str::FromStr for FileType {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let is = |ext: &str| value.eq_ignore_ascii_case(ext);

        if is(MV_PNG_EXT) || is(MZ_PNG_EXT) {
            Ok(Self::Png)
        } else if is(MV_OGG_EXT) || is(MZ_OGG_EXT) {
            Ok(Self::Ogg)
        } else if is(MV_M4A_EXT) || is(MZ_M4A_EXT) {
            Ok(Self::M4a)
        } else {
            Err(Error::UnsupportedExtension)
        }
    }
}

impl core::convert::TryFrom<&str> for FileType {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

/// Parses an encrypted asset extension from an `&OsStr`, such as [`std::path::Path::extension`]'s result.
#[cfg(feature = "std")]
impl core::convert::TryFrom<&std::ffi::OsStr> for FileType {
    type Error = Error;

    fn try_from(value: &std::ffi::OsStr) -> Result<Self, Self::Error> {
        value.to_str().ok_or(Error::UnsupportedExtension)?.parse()
    }
}

/// Errors returned by this crate.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[non_exhaustive]
pub enum Error {
    #[error(
        "Key must be set using any of `set_key` methods before calling a function that needs one, such as `encrypt` \
         or `decrypt_keyed`."
    )]
    KeyNotSet,
    #[error("Key must have a fixed length of 32 characters.")]
    InvalidKeyLength,
    #[error("Key must consist of hexadecimal digits only.")]
    InvalidKey,
    #[error(
        "Passed data has invalid header. RPG Maker encrypted files should always start with RPGMV header. Either \
         passed data is not RPG Maker data or it's corrupted."
    )]
    InvalidHeader,
    #[error("Unexpected end of file encountered. Either passed data is not RPG Maker data or it's corrupted.")]
    UnexpectedEOF,
    #[error(
        "Decrypter's key doesn't match passed data. The file was encrypted with a different key; use a separate \
         `Decrypter` for each encryption key."
    )]
    KeyMismatch,
    #[error(
        "Passed data doesn't look like the file type it was declared as. Either the file type is wrong or the data is \
         corrupted."
    )]
    InvalidContent,
    #[error("File extension is not one of the supported RPG Maker encrypted asset extensions.")]
    UnsupportedExtension,
}

/// Holds one encryption key and decrypts or encrypts assets with it.
#[derive(Clone, Default)]
pub struct Decrypter {
    key_hex: [u8; KEY_STR_LENGTH],
    key: [u8; KEY_LENGTH],
    has_key: bool,
    // Set when the key came from an M4A file, whose bytes 8..16 are a guess; see `set_key_from_file`.
    from_m4a: bool,
}

impl Decrypter {
    /// Creates a new `Decrypter`. The key comes from the first file passed to [`Decrypter::decrypt`], or from
    /// [`Decrypter::set_key_from_str`] (`encryptionKey` in `System.json`) or [`Decrypter::set_key_from_file`].
    ///
    /// Cheap to [`Clone`]: set the key once, then share it between threads with clones or references (the `*_keyed` methods).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// XORs the first 16 bytes of `buffer` with the key. Encryption and decryption are the same operation.
    #[inline]
    fn xor_buffer(&self, buffer: &mut [u8]) {
        for (item, key_byte) in buffer.iter_mut().zip(&self.key) {
            *item ^= key_byte;
        }
    }

    /// The only writer of the key, which keeps `key_hex` in sync with `key`.
    fn set_key_bytes(&mut self, key: [u8; KEY_LENGTH], from_m4a: bool) {
        for (i, &value) in key.iter().enumerate() {
            self.key_hex[i * 2] = HEX_CHARS[(value >> 4) as usize];
            self.key_hex[i * 2 + 1] = HEX_CHARS[(value & 0x0F) as usize];
        }

        self.key = key;
        self.has_key = true;
        self.from_m4a = from_m4a;
    }

    const fn key_str(&self) -> &str {
        // SAFETY: `key_hex` is either zeroed (ASCII) or filled from `HEX_CHARS` by `set_key_bytes`, so it's always valid UTF-8.
        unsafe { core::str::from_utf8_unchecked(&self.key_hex) }
    }

    /// Checks that the key turns the file's first bytes into `file_type`'s magic bytes.
    fn check_key(&self, file_content: &[u8], file_type: FileType) -> Result<(), Error> {
        if !self.has_key {
            return Err(Error::KeyNotSet);
        }

        if !file_content.starts_with(RPGM_HEADER) {
            return Err(Error::InvalidHeader);
        }

        // An M4A key may be wrong in bytes 8..16, which the magic below doesn't check, so it can't vouch for other types.
        if self.from_m4a && !file_type.is_m4a() {
            return Err(Error::KeyMismatch);
        }

        let (offset, magic) = file_type.magic();
        let start = HEADER_LENGTH + offset;
        let encrypted = file_content
            .get(start..start + magic.len())
            .ok_or(Error::UnexpectedEOF)?;

        if encrypted
            .iter()
            .zip(&self.key[offset..])
            .zip(magic)
            .all(|((&byte, &key), &expected)| byte ^ key == expected)
        {
            Ok(())
        } else {
            Err(Error::KeyMismatch)
        }
    }

    /// Derives the key from the file, or checks it against the existing key. A derived key needs no check.
    fn prepare_key(&mut self, file_content: &[u8], file_type: FileType) -> Result<(), Error> {
        // A key from an M4A can't check other types, so a PNG or OGG derives its own key.
        if self.has_key && (!self.from_m4a || file_type.is_m4a()) {
            self.check_key(file_content, file_type)
        } else {
            self.set_key_from_file(file_content, file_type).map(|_| ())
        }
    }

    fn read_ogg_page_serialno(buf: &[u8], pos: &mut usize) -> Result<u32, Error> {
        const HEADER_SIZE: usize = 27;
        const SEGMENT_COUNT_POS: usize = 26;
        const SERIALNO_POS: usize = 14;

        let page = buf.get(*pos..).ok_or(Error::UnexpectedEOF)?;
        let header = page.get(..HEADER_SIZE).ok_or(Error::UnexpectedEOF)?;

        let segment_count = header[SEGMENT_COUNT_POS] as usize;
        let segment_table = page[HEADER_SIZE..].get(..segment_count).ok_or(Error::UnexpectedEOF)?;
        let body_length: usize = segment_table.iter().map(|&segment| segment as usize).sum();

        *pos += HEADER_SIZE + segment_count + body_length;

        Ok(u32::from_le_bytes([
            header[SERIALNO_POS],
            header[SERIALNO_POS + 1],
            header[SERIALNO_POS + 2],
            header[SERIALNO_POS + 3],
        ]))
    }

    /// Returns the decrypter's key, or [`None`] if it's not set.
    ///
    /// Always lowercase hex. A key derived from an M4A file may differ from the real one in bytes the header doesn't
    /// reveal; decryption and playback are unaffected, but such a key is only used for M4A files.
    #[inline]
    #[must_use]
    pub const fn key(&self) -> Option<&str> {
        if self.has_key { Some(self.key_str()) } else { None }
    }

    /// Sets the key from a hex `&str` (any case).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKeyLength`] - if key's length is not 32 bytes.
    /// - [`Error::InvalidKey`] - if key contains anything but hexadecimal digits.
    #[inline]
    pub fn set_key_from_str(&mut self, key: &str) -> Result<(), Error> {
        const fn hex_value(digit: u8) -> Option<u8> {
            match digit {
                b'0'..=b'9' => Some(digit - b'0'),
                b'a'..=b'f' => Some(digit - b'a' + 10),
                b'A'..=b'F' => Some(digit - b'A' + 10),
                _ => None,
            }
        }

        if key.len() != KEY_STR_LENGTH {
            return Err(Error::InvalidKeyLength);
        }

        let mut bytes = [0; KEY_LENGTH];
        for (byte, pair) in bytes.iter_mut().zip(key.as_bytes().chunks_exact(2)) {
            let (Some(high), Some(low)) = (hex_value(pair[0]), hex_value(pair[1])) else {
                return Err(Error::InvalidKey);
            };
            *byte = high << 4 | low;
        }

        self.set_key_bytes(bytes, false);
        Ok(())
    }

    /// Sets the key from encrypted `file_content`.
    ///
    /// The key is rebuilt from `file_type`'s known header. For M4A it may differ from the real key in bytes 8..16
    /// (see [`Decrypter::key`]); playback is unaffected, but don't treat it as authoritative. For M4A, the first box's
    /// size is found by searching the 256 bytes that start at offset 16 of the decrypted file for a following box
    /// header.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidHeader`] - if `file_content` has an invalid header.
    /// - [`Error::UnexpectedEOF`] - if `file_content` ends unexpectedly.
    /// - [`Error::InvalidContent`] - if the unencrypted part of `file_content` can't belong to a file of `file_type`
    ///   (checked for PNG and OGG, and for M4A that no box header follows the type box).
    #[inline]
    pub fn set_key_from_file(&mut self, file_content: &[u8], file_type: FileType) -> Result<&str, Error> {
        if !file_content.starts_with(RPGM_HEADER) {
            return Err(Error::InvalidHeader);
        }

        let Some(post_header) = file_content.get(HEADER_LENGTH..HEADER_LENGTH * 2) else {
            return Err(Error::UnexpectedEOF);
        };

        // The signature is a per-call copy: it's patched with data from this file only.
        let mut signature = match file_type {
            FileType::Png => PNG_HEADER,
            FileType::Ogg => OGG_HEADER,
            FileType::M4a => M4A_HEADER,
        };

        match file_type {
            FileType::Png => {
                // IHDR data starts right after the encrypted part: width, height (4 bytes each), then bit depth, color type,
                // compression method, filter method and interlace method.
                let ihdr_tail = file_content
                    .get(HEADER_LENGTH * 2 + 8..HEADER_LENGTH * 2 + 13)
                    .ok_or(Error::UnexpectedEOF)?;

                let valid = matches!(ihdr_tail[0], 1 | 2 | 4 | 8 | 16)
                    && matches!(ihdr_tail[1], 0 | 2 | 3 | 4 | 6)
                    && ihdr_tail[2] == 0
                    && ihdr_tail[3] == 0
                    && ihdr_tail[4] <= 1;

                if !valid {
                    return Err(Error::InvalidContent);
                }
            }
            // Get proper M4A header box size
            //* Nothing else in the M4A header matters: `ftypM4A_` can be replaced by `ftypSHIT`, and FFmpeg won't complain.
            //* Bytes 12-15 can be any integer, too.
            FileType::M4a => {
                // Boxes are `[size: u32 BE][name]`. The type box is at least 16 bytes, so the next box starts past original
                // offset 16, where data is no longer encrypted. `post_header` above guarantees the file reaches there.
                const CHUNK_SIZE: usize = 4;
                const SEARCH_START: usize = HEADER_LENGTH * 2;
                const SEARCH_LENGTH: usize = 256;

                let rest = &file_content[SEARCH_START..];
                let window = &rest[..rest.len().min(SEARCH_LENGTH)];
                let original_length = file_content.len() - HEADER_LENGTH;

                // Every 4th `windows(8)` item is a candidate box header, starting at original offset `16 + 4 * step`.
                // The first box after the type box ends it; later matches are boxes further along.
                let box_start = window
                    .windows(CHUNK_SIZE * 2)
                    .step_by(CHUNK_SIZE)
                    .enumerate()
                    .find_map(|(step, candidate)| {
                        let box_start = HEADER_LENGTH + step * CHUNK_SIZE;
                        let box_size =
                            u32::from_be_bytes([candidate[0], candidate[1], candidate[2], candidate[3]]) as usize;

                        // Box size must be plausible (not below its header, fits the file). This rejects names that
                        // appear in another box's data.
                        (M4A_POST_HEADER_BOXES.contains(&&candidate[CHUNK_SIZE..])
                            && (CHUNK_SIZE * 2..=original_length - box_start).contains(&box_size))
                        .then_some(box_start)
                    })
                    // No box follows the type box, so the file is not M4A and a key guessed from it would be wrong.
                    .ok_or(Error::InvalidContent)?;
                signature[..CHUNK_SIZE].copy_from_slice(&(box_start as u32).to_be_bytes());
            }
            // `OGG_HEADER`'s stream serial number differs per file: read it from the second page and patch it into the first.
            // It is the same on every page of the stream.
            FileType::Ogg => {
                let mut pos = HEADER_LENGTH;

                Self::read_ogg_page_serialno(file_content, &mut pos)?;

                // Unlike the first page's, the second page's header is not encrypted.
                match file_content.get(pos..pos + OGG_MAGIC.len()) {
                    Some(capture) if capture == OGG_MAGIC => {}
                    Some(_) => return Err(Error::InvalidContent),
                    None => return Err(Error::UnexpectedEOF),
                }

                let serialno = Self::read_ogg_page_serialno(file_content, &mut pos)?;
                signature[14..16].copy_from_slice(&serialno.to_le_bytes()[0..2]);
            }
        }

        let mut key = [0; KEY_LENGTH];
        for ((key_byte, &signature_byte), &encrypted_byte) in key.iter_mut().zip(&signature).zip(post_header) {
            *key_byte = signature_byte ^ encrypted_byte;
        }

        self.set_key_bytes(key, file_type.is_m4a());
        Ok(self.key_str())
    }

    /// Decrypts RPG Maker file content, deriving the key from the file if none is set.
    ///
    /// An existing key is reused after checking that it turns the file's first bytes into `file_type`'s magic bytes
    /// ([`Error::KeyMismatch`] otherwise), so use a separate [`Decrypter`] per encryption key. A key derived from an
    /// M4A file is not reused for PNG or OGG files; a new key is derived from them instead.
    ///
    /// Copies the contents and returns the decrypted [`Vec<u8>`]; use [`Decrypter::decrypt_in_place`] to avoid the copy.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidHeader`] - if `file_content` has an invalid header.
    /// - [`Error::UnexpectedEOF`] - if `file_content` ends unexpectedly.
    /// - [`Error::InvalidContent`] - if the key has to be derived and `file_content` can't belong to a file of `file_type`.
    /// - [`Error::KeyMismatch`] - if the decrypter's existing key doesn't fit `file_content`.
    #[inline]
    #[cfg(feature = "alloc")]
    pub fn decrypt(&mut self, file_content: &[u8], file_type: FileType) -> Result<Vec<u8>, Error> {
        self.prepare_key(file_content, file_type)?;
        Ok(self.decrypted_copy(file_content))
    }

    /// Decrypts RPG Maker file content with the key already set, without modifying the decrypter.
    ///
    /// Unlike [`Decrypter::decrypt`], this takes `&self`, so a decrypter keyed via [`Decrypter::set_key_from_str`] or
    /// [`Decrypter::set_key_from_file`] can be shared between threads.
    ///
    /// # Errors
    ///
    /// - [`Error::KeyNotSet`] - if the decrypter has no key.
    /// - [`Error::InvalidHeader`] - if `file_content` has an invalid header.
    /// - [`Error::UnexpectedEOF`] - if `file_content` ends unexpectedly.
    /// - [`Error::KeyMismatch`] - if the decrypter's key doesn't fit `file_content`, or the key came from an M4A file and
    ///   `file_content` is not one (use [`Decrypter::decrypt`] to derive a key for it).
    #[inline]
    #[cfg(feature = "alloc")]
    pub fn decrypt_keyed(&self, file_content: &[u8], file_type: FileType) -> Result<Vec<u8>, Error> {
        self.check_key(file_content, file_type)?;
        Ok(self.decrypted_copy(file_content))
    }

    #[cfg(feature = "alloc")]
    fn decrypted_copy(&self, file_content: &[u8]) -> Vec<u8> {
        let mut result = file_content[HEADER_LENGTH..].to_vec();
        self.xor_buffer(&mut result);
        result
    }

    /// Decrypts RPG Maker file content in place, with the same key handling as [`Decrypter::decrypt`].
    /// To keep the input, use [`Decrypter::decrypt`].
    ///
    /// # Note
    ///
    /// Decrypted data is only valid starting at offset 16; the returned slice starts there.
    /// If the function fails, `file_content` is left unmodified.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidHeader`] - if `file_content` has an invalid header.
    /// - [`Error::UnexpectedEOF`] - if `file_content` ends unexpectedly.
    /// - [`Error::InvalidContent`] - if the key has to be derived and `file_content` can't belong to a file of `file_type`.
    /// - [`Error::KeyMismatch`] - if the decrypter's existing key doesn't fit `file_content`.
    #[inline]
    pub fn decrypt_in_place<'a>(&mut self, file_content: &'a mut [u8], file_type: FileType) -> Result<&'a [u8], Error> {
        self.prepare_key(file_content, file_type)?;
        Ok(self.decrypt_in_place_unchecked(file_content))
    }

    /// Decrypts in place with the key already set, without modifying the decrypter.
    ///
    /// In-place counterpart of [`Decrypter::decrypt_keyed`]; returns the same slice as [`Decrypter::decrypt_in_place`].
    ///
    /// # Errors
    ///
    /// The same as [`Decrypter::decrypt_keyed`].
    #[inline]
    pub fn decrypt_in_place_keyed<'a>(
        &self,
        file_content: &'a mut [u8],
        file_type: FileType,
    ) -> Result<&'a [u8], Error> {
        self.check_key(file_content, file_type)?;
        Ok(self.decrypt_in_place_unchecked(file_content))
    }

    fn decrypt_in_place_unchecked<'a>(&self, file_content: &'a mut [u8]) -> &'a [u8] {
        let sliced_past_header = &mut file_content[HEADER_LENGTH..];
        self.xor_buffer(sliced_past_header);
        sliced_past_header
    }

    /// Encrypts file content, returning a copy prefixed with the RPG Maker header ([`RPGM_HEADER`]).
    ///
    /// Requires a key: from `System.json`, or via [`Decrypter::set_key_from_file`] with data from an encrypted file.
    /// Use [`Decrypter::encrypt_in_place`] to avoid the copy.
    ///
    /// # Errors
    ///
    /// - [`Error::KeyNotSet`] - if the key is not set.
    /// - [`Error::UnexpectedEOF`] - if `file_content` is too short to be a file of `file_type`.
    /// - [`Error::InvalidContent`] - if `file_content` doesn't start like a file of `file_type`.
    #[inline]
    #[cfg(feature = "alloc")]
    pub fn encrypt(&self, file_content: &[u8], file_type: FileType) -> Result<Vec<u8>, Error> {
        if !self.has_key {
            return Err(Error::KeyNotSet);
        }

        file_type.check_plain(file_content)?;

        let mut output_data = Vec::with_capacity(HEADER_LENGTH + file_content.len());
        output_data.extend_from_slice(RPGM_HEADER);
        output_data.extend_from_slice(file_content);
        self.xor_buffer(&mut output_data[HEADER_LENGTH..]);
        Ok(output_data)
    }

    /// Encrypts file content in place. Key requirements are as for [`Decrypter::encrypt`]; to keep the input, use that.
    ///
    /// # Note
    ///
    /// The output has no RPG Maker header; prepend [`RPGM_HEADER`] yourself.
    /// If the function fails, `file_content` is left unmodified.
    ///
    /// # Errors
    ///
    /// - [`Error::KeyNotSet`] - if the key is not set.
    /// - [`Error::UnexpectedEOF`] - if `file_content` is too short to be a file of `file_type`.
    /// - [`Error::InvalidContent`] - if `file_content` doesn't start like a file of `file_type`.
    #[inline]
    pub fn encrypt_in_place(&self, file_content: &mut [u8], file_type: FileType) -> Result<(), Error> {
        if !self.has_key {
            return Err(Error::KeyNotSet);
        }

        file_type.check_plain(file_content)?;

        self.xor_buffer(file_content);
        Ok(())
    }
}

/// Decrypts RPG Maker file content using a temporary [`Decrypter`] instance.
///
/// Wrapper around [`Decrypter::decrypt`]; the key is derived from `file_content`.
/// Copies the contents and returns the decrypted [`Vec<u8>`]; use [`decrypt_in_place`] to avoid the copy.
///
/// # Errors
///
/// - [`Error::InvalidHeader`] – if `file_content` lacks the RPG Maker header.
/// - [`Error::UnexpectedEOF`] – if the data ends unexpectedly.
/// - [`Error::InvalidContent`] – if the data can't belong to a file of `file_type`.
#[cfg(feature = "alloc")]
pub fn decrypt(file_content: &[u8], file_type: FileType) -> Result<Vec<u8>, Error> {
    Decrypter::new().decrypt(file_content, file_type)
}

/// Decrypts RPG Maker file content in place using a temporary [`Decrypter`] instance.
///
/// Wrapper around [`Decrypter::decrypt_in_place`]; the key is derived from the data.
/// The returned data is valid starting at offset 16 of the buffer. To keep the input, use [`decrypt`].
///
/// # Errors
///
/// - [`Error::InvalidHeader`] – if `file_content` lacks the RPG Maker header.
/// - [`Error::UnexpectedEOF`] – if the data ends unexpectedly.
/// - [`Error::InvalidContent`] – if the data can't belong to a file of `file_type`.
pub fn decrypt_in_place(file_content: &mut [u8], file_type: FileType) -> Result<&[u8], Error> {
    Decrypter::new().decrypt_in_place(file_content, file_type)
}

/// Encrypts file content with a key string and a temporary [`Decrypter`] instance.
///
/// Wrapper around [`Decrypter::encrypt`]. Copies the contents and returns the encrypted [`Vec<u8>`], which includes
/// the RPG Maker header (`RPGM_HEADER`). Use [`encrypt_in_place`] to avoid the copy.
///
/// # Errors
///
/// - [`Error::InvalidKeyLength`] - if key's length is not 32 bytes.
/// - [`Error::InvalidKey`] - if key contains anything but hexadecimal digits.
/// - [`Error::UnexpectedEOF`] / [`Error::InvalidContent`] - if `file_content` isn't a file of `file_type`.
#[cfg(feature = "alloc")]
pub fn encrypt(file_content: &[u8], file_type: FileType, key: &str) -> Result<Vec<u8>, Error> {
    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(key)?;
    decrypter.encrypt(file_content, file_type)
}

/// Encrypts file content in place with a key string and a temporary [`Decrypter`] instance.
///
/// Wrapper around [`Decrypter::encrypt_in_place`]. Produces *only* the encrypted payload: the RPG Maker header is
/// **not** added, so prepend it yourself for a complete `.rpgmvp`, `.rpgmvo`, or `.rpgmvm` file.
/// To keep the input, use [`encrypt`].
///
/// # Errors
///
/// - [`Error::InvalidKeyLength`] - if key's length is not 32 bytes.
/// - [`Error::InvalidKey`] - if key contains anything but hexadecimal digits.
/// - [`Error::UnexpectedEOF`] / [`Error::InvalidContent`] - if `file_content` isn't a file of `file_type`.
pub fn encrypt_in_place(file_content: &mut [u8], file_type: FileType, key: &str) -> Result<(), Error> {
    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(key)?;
    decrypter.encrypt_in_place(file_content, file_type)
}
