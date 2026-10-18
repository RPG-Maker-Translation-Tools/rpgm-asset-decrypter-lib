#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::too_long_first_doc_paragraph)]

use core::{
    ffi::{CStr, c_char},
    mem, ptr, slice,
};
use rpgm_asset_decrypter_lib::{Decrypter as InnerDecrypter, Error as InnerError, FileType as InnerFileType};

// No allocator or heap types are used, so a no_std build needs only a panic handler. It's left out when the default
// `std` feature is on: `std` already provides one, and a second causes a duplicate lang item.
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    extern "C" {
        fn abort() -> !;
    }
    unsafe { abort() }
}

// The file type crosses the ABI as a plain `u32`, not a Rust enum: C may pass any integer, and an out-of-range
// discriminant is undefined behavior. Literal consts, so cbindgen emits `#define`s.

/// The `file_type` value for a PNG asset.
pub const RPGMASD_FILE_TYPE_PNG: u32 = 0;

/// The `file_type` value for an OGG asset.
pub const RPGMASD_FILE_TYPE_OGG: u32 = 1;

/// The `file_type` value for an M4A asset.
pub const RPGMASD_FILE_TYPE_M4A: u32 = 2;

const fn file_type_from_raw(file_type: u32) -> Option<InnerFileType> {
    match file_type {
        RPGMASD_FILE_TYPE_PNG => Some(InnerFileType::Png),
        RPGMASD_FILE_TYPE_OGG => Some(InnerFileType::Ogg),
        RPGMASD_FILE_TYPE_M4A => Some(InnerFileType::M4a),
        _ => None,
    }
}

/// The shared body of the in-place functions: checks `file_type` and `data`, then runs `operation` on the bytes.
///
/// # Safety
///
/// `data` must be readable and writable for `data_len` bytes and not accessed by anything else during the call.
unsafe fn in_place(
    data: *mut u8,
    data_len: usize,
    file_type: u32,
    operation: impl FnOnce(&mut [u8], InnerFileType) -> Result<(), InnerError>,
) -> RpgmasdStatus {
    if data.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    let Some(file_type) = file_type_from_raw(file_type) else {
        return RpgmasdStatus::InvalidFileType;
    };

    // SAFETY: caller guarantees `data` points to `data_len` readable and writable, initialized bytes.
    let data = unsafe { slice::from_raw_parts_mut(data, data_len) };

    match operation(data, file_type) {
        Ok(()) => RpgmasdStatus::Ok,
        Err(error) => error.into(),
    }
}

/// Status code returned by every fallible `rpgmasd_*` function. `RPGMASD_STATUS_OK` is the only success value.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpgmasdStatus {
    Ok = 0,
    KeyNotSet = 1,
    InvalidKeyLength = 2,
    InvalidHeader = 3,
    UnexpectedEof = 4,
    /// A pointer argument that must not be null (`decrypter`, `data`, `key`, `out_*`) was null.
    NullArgument = 5,
    /// `key` was not valid UTF-8.
    InvalidUtf8 = 6,
    /// `key` was 32 bytes long but contained non-hexadecimal characters.
    InvalidKey = 7,
    /// `file_type` was not one of the `RPGMASD_FILE_TYPE_*` values.
    InvalidFileType = 8,
    /// The decrypter already had a key, and it doesn't fit `data`.
    KeyMismatch = 9,
    /// `data` can't be a file of the given `file_type`.
    InvalidContent = 10,
    /// An output buffer is too small; see the function's documentation for the size it needs.
    BufferTooSmall = 11,
    /// An error this version of the bindings doesn't know about.
    Unknown = 12,
}

impl From<InnerError> for RpgmasdStatus {
    fn from(error: InnerError) -> Self {
        match error {
            InnerError::KeyNotSet => Self::KeyNotSet,
            InnerError::InvalidKeyLength => Self::InvalidKeyLength,
            InnerError::InvalidKey => Self::InvalidKey,
            InnerError::InvalidHeader => Self::InvalidHeader,
            InnerError::UnexpectedEOF => Self::UnexpectedEof,
            InnerError::KeyMismatch => Self::KeyMismatch,
            InnerError::InvalidContent => Self::InvalidContent,
            // `UnsupportedExtension` is never returned: no function here parses extensions.
            _ => Self::Unknown,
        }
    }
}

/// Opaque `Decrypter`, stored in caller-owned memory of `RPGMASD_DECRYPTER_SIZE` bytes aligned to
/// `RPGMASD_DECRYPTER_ALIGN`, initialized with `rpgmasd_decrypter_init`. Nothing to free.
pub struct RpgmasdDecrypter(InnerDecrypter);

// Literals, not `mem::size_of`: cbindgen only turns literal consts into `#define`s, which work in array
// sizes. The assertion checks them against the real layout; update the numbers if it fails.

/// The size, in bytes, of a `Decrypter` instance - the minimum size of the storage passed to
/// `rpgmasd_decrypter_init`.
pub const RPGMASD_DECRYPTER_SIZE: usize = 50;

/// The required alignment, in bytes, of the storage passed to `rpgmasd_decrypter_init`.
pub const RPGMASD_DECRYPTER_ALIGN: usize = 1;

const _: () = {
    assert!(RPGMASD_DECRYPTER_SIZE == mem::size_of::<RpgmasdDecrypter>());
    assert!(RPGMASD_DECRYPTER_ALIGN == mem::align_of::<RpgmasdDecrypter>());
};

/// The same as `RPGMASD_DECRYPTER_SIZE`, for storage whose size is only known at run time.
#[no_mangle]
pub const extern "C" fn rpgmasd_decrypter_size() -> usize {
    RPGMASD_DECRYPTER_SIZE
}

/// The same as `RPGMASD_DECRYPTER_ALIGN`, for storage whose alignment is only known at run time.
#[no_mangle]
pub const extern "C" fn rpgmasd_decrypter_align() -> usize {
    RPGMASD_DECRYPTER_ALIGN
}

/// Copies the 16-byte RPG Maker encryption header into `out`. Prepend it to the output of the
/// `*_encrypt_in_place` functions to produce a complete encrypted file (or use
/// `rpgmasd_decrypter_encrypt_into`, which does it for you).
///
/// Returns `RPGMASD_STATUS_OK` on success, or `RPGMASD_STATUS_NULL_ARGUMENT` if `out` is null.
///
/// # Safety
///
/// `out` must be valid for writing `RPGMASD_HEADER_LENGTH` bytes.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_header(out: *mut u8) -> RpgmasdStatus {
    if out.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `out` is writable for `RPGMASD_HEADER_LENGTH` bytes; the header is a static, so no overlap.
    unsafe {
        ptr::copy_nonoverlapping(
            rpgm_asset_decrypter_lib::RPGM_HEADER.as_ptr(),
            out,
            RPGMASD_HEADER_LENGTH,
        );
    };

    RpgmasdStatus::Ok
}

/// Initializes a `Decrypter` into caller-provided storage (see Safety).
///
/// Returns `RPGMASD_STATUS_OK` on success, or `RPGMASD_STATUS_NULL_ARGUMENT` if `out` is null.
///
/// # Safety
///
/// `out` must point to writable storage of `RPGMASD_DECRYPTER_SIZE` bytes, aligned to `RPGMASD_DECRYPTER_ALIGN`.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_init(out: *mut RpgmasdDecrypter) -> RpgmasdStatus {
    if out.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `out` points to writable storage of at least `RPGMASD_DECRYPTER_SIZE`
    // bytes, aligned to `RPGMASD_DECRYPTER_ALIGN`.
    unsafe { out.write(RpgmasdDecrypter(InnerDecrypter::new())) };

    RpgmasdStatus::Ok
}

/// Writes `key` as a NUL-terminated string into `out_key`. The caller has to check `out_key_len` first.
///
/// # Safety
///
/// `out_key` must be writable for `key.len() + 1` bytes.
unsafe fn write_key(key: &str, out_key: *mut c_char) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        ptr::copy_nonoverlapping(key.as_ptr(), out_key.cast::<u8>(), key.len());
        *out_key.add(key.len()) = 0;
    }
}

/// Writes the decrypter's key as a NUL-terminated 32-character lowercase hex string into `out_key`, which
/// must have room for `out_key_len` bytes - at least `RPGMASD_KEY_BUFFER_LENGTH`.
///
/// Returns `RPGMASD_STATUS_OK` on success, `RPGMASD_STATUS_KEY_NOT_SET` if no key has been set yet,
/// `RPGMASD_STATUS_BUFFER_TOO_SMALL` if `out_key_len` is less than `RPGMASD_KEY_BUFFER_LENGTH`, or
/// `RPGMASD_STATUS_NULL_ARGUMENT` if `decrypter` or `out_key` is null.
///
/// # Safety
///
/// `decrypter` must point to a `Decrypter` initialized by `rpgmasd_decrypter_init`. `out_key` must be
/// writable for `out_key_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_key(
    decrypter: *const RpgmasdDecrypter,
    out_key: *mut c_char,
    out_key_len: usize,
) -> RpgmasdStatus {
    if decrypter.is_null() || out_key.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    if out_key_len < RPGMASD_KEY_BUFFER_LENGTH {
        return RpgmasdStatus::BufferTooSmall;
    }

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmasd_decrypter_init`.
    let key = unsafe { &*decrypter }.0.key();

    let Some(key) = key else {
        return RpgmasdStatus::KeyNotSet;
    };

    // SAFETY: `out_key_len >= RPGMASD_KEY_BUFFER_LENGTH == key.len() + 1`, and the caller guarantees the buffer.
    unsafe { write_key(key, out_key) };

    RpgmasdStatus::Ok
}

/// Sets the decrypter's key from a NUL-terminated 32-character hex string (any case).
///
/// Returns `RPGMASD_STATUS_OK` on success, `RPGMASD_STATUS_INVALID_KEY_LENGTH` if `key` isn't 32 bytes
/// long, `RPGMASD_STATUS_INVALID_KEY` if it contains non-hexadecimal characters,
/// `RPGMASD_STATUS_INVALID_UTF8` if it isn't valid UTF-8, or `RPGMASD_STATUS_NULL_ARGUMENT` if a pointer is
/// null. The previous key, if any, is kept on failure.
///
/// # Safety
///
/// `decrypter` must point to a `Decrypter` initialized by `rpgmasd_decrypter_init`. `key` must be a valid
/// NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_set_key_from_str(
    decrypter: *mut RpgmasdDecrypter,
    key: *const c_char,
) -> RpgmasdStatus {
    if decrypter.is_null() || key.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `key` is a valid, NUL-terminated C string.
    let Ok(key) = unsafe { CStr::from_ptr(key) }.to_str() else {
        return RpgmasdStatus::InvalidUtf8;
    };

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmasd_decrypter_init`.
    match unsafe { &mut *decrypter }.0.set_key_from_str(key) {
        Ok(()) => RpgmasdStatus::Ok,
        Err(error) => error.into(),
    }
}

/// Sets the key of the decrypter from encrypted `data`, writing the derived 32-character hex key as a
/// NUL-terminated string into `out_key`, which must have room for `out_key_len` bytes - at least
/// `RPGMASD_KEY_BUFFER_LENGTH`.
///
/// `file_type` is one of the `RPGMASD_FILE_TYPE_*` values. Returns `RPGMASD_STATUS_OK` on success,
/// `RPGMASD_STATUS_INVALID_FILE_TYPE` for any other `file_type`, `RPGMASD_STATUS_BUFFER_TOO_SMALL` if
/// `out_key_len` is too small, or an error status if `data` has an invalid header, ends unexpectedly or
/// can't be a file of `file_type`. The decrypter keeps its previous key on failure.
///
/// # Safety
///
/// `decrypter` must point to a `Decrypter` initialized by `rpgmasd_decrypter_init`. `data` must be
/// readable for `data_len` bytes. `out_key` must be writable for `out_key_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_set_key_from_file(
    decrypter: *mut RpgmasdDecrypter,
    data: *const u8,
    data_len: usize,
    file_type: u32,
    out_key: *mut c_char,
    out_key_len: usize,
) -> RpgmasdStatus {
    if decrypter.is_null() || data.is_null() || out_key.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    let Some(file_type) = file_type_from_raw(file_type) else {
        return RpgmasdStatus::InvalidFileType;
    };

    if out_key_len < RPGMASD_KEY_BUFFER_LENGTH {
        return RpgmasdStatus::BufferTooSmall;
    }

    // SAFETY: caller guarantees `data` points to `data_len` readable, initialized bytes.
    let data = unsafe { slice::from_raw_parts(data, data_len) };

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmasd_decrypter_init`.
    match unsafe { &mut *decrypter }.0.set_key_from_file(data, file_type) {
        Ok(key) => {
            // SAFETY: `out_key_len >= RPGMASD_KEY_BUFFER_LENGTH == key.len() + 1`, and the caller guarantees the buffer.
            unsafe { write_key(key, out_key) };

            RpgmasdStatus::Ok
        }
        Err(error) => error.into(),
    }
}

/// Decrypts RPG Maker file content in place. Auto-determines the key from `data` if the decrypter
/// doesn't already have one set; an existing key is reused after being checked against `data`
/// (`RPGMASD_STATUS_KEY_MISMATCH` if it doesn't fit). Decrypted data is valid starting at byte offset 16 of
/// `data`. On failure, `data` is left unmodified.
///
/// `file_type` is one of the `RPGMASD_FILE_TYPE_*` values; any other value gives
/// `RPGMASD_STATUS_INVALID_FILE_TYPE`.
///
/// # Safety
///
/// `decrypter` must point to a `Decrypter` initialized by `rpgmasd_decrypter_init`. `data` must be
/// readable and writable for `data_len` bytes and not accessed by anything else during the call.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_decrypt_in_place(
    decrypter: *mut RpgmasdDecrypter,
    data: *mut u8,
    data_len: usize,
    file_type: u32,
) -> RpgmasdStatus {
    if decrypter.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmasd_decrypter_init`.
    let decrypter = unsafe { &mut (*decrypter).0 };

    // SAFETY: forwarded from the caller's guarantee about `data`.
    unsafe {
        in_place(data, data_len, file_type, |data, file_type| {
            decrypter.decrypt_in_place(data, file_type).map(|_| ())
        })
    }
}

/// Like `rpgmasd_decrypter_decrypt_in_place`, but never modifies the decrypter, so several threads can
/// share one decrypter that already has a key (`RPGMASD_STATUS_KEY_NOT_SET` otherwise).
///
/// # Safety
///
/// `decrypter` must point to a `Decrypter` initialized by `rpgmasd_decrypter_init` that nothing modifies
/// during the call. `data` must be readable and writable for `data_len` bytes and not accessed by anything
/// else during the call.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_decrypt_in_place_keyed(
    decrypter: *const RpgmasdDecrypter,
    data: *mut u8,
    data_len: usize,
    file_type: u32,
) -> RpgmasdStatus {
    if decrypter.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` that nothing modifies during the call.
    let decrypter = unsafe { &(*decrypter).0 };

    // SAFETY: forwarded from the caller's guarantee about `data`.
    unsafe {
        in_place(data, data_len, file_type, |data, file_type| {
            decrypter.decrypt_in_place_keyed(data, file_type).map(|_| ())
        })
    }
}

/// Encrypts file content in place. Requires the decrypter to already have a key set. Produces the raw
/// encrypted payload, without the RPG Maker header; see `rpgmasd_header` and
/// `rpgmasd_decrypter_encrypt_into`. `data` must be a file of `file_type` (its magic bytes are checked)
/// and is left unmodified on failure.
///
/// # Safety
///
/// `decrypter` must point to a `Decrypter` initialized by `rpgmasd_decrypter_init`. `data` must be
/// readable and writable for `data_len` bytes and not accessed by anything else during the call.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_encrypt_in_place(
    decrypter: *const RpgmasdDecrypter,
    data: *mut u8,
    data_len: usize,
    file_type: u32,
) -> RpgmasdStatus {
    if decrypter.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmasd_decrypter_init`.
    let decrypter = unsafe { &(*decrypter).0 };

    // SAFETY: forwarded from the caller's guarantee about `data`.
    unsafe {
        in_place(data, data_len, file_type, |data, file_type| {
            decrypter.encrypt_in_place(data, file_type)
        })
    }
}

/// Encrypts file content into a separate buffer: the RPG Maker header followed by the encrypted `data`, which is not
/// modified. Requires a key set; `data` must be a file of `file_type` (its magic bytes are checked). On failure the
/// payload part of `out` is zeroed, so no plaintext is left behind.
///
/// The output is `RPGMASD_HEADER_LENGTH + data_len` bytes long and must fit in `out_cap` bytes. Its length is written
/// to `out_len`, also when `RPGMASD_STATUS_BUFFER_TOO_SMALL` is returned, which tells the size to allocate. The one
/// exception is a `data_len` so large that the length overflows `size_t`: then `out_len` is left unwritten.
///
/// # Safety
///
/// `decrypter` must point to a `Decrypter` initialized by `rpgmasd_decrypter_init`. `data` must be
/// readable for `data_len` bytes. `out` must be writable for `out_cap` bytes and must not overlap `data`.
/// `out_len` must be valid for writing a `size_t`.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_encrypt_into(
    decrypter: *const RpgmasdDecrypter,
    data: *const u8,
    data_len: usize,
    file_type: u32,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> RpgmasdStatus {
    if decrypter.is_null() || data.is_null() || out.is_null() || out_len.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    let Some(file_type) = file_type_from_raw(file_type) else {
        return RpgmasdStatus::InvalidFileType;
    };

    let Some(needed) = data_len.checked_add(RPGMASD_HEADER_LENGTH) else {
        return RpgmasdStatus::BufferTooSmall;
    };

    // SAFETY: caller guarantees `out_len` is valid for writes.
    unsafe { out_len.write(needed) };

    if out_cap < needed {
        return RpgmasdStatus::BufferTooSmall;
    }

    // SAFETY: caller guarantees `data` points to `data_len` readable, initialized bytes.
    let data = unsafe { slice::from_raw_parts(data, data_len) };

    // SAFETY: caller guarantees `out` is writable for `out_cap >= needed` bytes and doesn't overlap `data`.
    let out = unsafe { slice::from_raw_parts_mut(out, needed) };

    let (header, payload) = out.split_at_mut(RPGMASD_HEADER_LENGTH);
    payload.copy_from_slice(data);

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmasd_decrypter_init`.
    match unsafe { &*decrypter }.0.encrypt_in_place(payload, file_type) {
        Ok(()) => {
            header.copy_from_slice(rpgm_asset_decrypter_lib::RPGM_HEADER);
            RpgmasdStatus::Ok
        }
        Err(error) => {
            // The payload holds the plaintext copy; clear it so a caller that ignores the status can't read it.
            payload.fill(0);
            error.into()
        }
    }
}

/// Decrypts RPG Maker file content in place with a temporary `Decrypter`; the data is valid from byte offset 16.
///
/// `file_type` is one of the `RPGMASD_FILE_TYPE_*` values; any other value gives
/// `RPGMASD_STATUS_INVALID_FILE_TYPE`.
///
/// # Safety
///
/// `data` must be readable and writable for `data_len` bytes and not accessed by anything else during the call.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypt_asset_in_place(
    data: *mut u8,
    data_len: usize,
    file_type: u32,
) -> RpgmasdStatus {
    // SAFETY: forwarded from the caller's guarantee about `data`.
    unsafe {
        in_place(data, data_len, file_type, |data, file_type| {
            InnerDecrypter::new().decrypt_in_place(data, file_type).map(|_| ())
        })
    }
}

/// Encrypts file content in place using a NUL-terminated key string and a temporary `Decrypter` instance.
/// Produces the raw encrypted payload, without the RPG Maker header; see `rpgmasd_header`. `data` must be a
/// file of `file_type` (its magic bytes are checked) and is left unmodified on failure.
///
/// # Safety
///
/// `data` must be readable and writable for `data_len` bytes and not accessed by anything else during the
/// call. `key` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_encrypt_asset_in_place(
    data: *mut u8,
    data_len: usize,
    file_type: u32,
    key: *const c_char,
) -> RpgmasdStatus {
    if data.is_null() || key.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    let Some(file_type) = file_type_from_raw(file_type) else {
        return RpgmasdStatus::InvalidFileType;
    };

    // SAFETY: caller guarantees `data` points to `data_len` readable and writable, initialized bytes.
    let data = unsafe { slice::from_raw_parts_mut(data, data_len) };

    // SAFETY: caller guarantees `key` is a valid, NUL-terminated C string.
    let Ok(key) = unsafe { CStr::from_ptr(key) }.to_str() else {
        return RpgmasdStatus::InvalidUtf8;
    };

    let mut decrypter = InnerDecrypter::new();

    match decrypter
        .set_key_from_str(key)
        .and_then(|()| decrypter.encrypt_in_place(data, file_type))
    {
        Ok(()) => RpgmasdStatus::Ok,
        Err(error) => error.into(),
    }
}

// Literals, not `= rpgm_asset_decrypter_lib::X`: cbindgen only turns literal consts into `#define`s, which work in
// array sizes and need no `dllimport` from a Windows DLL consumer (unlike an exported `extern const`). The assertions
// keep them equal to the real lengths.

/// The fixed 16-byte length of the RPG Maker encryption header.
pub const RPGMASD_HEADER_LENGTH: usize = 16;

/// The fixed 32-character length of a hex-encoded key string.
pub const RPGMASD_KEY_STR_LENGTH: usize = 32;

/// The size of a buffer that receives a key string: `RPGMASD_KEY_STR_LENGTH` characters and the NUL terminator.
pub const RPGMASD_KEY_BUFFER_LENGTH: usize = 33;

const _: () = {
    assert!(RPGMASD_HEADER_LENGTH == rpgm_asset_decrypter_lib::HEADER_LENGTH);
    assert!(RPGMASD_KEY_STR_LENGTH == rpgm_asset_decrypter_lib::KEY_STR_LENGTH);
    assert!(RPGMASD_KEY_BUFFER_LENGTH == RPGMASD_KEY_STR_LENGTH + 1);
};

// A C string, not a `&str`: cbindgen can't emit string constants, and the caller needs a NUL terminator.
const DEFAULT_KEY_C: &CStr = c"d41d8cd98f00b204e9800998ecf8427e";

/// The key RPG Maker uses when a project's encryption key is empty, as a NUL-terminated 32-character hex string.
/// It points to static storage, so it must not be freed.
#[no_mangle]
pub const extern "C" fn rpgmasd_default_key() -> *const c_char {
    DEFAULT_KEY_C.as_ptr()
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    const KEY: &CStr = c"d41d8cd98f00b204e9800998ecf8427e";
    const OTHER_KEY: &CStr = c"00112233445566778899aabbccddeeff";

    // Smallest valid-looking PNG: signature and an IHDR chunk with sane fields, padded.
    fn png_plain() -> [u8; 64] {
        let mut plain = [0u8; 64];
        plain[..16].copy_from_slice(&[
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
        ]);
        // width, height, bit depth, color type, compression, filter, interlace
        plain[16..29].copy_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
        plain
    }

    fn encrypted(plain: &[u8], key: &CStr) -> Vec<u8> {
        let mut file = vec![0u8; RPGMASD_HEADER_LENGTH + plain.len()];
        let mut decrypter = MaybeUninit::<RpgmasdDecrypter>::uninit();
        let mut written = 0;

        unsafe {
            assert_eq!(rpgmasd_decrypter_init(decrypter.as_mut_ptr()), RpgmasdStatus::Ok);
            assert_eq!(
                rpgmasd_decrypter_set_key_from_str(decrypter.as_mut_ptr(), key.as_ptr()),
                RpgmasdStatus::Ok
            );
            let status = rpgmasd_decrypter_encrypt_into(
                decrypter.as_ptr(),
                plain.as_ptr(),
                plain.len(),
                RPGMASD_FILE_TYPE_PNG,
                file.as_mut_ptr(),
                file.len(),
                ptr::addr_of_mut!(written),
            );
            assert_eq!(status, RpgmasdStatus::Ok);
        }

        assert_eq!(written, file.len());
        file
    }

    #[test]
    fn abi_values_are_stable() {
        // C code compares against these numbers through the generated header.
        assert_eq!(RpgmasdStatus::Ok as u32, 0);
        assert_eq!(RpgmasdStatus::KeyNotSet as u32, 1);
        assert_eq!(RpgmasdStatus::InvalidKeyLength as u32, 2);
        assert_eq!(RpgmasdStatus::InvalidHeader as u32, 3);
        assert_eq!(RpgmasdStatus::UnexpectedEof as u32, 4);
        assert_eq!(RpgmasdStatus::NullArgument as u32, 5);
        assert_eq!(RpgmasdStatus::InvalidUtf8 as u32, 6);
        assert_eq!(RpgmasdStatus::InvalidKey as u32, 7);
        assert_eq!(RpgmasdStatus::InvalidFileType as u32, 8);
        assert_eq!(RpgmasdStatus::KeyMismatch as u32, 9);
        assert_eq!(RpgmasdStatus::InvalidContent as u32, 10);
        assert_eq!(RpgmasdStatus::BufferTooSmall as u32, 11);
        assert_eq!(RpgmasdStatus::Unknown as u32, 12);
        assert_eq!(
            (RPGMASD_FILE_TYPE_PNG, RPGMASD_FILE_TYPE_OGG, RPGMASD_FILE_TYPE_M4A),
            (0, 1, 2)
        );
        assert_eq!(rpgmasd_decrypter_size(), RPGMASD_DECRYPTER_SIZE);
        assert_eq!(rpgmasd_decrypter_align(), RPGMASD_DECRYPTER_ALIGN);
    }

    #[test]
    fn default_key_matches_the_library() {
        let key = unsafe { CStr::from_ptr(rpgmasd_default_key()) };
        assert_eq!(key.to_str(), Ok(rpgm_asset_decrypter_lib::DEFAULT_KEY));
    }

    #[test]
    fn encrypt_into_and_decrypt_roundtrip() {
        let plain = png_plain();
        let mut file = encrypted(&plain, KEY);

        let mut header = [0u8; RPGMASD_HEADER_LENGTH];
        assert_eq!(unsafe { rpgmasd_header(header.as_mut_ptr()) }, RpgmasdStatus::Ok);
        assert_eq!(file[..RPGMASD_HEADER_LENGTH], header);

        let status = unsafe { rpgmasd_decrypt_asset_in_place(file.as_mut_ptr(), file.len(), RPGMASD_FILE_TYPE_PNG) };
        assert_eq!(status, RpgmasdStatus::Ok);
        assert_eq!(file[RPGMASD_HEADER_LENGTH..], plain);
    }

    #[test]
    fn encrypt_into_reports_the_needed_size() {
        let plain = png_plain();
        let mut decrypter = MaybeUninit::<RpgmasdDecrypter>::uninit();
        let mut out = [0u8; 8];
        let mut needed = 0;

        unsafe {
            assert_eq!(rpgmasd_decrypter_init(decrypter.as_mut_ptr()), RpgmasdStatus::Ok);
            let status = rpgmasd_decrypter_encrypt_into(
                decrypter.as_ptr(),
                plain.as_ptr(),
                plain.len(),
                RPGMASD_FILE_TYPE_PNG,
                out.as_mut_ptr(),
                out.len(),
                ptr::addr_of_mut!(needed),
            );
            assert_eq!(status, RpgmasdStatus::BufferTooSmall);
        }

        assert_eq!(needed, RPGMASD_HEADER_LENGTH + plain.len());
    }

    #[test]
    fn decrypter_derives_reports_and_checks_keys() {
        let mut file = encrypted(&png_plain(), KEY);
        let mut other = encrypted(&png_plain(), OTHER_KEY);
        let mut slot = MaybeUninit::<RpgmasdDecrypter>::uninit();
        let mut key_out = [0 as c_char; RPGMASD_KEY_BUFFER_LENGTH];

        unsafe {
            let decrypter = slot.as_mut_ptr();
            assert_eq!(rpgmasd_decrypter_init(decrypter), RpgmasdStatus::Ok);

            let key = |out: &mut [c_char]| rpgmasd_decrypter_key(decrypter, out.as_mut_ptr(), out.len());
            assert_eq!(key(&mut key_out), RpgmasdStatus::KeyNotSet);

            let status = rpgmasd_decrypter_set_key_from_file(
                decrypter,
                file.as_ptr(),
                file.len(),
                RPGMASD_FILE_TYPE_PNG,
                key_out.as_mut_ptr(),
                key_out.len(),
            );
            assert_eq!(status, RpgmasdStatus::Ok);
            assert_eq!(CStr::from_ptr(key_out.as_ptr()), KEY);

            key_out.fill(0);
            assert_eq!(key(&mut key_out), RpgmasdStatus::Ok);
            assert_eq!(CStr::from_ptr(key_out.as_ptr()), KEY);

            // A buffer without room for the NUL terminator must be refused, not overflowed.
            assert_eq!(
                key(&mut key_out[..RPGMASD_KEY_STR_LENGTH]),
                RpgmasdStatus::BufferTooSmall
            );

            // Keyed decryption works through a const pointer and doesn't touch the decrypter.
            let mut copy = file.clone();
            let status = rpgmasd_decrypter_decrypt_in_place_keyed(
                decrypter,
                copy.as_mut_ptr(),
                copy.len(),
                RPGMASD_FILE_TYPE_PNG,
            );
            assert_eq!(status, RpgmasdStatus::Ok);

            let status =
                rpgmasd_decrypter_decrypt_in_place(decrypter, file.as_mut_ptr(), file.len(), RPGMASD_FILE_TYPE_PNG);
            assert_eq!(status, RpgmasdStatus::Ok);
            assert_eq!(file[RPGMASD_HEADER_LENGTH..], png_plain());

            // A file from another project is rejected, and left alone.
            let untouched = other.clone();
            let status =
                rpgmasd_decrypter_decrypt_in_place(decrypter, other.as_mut_ptr(), other.len(), RPGMASD_FILE_TYPE_PNG);
            assert_eq!(status, RpgmasdStatus::KeyMismatch);
            assert_eq!(other, untouched);
        }
    }

    #[test]
    fn key_errors_are_reported() {
        let mut slot = MaybeUninit::<RpgmasdDecrypter>::uninit();

        unsafe {
            let decrypter = slot.as_mut_ptr();
            assert_eq!(rpgmasd_decrypter_init(decrypter), RpgmasdStatus::Ok);

            assert_eq!(
                rpgmasd_decrypter_set_key_from_str(decrypter, c"short".as_ptr()),
                RpgmasdStatus::InvalidKeyLength
            );
            assert_eq!(
                rpgmasd_decrypter_set_key_from_str(decrypter, c"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".as_ptr()),
                RpgmasdStatus::InvalidKey
            );
            assert_eq!(
                rpgmasd_decrypter_set_key_from_str(decrypter, c"\xff\xfe".as_ptr()),
                RpgmasdStatus::InvalidUtf8
            );

            // Uppercase is accepted, and read back in lowercase.
            let status = rpgmasd_decrypter_set_key_from_str(decrypter, c"D41D8CD98F00B204E9800998ECF8427E".as_ptr());
            assert_eq!(status, RpgmasdStatus::Ok);
            let mut key_out = [0 as c_char; RPGMASD_KEY_BUFFER_LENGTH];
            assert_eq!(
                rpgmasd_decrypter_key(decrypter, key_out.as_mut_ptr(), key_out.len()),
                RpgmasdStatus::Ok
            );
            assert_eq!(CStr::from_ptr(key_out.as_ptr()), KEY);

            assert_eq!(
                rpgmasd_decrypter_key(decrypter, ptr::null_mut(), RPGMASD_KEY_BUFFER_LENGTH),
                RpgmasdStatus::NullArgument
            );

            // A failed derivation leaves the key alone and reports why.
            let garbage = [0u8; 300];
            let status = rpgmasd_decrypter_set_key_from_file(
                decrypter,
                garbage.as_ptr(),
                garbage.len(),
                RPGMASD_FILE_TYPE_PNG,
                key_out.as_mut_ptr(),
                key_out.len(),
            );
            assert_eq!(status, RpgmasdStatus::InvalidHeader);

            let mut garbage = [0u8; 300];
            garbage[..RPGMASD_HEADER_LENGTH].copy_from_slice(rpgm_asset_decrypter_lib::RPGM_HEADER);
            // The decrypter has a key, so zeros that the key can't turn into any file type's magic bytes are a mismatch.
            for (file_type, expected) in [
                (RPGMASD_FILE_TYPE_PNG, RpgmasdStatus::KeyMismatch),
                (RPGMASD_FILE_TYPE_OGG, RpgmasdStatus::KeyMismatch),
                (RPGMASD_FILE_TYPE_M4A, RpgmasdStatus::KeyMismatch),
                (3, RpgmasdStatus::InvalidFileType),
            ] {
                let status =
                    rpgmasd_decrypter_decrypt_in_place_keyed(decrypter, garbage.as_mut_ptr(), garbage.len(), file_type);
                assert_eq!(status, expected, "{file_type}");
            }

            let mut fresh = MaybeUninit::<RpgmasdDecrypter>::uninit();
            assert_eq!(rpgmasd_decrypter_init(fresh.as_mut_ptr()), RpgmasdStatus::Ok);
            let status = rpgmasd_decrypter_set_key_from_file(
                fresh.as_mut_ptr(),
                garbage.as_ptr(),
                garbage.len(),
                RPGMASD_FILE_TYPE_OGG,
                key_out.as_mut_ptr(),
                key_out.len(),
            );
            assert_eq!(status, RpgmasdStatus::InvalidContent);
            let status = rpgmasd_decrypter_set_key_from_file(
                fresh.as_mut_ptr(),
                garbage.as_ptr(),
                garbage.len(),
                RPGMASD_FILE_TYPE_OGG,
                key_out.as_mut_ptr(),
                8,
            );
            assert_eq!(status, RpgmasdStatus::BufferTooSmall);
        }
    }

    #[test]
    fn encrypt_checks_arguments() {
        let mut plain = png_plain();
        let mut slot = MaybeUninit::<RpgmasdDecrypter>::uninit();

        unsafe {
            let decrypter = slot.as_mut_ptr();
            assert_eq!(rpgmasd_decrypter_init(decrypter), RpgmasdStatus::Ok);

            let status =
                rpgmasd_decrypter_encrypt_in_place(decrypter, plain.as_mut_ptr(), plain.len(), RPGMASD_FILE_TYPE_PNG);
            assert_eq!(status, RpgmasdStatus::KeyNotSet);

            assert_eq!(
                rpgmasd_decrypter_set_key_from_str(decrypter, KEY.as_ptr()),
                RpgmasdStatus::Ok
            );

            // Wrong file type: refused, and the data stays as it was.
            let before = plain;
            let status =
                rpgmasd_decrypter_encrypt_in_place(decrypter, plain.as_mut_ptr(), plain.len(), RPGMASD_FILE_TYPE_OGG);
            assert_eq!(status, RpgmasdStatus::InvalidContent);
            assert_eq!(plain, before);

            let status =
                rpgmasd_decrypter_encrypt_in_place(decrypter, plain.as_mut_ptr(), plain.len(), RPGMASD_FILE_TYPE_PNG);
            assert_eq!(status, RpgmasdStatus::Ok);
            assert_eq!(
                rpgmasd_encrypt_asset_in_place(plain.as_mut_ptr(), plain.len(), RPGMASD_FILE_TYPE_PNG, KEY.as_ptr()),
                RpgmasdStatus::InvalidContent
            );
        }
    }

    #[test]
    fn encrypt_into_clears_the_payload_on_failure() {
        let plain = png_plain();
        let mut decrypter = MaybeUninit::<RpgmasdDecrypter>::uninit();
        let mut out = [0xaa_u8; RPGMASD_HEADER_LENGTH + 64];
        let mut written = 0;

        unsafe {
            assert_eq!(rpgmasd_decrypter_init(decrypter.as_mut_ptr()), RpgmasdStatus::Ok);
            assert_eq!(
                rpgmasd_decrypter_set_key_from_str(decrypter.as_mut_ptr(), KEY.as_ptr()),
                RpgmasdStatus::Ok
            );
            let status = rpgmasd_decrypter_encrypt_into(
                decrypter.as_ptr(),
                plain.as_ptr(),
                plain.len(),
                RPGMASD_FILE_TYPE_OGG,
                out.as_mut_ptr(),
                out.len(),
                ptr::addr_of_mut!(written),
            );
            assert_eq!(status, RpgmasdStatus::InvalidContent);
        }

        assert!(out[RPGMASD_HEADER_LENGTH..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn encrypt_asset_in_place_matches_the_keyed_encryption() {
        let mut payload = png_plain();
        let status = unsafe {
            rpgmasd_encrypt_asset_in_place(payload.as_mut_ptr(), payload.len(), RPGMASD_FILE_TYPE_PNG, KEY.as_ptr())
        };
        assert_eq!(status, RpgmasdStatus::Ok);
        assert_eq!(payload, encrypted(&png_plain(), KEY)[RPGMASD_HEADER_LENGTH..]);
    }

    #[test]
    fn ogg_and_m4a_keys_are_derived_through_the_c_api() {
        // `offset` is where the file type's magic bytes sit in the decrypted file, relative to the start of the payload.
        for (fixture, file_type, offset, magic) in [
            (
                &include_bytes!("../../tests/assets/mz/test-default.ogg_")[..],
                RPGMASD_FILE_TYPE_OGG,
                0,
                &b"OggS"[..],
            ),
            (
                &include_bytes!("../../tests/assets/mz/test-default.m4a_")[..],
                RPGMASD_FILE_TYPE_M4A,
                4,
                &b"ftyp"[..],
            ),
        ] {
            let mut file = fixture.to_vec();
            let mut slot = MaybeUninit::<RpgmasdDecrypter>::uninit();
            let mut key_out = [0 as c_char; RPGMASD_KEY_BUFFER_LENGTH];

            unsafe {
                assert_eq!(rpgmasd_decrypter_init(slot.as_mut_ptr()), RpgmasdStatus::Ok);
                let status = rpgmasd_decrypter_set_key_from_file(
                    slot.as_mut_ptr(),
                    file.as_ptr(),
                    file.len(),
                    file_type,
                    key_out.as_mut_ptr(),
                    key_out.len(),
                );
                assert_eq!(status, RpgmasdStatus::Ok, "file type {file_type}");

                let status =
                    rpgmasd_decrypter_decrypt_in_place_keyed(slot.as_ptr(), file.as_mut_ptr(), file.len(), file_type);
                assert_eq!(status, RpgmasdStatus::Ok, "file type {file_type}");
            }
            assert_eq!(
                &file[RPGMASD_HEADER_LENGTH + offset..][..magic.len()],
                magic,
                "file type {file_type}"
            );
        }
    }

    #[test]
    fn rejects_bad_arguments() {
        let mut file = encrypted(&png_plain(), KEY);
        let mut slot = MaybeUninit::<RpgmasdDecrypter>::uninit();

        unsafe {
            assert_eq!(rpgmasd_header(ptr::null_mut()), RpgmasdStatus::NullArgument);
            assert_eq!(rpgmasd_decrypter_init(ptr::null_mut()), RpgmasdStatus::NullArgument);
            assert_eq!(
                rpgmasd_decrypt_asset_in_place(ptr::null_mut(), 0, RPGMASD_FILE_TYPE_PNG),
                RpgmasdStatus::NullArgument
            );
            assert_eq!(
                rpgmasd_encrypt_asset_in_place(file.as_mut_ptr(), file.len(), RPGMASD_FILE_TYPE_PNG, ptr::null()),
                RpgmasdStatus::NullArgument
            );
            assert_eq!(
                rpgmasd_decrypter_key(ptr::null(), ptr::null_mut(), 0),
                RpgmasdStatus::NullArgument
            );
            // Out-of-range file types must be an error, not UB.
            assert_eq!(
                rpgmasd_decrypt_asset_in_place(file.as_mut_ptr(), file.len(), 3),
                RpgmasdStatus::InvalidFileType
            );
            assert_eq!(
                rpgmasd_decrypt_asset_in_place(file.as_mut_ptr(), file.len(), u32::MAX),
                RpgmasdStatus::InvalidFileType
            );
            assert_eq!(rpgmasd_decrypter_init(slot.as_mut_ptr()), RpgmasdStatus::Ok);
            assert_eq!(
                rpgmasd_decrypter_decrypt_in_place_keyed(
                    slot.as_ptr(),
                    file.as_mut_ptr(),
                    file.len(),
                    RPGMASD_FILE_TYPE_PNG
                ),
                RpgmasdStatus::KeyNotSet
            );
            // Empty input is a normal error, not a crash.
            assert_eq!(
                rpgmasd_decrypt_asset_in_place(file.as_mut_ptr(), 0, RPGMASD_FILE_TYPE_PNG),
                RpgmasdStatus::InvalidHeader
            );
        }
    }
}
