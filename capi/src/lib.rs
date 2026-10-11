#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

use core::{
    ffi::{CStr, c_char},
    mem, ptr, slice,
};
use rpgm_asset_decrypter_lib::{Decrypter as InnerDecrypter, Error as InnerError, FileType as InnerFileType};

// No allocator or heap types are used anywhere in this crate, so a no_std build needs nothing
// beyond a panic handler - never linked in when the default `std` feature (and with it, `std`'s
// own panic handler) is enabled, to avoid a duplicate lang item.
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe extern "C" {
        fn abort() -> !;
    }
    unsafe { abort() }
}

/// The original, decrypted asset kind.
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RpgmasdFileType {
    Png = 0,
    Ogg = 1,
    M4a = 2,
}

impl From<RpgmasdFileType> for InnerFileType {
    fn from(file_type: RpgmasdFileType) -> Self {
        match file_type {
            RpgmasdFileType::Png => InnerFileType::PNG,
            RpgmasdFileType::Ogg => InnerFileType::OGG,
            RpgmasdFileType::M4a => InnerFileType::M4A,
        }
    }
}

/// Status code returned by every fallible `rpgmasd_*` function. `RPGMASD_STATUS_OK` is the only success value.
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
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
}

impl From<InnerError> for RpgmasdStatus {
    fn from(error: InnerError) -> Self {
        match error {
            InnerError::KeyNotSet => Self::KeyNotSet,
            InnerError::InvalidKeyLength => Self::InvalidKeyLength,
            InnerError::InvalidKey => Self::InvalidKey,
            InnerError::InvalidHeader => Self::InvalidHeader,
            InnerError::UnexpectedEOF => Self::UnexpectedEof,
        }
    }
}

/// Opaque `Decrypter` instance. This type carries no heap allocation - it is a fixed-size,
/// fixed-alignment value the caller owns directly. Reserve storage for it (e.g. a local variable,
/// or a buffer sized/aligned per `rpgmasd_decrypter_size`/`rpgmasd_decrypter_align`) and initialize
/// it with `rpgmasd_decrypter_init`; there is no corresponding free function; once you are done
/// with the storage, simply reclaim it (e.g. let it go out of scope).
pub struct RpgmasdDecrypter(InnerDecrypter);

/// The size, in bytes, of a `Decrypter` instance - the minimum size of the storage passed to
/// `rpgmasd_decrypter_init`.
#[no_mangle]
pub extern "C" fn rpgmasd_decrypter_size() -> usize {
    mem::size_of::<RpgmasdDecrypter>()
}

/// The required alignment, in bytes, of the storage passed to `rpgmasd_decrypter_init`.
#[no_mangle]
pub extern "C" fn rpgmasd_decrypter_align() -> usize {
    mem::align_of::<RpgmasdDecrypter>()
}

/// Initializes a `Decrypter` into caller-provided storage. `out` must point to at least
/// `rpgmasd_decrypter_size()` writable bytes, aligned to `rpgmasd_decrypter_align()`.
///
/// Returns `RPGMASD_STATUS_OK` on success, or `RPGMASD_STATUS_NULL_ARGUMENT` if `out` is null.
///
/// # Safety
///
/// Pointer arguments must be valid for the access their type and any paired length imply; `data` is
/// written through, so it must also be exclusively accessible for the call. Key arguments must be
/// NUL-terminated, and `out_key` must have room for 33 bytes. `decrypter` must point to storage of
/// `rpgmasd_decrypter_size()` bytes aligned to `rpgmasd_decrypter_align()` that
/// `rpgmasd_decrypter_init` has initialised. Null pointers are rejected with
/// `RPGMASD_STATUS_NULL_ARGUMENT` where the function documents it.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_init(out: *mut RpgmasdDecrypter) -> RpgmasdStatus {
    if out.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `out` points to writable storage of at least `rpgmasd_decrypter_size()`
    // bytes, aligned to `rpgmasd_decrypter_align()`.
    unsafe { out.write(RpgmasdDecrypter(InnerDecrypter::new())) };

    RpgmasdStatus::Ok
}

/// Writes the decrypter's key as a NUL-terminated 32-character hex string into `out_key`, which must
/// point to a buffer of at least 33 bytes.
///
/// Returns `RPGMASD_STATUS_OK` on success, `RPGMASD_STATUS_KEY_NOT_SET` if no key has been set yet, or
/// `RPGMASD_STATUS_NULL_ARGUMENT` if `decrypter` or `out_key` is null.
///
/// # Safety
///
/// Pointer arguments must be valid for the access their type and any paired length imply; `data` is
/// written through, so it must also be exclusively accessible for the call. Key arguments must be
/// NUL-terminated, and `out_key` must have room for 33 bytes. `decrypter` must point to storage of
/// `rpgmasd_decrypter_size()` bytes aligned to `rpgmasd_decrypter_align()` that
/// `rpgmasd_decrypter_init` has initialised. Null pointers are rejected with
/// `RPGMASD_STATUS_NULL_ARGUMENT` where the function documents it.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_key(decrypter: *const RpgmasdDecrypter, out_key: *mut c_char) -> RpgmasdStatus {
    if decrypter.is_null() || out_key.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmasd_decrypter_init`.
    let key = unsafe { &*decrypter }.0.key();

    let Some(key) = key else {
        return RpgmasdStatus::KeyNotSet;
    };

    // SAFETY: caller guarantees `out_key` points to a writable buffer of at least `key.len() + 1` bytes.
    unsafe {
        ptr::copy_nonoverlapping(key.as_ptr(), out_key.cast::<u8>(), key.len());
        *out_key.add(key.len()) = 0;
    }

    RpgmasdStatus::Ok
}

/// Sets the decrypter's key from a NUL-terminated 32-character hex string.
///
/// Returns `RPGMASD_STATUS_OK` on success, `RPGMASD_STATUS_INVALID_KEY_LENGTH` if `key` isn't 32 bytes
/// long, `RPGMASD_STATUS_INVALID_UTF8` if `key` isn't valid UTF-8, or `RPGMASD_STATUS_NULL_ARGUMENT` if a
/// pointer is null.
///
/// # Safety
///
/// Pointer arguments must be valid for the access their type and any paired length imply; `data` is
/// written through, so it must also be exclusively accessible for the call. Key arguments must be
/// NUL-terminated, and `out_key` must have room for 33 bytes. `decrypter` must point to storage of
/// `rpgmasd_decrypter_size()` bytes aligned to `rpgmasd_decrypter_align()` that
/// `rpgmasd_decrypter_init` has initialised. Null pointers are rejected with
/// `RPGMASD_STATUS_NULL_ARGUMENT` where the function documents it.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_set_key_from_str(decrypter: *mut RpgmasdDecrypter, key: *const c_char) -> RpgmasdStatus {
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
/// NUL-terminated string into `out_key`, which must point to a buffer of at least 33 bytes.
///
/// Returns `RPGMASD_STATUS_OK` on success, or an error status if `data` has an invalid header or ends
/// unexpectedly.
///
/// # Safety
///
/// Pointer arguments must be valid for the access their type and any paired length imply; `data` is
/// written through, so it must also be exclusively accessible for the call. Key arguments must be
/// NUL-terminated, and `out_key` must have room for 33 bytes. `decrypter` must point to storage of
/// `rpgmasd_decrypter_size()` bytes aligned to `rpgmasd_decrypter_align()` that
/// `rpgmasd_decrypter_init` has initialised. Null pointers are rejected with
/// `RPGMASD_STATUS_NULL_ARGUMENT` where the function documents it.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_set_key_from_file(
    decrypter: *mut RpgmasdDecrypter,
    data: *const u8,
    data_len: usize,
    file_type: RpgmasdFileType,
    out_key: *mut c_char,
) -> RpgmasdStatus {
    if decrypter.is_null() || data.is_null() || out_key.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `data` points to `data_len` readable, initialized bytes.
    let data = unsafe { slice::from_raw_parts(data, data_len) };

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmasd_decrypter_init`.
    match unsafe { &mut *decrypter }.0.set_key_from_file(data, file_type.into()) {
        Ok(key) => {
            // SAFETY: caller guarantees `out_key` points to a writable buffer of at least `key.len() + 1` bytes.
            unsafe {
                ptr::copy_nonoverlapping(key.as_ptr(), out_key.cast::<u8>(), key.len());
                *out_key.add(key.len()) = 0;
            }

            RpgmasdStatus::Ok
        }
        Err(error) => error.into(),
    }
}

/// Decrypts RPG Maker file content in place. Auto-determines the key from `data` if the decrypter
/// doesn't already have one set. Decrypted data is valid starting at byte offset 16 of `data`.
///
/// # Safety
///
/// Pointer arguments must be valid for the access their type and any paired length imply; `data` is
/// written through, so it must also be exclusively accessible for the call. Key arguments must be
/// NUL-terminated, and `out_key` must have room for 33 bytes. `decrypter` must point to storage of
/// `rpgmasd_decrypter_size()` bytes aligned to `rpgmasd_decrypter_align()` that
/// `rpgmasd_decrypter_init` has initialised. Null pointers are rejected with
/// `RPGMASD_STATUS_NULL_ARGUMENT` where the function documents it.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_decrypt_in_place(
    decrypter: *mut RpgmasdDecrypter,
    data: *mut u8,
    data_len: usize,
    file_type: RpgmasdFileType,
) -> RpgmasdStatus {
    if decrypter.is_null() || data.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `data` points to `data_len` readable and writable, initialized bytes.
    let data = unsafe { slice::from_raw_parts_mut(data, data_len) };

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmasd_decrypter_init`.
    match unsafe { &mut *decrypter }.0.decrypt_in_place(data, file_type.into()) {
        Ok(_) => RpgmasdStatus::Ok,
        Err(error) => error.into(),
    }
}

/// Encrypts file content in place. Requires the decrypter to already have a key set. Produces the raw
/// encrypted payload, without the RPG Maker header.
///
/// # Safety
///
/// Pointer arguments must be valid for the access their type and any paired length imply; `data` is
/// written through, so it must also be exclusively accessible for the call. Key arguments must be
/// NUL-terminated, and `out_key` must have room for 33 bytes. `decrypter` must point to storage of
/// `rpgmasd_decrypter_size()` bytes aligned to `rpgmasd_decrypter_align()` that
/// `rpgmasd_decrypter_init` has initialised. Null pointers are rejected with
/// `RPGMASD_STATUS_NULL_ARGUMENT` where the function documents it.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypter_encrypt_in_place(
    decrypter: *const RpgmasdDecrypter,
    data: *mut u8,
    data_len: usize,
) -> RpgmasdStatus {
    if decrypter.is_null() || data.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `data` points to `data_len` readable and writable, initialized bytes.
    let data = unsafe { slice::from_raw_parts_mut(data, data_len) };

    // SAFETY: caller guarantees `decrypter` points to a live `Decrypter` from `rpgmasd_decrypter_init`.
    match unsafe { &*decrypter }.0.encrypt_in_place(data) {
        Ok(()) => RpgmasdStatus::Ok,
        Err(error) => error.into(),
    }
}

/// Decrypts RPG Maker file content in place using a temporary `Decrypter` instance.
///
/// # Safety
///
/// Pointer arguments must be valid for the access their type and any paired length imply; `data` is
/// written through, so it must also be exclusively accessible for the call. Key arguments must be
/// NUL-terminated, and `out_key` must have room for 33 bytes. `decrypter` must point to storage of
/// `rpgmasd_decrypter_size()` bytes aligned to `rpgmasd_decrypter_align()` that
/// `rpgmasd_decrypter_init` has initialised. Null pointers are rejected with
/// `RPGMASD_STATUS_NULL_ARGUMENT` where the function documents it.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_decrypt_asset_in_place(data: *mut u8, data_len: usize, file_type: RpgmasdFileType) -> RpgmasdStatus {
    if data.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `data` points to `data_len` readable and writable, initialized bytes.
    let data = unsafe { slice::from_raw_parts_mut(data, data_len) };

    match InnerDecrypter::new().decrypt_in_place(data, file_type.into()) {
        Ok(_) => RpgmasdStatus::Ok,
        Err(error) => error.into(),
    }
}

/// Encrypts file content in place using a NUL-terminated key string and a temporary `Decrypter` instance.
///
/// # Safety
///
/// Pointer arguments must be valid for the access their type and any paired length imply; `data` is
/// written through, so it must also be exclusively accessible for the call. Key arguments must be
/// NUL-terminated, and `out_key` must have room for 33 bytes. `decrypter` must point to storage of
/// `rpgmasd_decrypter_size()` bytes aligned to `rpgmasd_decrypter_align()` that
/// `rpgmasd_decrypter_init` has initialised. Null pointers are rejected with
/// `RPGMASD_STATUS_NULL_ARGUMENT` where the function documents it.
#[no_mangle]
pub unsafe extern "C" fn rpgmasd_encrypt_asset_in_place(data: *mut u8, data_len: usize, key: *const c_char) -> RpgmasdStatus {
    if data.is_null() || key.is_null() {
        return RpgmasdStatus::NullArgument;
    }

    // SAFETY: caller guarantees `data` points to `data_len` readable and writable, initialized bytes.
    let data = unsafe { slice::from_raw_parts_mut(data, data_len) };

    // SAFETY: caller guarantees `key` is a valid, NUL-terminated C string.
    let Ok(key) = unsafe { CStr::from_ptr(key) }.to_str() else {
        return RpgmasdStatus::InvalidUtf8;
    };

    let mut decrypter = InnerDecrypter::new();

    match decrypter
        .set_key_from_str(key)
        .and_then(|()| decrypter.encrypt_in_place(data))
    {
        Ok(()) => RpgmasdStatus::Ok,
        Err(error) => error.into(),
    }
}

// Literals, not `= rpgm_asset_decrypter_lib::X`: cbindgen only turns literal consts into `#define`s,
// which (unlike an exported `extern const` symbol) work in array sizes and need no `dllimport` from
// a Windows DLL consumer. The assertions keep them equal to the real lengths.

/// The fixed 16-byte length of the RPG Maker encryption header.
pub const RPGMASD_HEADER_LENGTH: usize = 16;

/// The fixed 32-character length of a hex-encoded key string.
pub const RPGMASD_KEY_STR_LENGTH: usize = 32;

const _: () = {
    assert!(RPGMASD_HEADER_LENGTH == rpgm_asset_decrypter_lib::HEADER_LENGTH);
    assert!(RPGMASD_KEY_STR_LENGTH == rpgm_asset_decrypter_lib::KEY_STR_LENGTH);
};
