//! The C ABI's error paths and its less common success paths, from Rust. `c_api.c` covers the usual flow in C; these cover
//! null pointers, short buffers, unknown file types and keys that don't fit, where the coverage tool can see them.

use rpgm_asset_decrypter_lib::{FileType, RPGM_HEADER, encrypt};
use rpgmasd::{
    RPGMASD_DECRYPTER_ALIGN, RPGMASD_DECRYPTER_SIZE, RPGMASD_FILE_TYPE_PNG, RPGMASD_HEADER_LENGTH,
    RPGMASD_KEY_BUFFER_LENGTH, RpgmasdDecrypter, RpgmasdStatus, rpgmasd_decrypt_asset_in_place,
    rpgmasd_decrypter_align, rpgmasd_decrypter_decrypt_in_place, rpgmasd_decrypter_decrypt_in_place_keyed,
    rpgmasd_decrypter_encrypt_in_place, rpgmasd_decrypter_encrypt_into, rpgmasd_decrypter_init, rpgmasd_decrypter_key,
    rpgmasd_decrypter_set_key_from_file, rpgmasd_decrypter_set_key_from_str, rpgmasd_decrypter_size,
    rpgmasd_default_key, rpgmasd_encrypt_asset_in_place, rpgmasd_header,
};
use std::{
    ffi::{CStr, c_char},
    mem::MaybeUninit,
};

const KEY: &str = "00112233445566778899aabbccddeeff";

// A PNG whose IHDR passes the checker (8-bit RGBA, not interlaced), followed by nothing.
fn png() -> Vec<u8> {
    let mut plain = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    plain.extend_from_slice(&16u32.to_be_bytes());
    plain.extend_from_slice(&16u32.to_be_bytes());
    plain.extend_from_slice(&[8, 6, 0, 0, 0]);
    plain
}

/// A decrypter initialized in caller-owned storage, the way C code does it.
fn initialized() -> MaybeUninit<RpgmasdDecrypter> {
    let mut storage = MaybeUninit::<RpgmasdDecrypter>::uninit();

    // SAFETY: `storage` is writable, sized and aligned for a `RpgmasdDecrypter`.
    assert_eq!(
        unsafe { rpgmasd_decrypter_init(storage.as_mut_ptr()) },
        RpgmasdStatus::Ok
    );

    storage
}

/// A decrypter with `KEY` set.
fn keyed() -> MaybeUninit<RpgmasdDecrypter> {
    let mut storage = initialized();
    let key = c"00112233445566778899aabbccddeeff";

    // SAFETY: `storage` was initialized above and `key` is NUL-terminated.
    assert_eq!(
        unsafe { rpgmasd_decrypter_set_key_from_str(storage.as_mut_ptr(), key.as_ptr()) },
        RpgmasdStatus::Ok
    );

    storage
}

#[test]
fn the_storage_constants_match_the_layout() {
    assert_eq!(rpgmasd_decrypter_size(), RPGMASD_DECRYPTER_SIZE);
    assert_eq!(rpgmasd_decrypter_align(), RPGMASD_DECRYPTER_ALIGN);
}

#[test]
fn the_header_is_copied_out_and_null_is_refused() {
    let mut out = [0u8; RPGMASD_HEADER_LENGTH];

    // SAFETY: `out` is writable for the header's length.
    assert_eq!(unsafe { rpgmasd_header(out.as_mut_ptr()) }, RpgmasdStatus::Ok);
    assert_eq!(out, RPGM_HEADER);

    // SAFETY: a null pointer is refused without being written through.
    assert_eq!(
        unsafe { rpgmasd_header(std::ptr::null_mut()) },
        RpgmasdStatus::NullArgument
    );
}

#[test]
fn init_refuses_null() {
    // SAFETY: a null pointer is refused without being written through.
    assert_eq!(
        unsafe { rpgmasd_decrypter_init(std::ptr::null_mut()) },
        RpgmasdStatus::NullArgument
    );
}

#[test]
fn the_key_is_refused_while_unset_or_when_the_buffer_is_short() {
    let storage = initialized();
    let mut buffer = [0 as c_char; RPGMASD_KEY_BUFFER_LENGTH];

    // SAFETY: the decrypter is initialized and the buffer is writable for its length.
    unsafe {
        assert_eq!(
            rpgmasd_decrypter_key(storage.as_ptr(), buffer.as_mut_ptr(), RPGMASD_KEY_BUFFER_LENGTH - 1),
            RpgmasdStatus::BufferTooSmall
        );
        assert_eq!(
            rpgmasd_decrypter_key(storage.as_ptr(), buffer.as_mut_ptr(), RPGMASD_KEY_BUFFER_LENGTH),
            RpgmasdStatus::KeyNotSet
        );
        assert_eq!(
            rpgmasd_decrypter_key(std::ptr::null(), buffer.as_mut_ptr(), RPGMASD_KEY_BUFFER_LENGTH),
            RpgmasdStatus::NullArgument
        );
        assert_eq!(
            rpgmasd_decrypter_key(storage.as_ptr(), std::ptr::null_mut(), RPGMASD_KEY_BUFFER_LENGTH),
            RpgmasdStatus::NullArgument
        );
    }
}

#[test]
fn the_key_is_written_once_set() {
    let storage = keyed();
    let mut buffer = [0 as c_char; RPGMASD_KEY_BUFFER_LENGTH];

    // SAFETY: the decrypter has a key and the buffer is writable for its length.
    assert_eq!(
        unsafe { rpgmasd_decrypter_key(storage.as_ptr(), buffer.as_mut_ptr(), RPGMASD_KEY_BUFFER_LENGTH) },
        RpgmasdStatus::Ok
    );

    // SAFETY: the buffer holds a NUL-terminated key string.
    let key = unsafe { CStr::from_ptr(buffer.as_ptr()) };
    assert_eq!(key.to_str(), Ok(KEY));
}

#[test]
fn a_key_string_is_checked_before_it_is_set() {
    let mut storage = initialized();

    // SAFETY: the decrypter is initialized and every string is NUL-terminated.
    unsafe {
        assert_eq!(
            rpgmasd_decrypter_set_key_from_str(std::ptr::null_mut(), c"x".as_ptr()),
            RpgmasdStatus::NullArgument
        );
        assert_eq!(
            rpgmasd_decrypter_set_key_from_str(storage.as_mut_ptr(), std::ptr::null()),
            RpgmasdStatus::NullArgument
        );
        assert_eq!(
            rpgmasd_decrypter_set_key_from_str(storage.as_mut_ptr(), c"\xff".as_ptr()),
            RpgmasdStatus::InvalidUtf8
        );
        assert_eq!(
            rpgmasd_decrypter_set_key_from_str(storage.as_mut_ptr(), c"abc".as_ptr()),
            RpgmasdStatus::InvalidKeyLength
        );
        assert_eq!(
            rpgmasd_decrypter_set_key_from_str(storage.as_mut_ptr(), c"zz112233445566778899aabbccddeeff".as_ptr()),
            RpgmasdStatus::InvalidKey
        );
    }
}

#[test]
fn a_key_is_derived_from_an_encrypted_file() {
    // `encrypt` returns a complete file, RPG Maker header included.
    let file = encrypt(&png(), FileType::Png, KEY).unwrap();

    let mut storage = initialized();
    let mut buffer = [0 as c_char; RPGMASD_KEY_BUFFER_LENGTH];

    // SAFETY: the decrypter is initialized, `file` is readable for its length and `buffer` is writable for its length.
    unsafe {
        assert_eq!(
            rpgmasd_decrypter_set_key_from_file(
                std::ptr::null_mut(),
                file.as_ptr(),
                file.len(),
                RPGMASD_FILE_TYPE_PNG,
                buffer.as_mut_ptr(),
                RPGMASD_KEY_BUFFER_LENGTH,
            ),
            RpgmasdStatus::NullArgument
        );
        assert_eq!(
            rpgmasd_decrypter_set_key_from_file(
                storage.as_mut_ptr(),
                file.as_ptr(),
                file.len(),
                9,
                buffer.as_mut_ptr(),
                RPGMASD_KEY_BUFFER_LENGTH,
            ),
            RpgmasdStatus::InvalidFileType
        );
        assert_eq!(
            rpgmasd_decrypter_set_key_from_file(
                storage.as_mut_ptr(),
                file.as_ptr(),
                file.len(),
                RPGMASD_FILE_TYPE_PNG,
                buffer.as_mut_ptr(),
                RPGMASD_KEY_BUFFER_LENGTH - 1,
            ),
            RpgmasdStatus::BufferTooSmall
        );
        assert_eq!(
            rpgmasd_decrypter_set_key_from_file(
                storage.as_mut_ptr(),
                file.as_ptr(),
                file.len(),
                RPGMASD_FILE_TYPE_PNG,
                buffer.as_mut_ptr(),
                RPGMASD_KEY_BUFFER_LENGTH,
            ),
            RpgmasdStatus::Ok
        );

        let key = CStr::from_ptr(buffer.as_ptr());
        assert_eq!(key.to_str(), Ok(KEY));
    }
}

#[test]
fn decrypting_refuses_null_unknown_types_and_missing_keys() {
    let mut data = png();
    let mut storage = initialized();

    // SAFETY: the decrypter is initialized and `data` is readable and writable for its length.
    unsafe {
        assert_eq!(
            rpgmasd_decrypter_decrypt_in_place(
                std::ptr::null_mut(),
                data.as_mut_ptr(),
                data.len(),
                RPGMASD_FILE_TYPE_PNG
            ),
            RpgmasdStatus::NullArgument
        );
        assert_eq!(
            rpgmasd_decrypter_decrypt_in_place(storage.as_mut_ptr(), data.as_mut_ptr(), data.len(), 9),
            RpgmasdStatus::InvalidFileType
        );
        assert_eq!(
            rpgmasd_decrypter_decrypt_in_place_keyed(
                std::ptr::null(),
                data.as_mut_ptr(),
                data.len(),
                RPGMASD_FILE_TYPE_PNG
            ),
            RpgmasdStatus::NullArgument
        );
        // Keyed decryption needs a key already set; this decrypter has none.
        assert_eq!(
            rpgmasd_decrypter_decrypt_in_place_keyed(
                storage.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                RPGMASD_FILE_TYPE_PNG
            ),
            RpgmasdStatus::KeyNotSet
        );
        assert_eq!(
            rpgmasd_decrypt_asset_in_place(data.as_mut_ptr(), data.len(), 9),
            RpgmasdStatus::InvalidFileType
        );
    }
}

#[test]
fn encrypting_in_place_needs_a_key_and_a_known_type() {
    let mut data = png();
    let unset = initialized();
    let keyed_storage = keyed();

    // SAFETY: the decrypters are initialized and `data` is readable and writable for its length.
    unsafe {
        assert_eq!(
            rpgmasd_decrypter_encrypt_in_place(std::ptr::null(), data.as_mut_ptr(), data.len(), RPGMASD_FILE_TYPE_PNG),
            RpgmasdStatus::NullArgument
        );
        assert_eq!(
            rpgmasd_decrypter_encrypt_in_place(unset.as_ptr(), data.as_mut_ptr(), data.len(), 9),
            RpgmasdStatus::InvalidFileType
        );
        assert_eq!(
            rpgmasd_decrypter_encrypt_in_place(unset.as_ptr(), data.as_mut_ptr(), data.len(), RPGMASD_FILE_TYPE_PNG),
            RpgmasdStatus::KeyNotSet
        );
        assert_eq!(
            rpgmasd_decrypter_encrypt_in_place(
                keyed_storage.as_ptr(),
                data.as_mut_ptr(),
                data.len(),
                RPGMASD_FILE_TYPE_PNG
            ),
            RpgmasdStatus::Ok
        );
    }
}

#[test]
fn encrypt_into_writes_the_header_and_the_payload_and_reports_its_length() {
    let plain = png();
    let storage = keyed();
    let total = RPGMASD_HEADER_LENGTH + plain.len();
    let mut out = vec![0u8; total];
    let mut out_len = 0usize;

    // SAFETY: the decrypter has a key, `plain` is readable, `out` is writable for `total` bytes and does not overlap `plain`.
    unsafe {
        assert_eq!(
            rpgmasd_decrypter_encrypt_into(
                std::ptr::null(),
                plain.as_ptr(),
                plain.len(),
                RPGMASD_FILE_TYPE_PNG,
                out.as_mut_ptr(),
                total,
                std::ptr::addr_of_mut!(out_len),
            ),
            RpgmasdStatus::NullArgument
        );

        // Too short for the output: the length is still reported, so the caller knows what to allocate.
        assert_eq!(
            rpgmasd_decrypter_encrypt_into(
                storage.as_ptr(),
                plain.as_ptr(),
                plain.len(),
                RPGMASD_FILE_TYPE_PNG,
                out.as_mut_ptr(),
                total - 1,
                std::ptr::addr_of_mut!(out_len),
            ),
            RpgmasdStatus::BufferTooSmall
        );
        assert_eq!(out_len, total);

        assert_eq!(
            rpgmasd_decrypter_encrypt_into(
                storage.as_ptr(),
                plain.as_ptr(),
                plain.len(),
                RPGMASD_FILE_TYPE_PNG,
                out.as_mut_ptr(),
                total,
                std::ptr::addr_of_mut!(out_len),
            ),
            RpgmasdStatus::Ok
        );
    }

    assert_eq!(out_len, total);
    assert_eq!(&out[..RPGMASD_HEADER_LENGTH], RPGM_HEADER);
    assert_ne!(&out[RPGMASD_HEADER_LENGTH..], &plain[..]);
}

#[test]
fn encrypt_into_refuses_an_overflowing_length_without_writing_it() {
    let plain = png();
    let storage = keyed();
    let mut out = [0u8; 4];
    let mut out_len = 0usize;

    // SAFETY: `out` is writable for its length; the length would overflow, so nothing is read past `plain`.
    assert_eq!(
        unsafe {
            rpgmasd_decrypter_encrypt_into(
                storage.as_ptr(),
                plain.as_ptr(),
                usize::MAX,
                RPGMASD_FILE_TYPE_PNG,
                out.as_mut_ptr(),
                out.len(),
                std::ptr::addr_of_mut!(out_len),
            )
        },
        RpgmasdStatus::BufferTooSmall
    );
    assert_eq!(out_len, 0);
}

#[test]
fn a_failed_encrypt_into_clears_the_payload() {
    let plain = png();
    let unset = initialized();
    let total = RPGMASD_HEADER_LENGTH + plain.len();
    let mut out = vec![0xaau8; total];
    let mut out_len = 0usize;

    // SAFETY: the decrypter has no key, so the encryption fails after the plaintext was copied into `out`.
    assert_eq!(
        unsafe {
            rpgmasd_decrypter_encrypt_into(
                unset.as_ptr(),
                plain.as_ptr(),
                plain.len(),
                RPGMASD_FILE_TYPE_PNG,
                out.as_mut_ptr(),
                total,
                std::ptr::addr_of_mut!(out_len),
            )
        },
        RpgmasdStatus::KeyNotSet
    );
    assert!(out[RPGMASD_HEADER_LENGTH..].iter().all(|&byte| byte == 0));
}

#[test]
fn the_one_shot_encrypt_checks_its_arguments() {
    let mut data = png();

    // SAFETY: `data` is readable and writable for its length, and the key strings are NUL-terminated.
    unsafe {
        assert_eq!(
            rpgmasd_encrypt_asset_in_place(std::ptr::null_mut(), data.len(), RPGMASD_FILE_TYPE_PNG, c"x".as_ptr()),
            RpgmasdStatus::NullArgument
        );
        assert_eq!(
            rpgmasd_encrypt_asset_in_place(data.as_mut_ptr(), data.len(), RPGMASD_FILE_TYPE_PNG, std::ptr::null()),
            RpgmasdStatus::NullArgument
        );
        assert_eq!(
            rpgmasd_encrypt_asset_in_place(data.as_mut_ptr(), data.len(), 9, c"x".as_ptr()),
            RpgmasdStatus::InvalidFileType
        );
        assert_eq!(
            rpgmasd_encrypt_asset_in_place(data.as_mut_ptr(), data.len(), RPGMASD_FILE_TYPE_PNG, c"\xff".as_ptr()),
            RpgmasdStatus::InvalidUtf8
        );
        assert_eq!(
            rpgmasd_encrypt_asset_in_place(data.as_mut_ptr(), data.len(), RPGMASD_FILE_TYPE_PNG, c"abc".as_ptr()),
            RpgmasdStatus::InvalidKeyLength
        );
    }
}

#[test]
fn the_default_key_is_the_empty_key_hash() {
    // SAFETY: the pointer refers to static, NUL-terminated storage.
    let key = unsafe { CStr::from_ptr(rpgmasd_default_key()) };

    assert_eq!(key.to_str(), Ok("d41d8cd98f00b204e9800998ecf8427e"));
}
