#![no_main]
use libfuzzer_sys::fuzz_target;
use rpgm_asset_decrypter_lib::{Decrypter, FileType};
use rpgmasd::{
    RPGMASD_FILE_TYPE_M4A, RPGMASD_FILE_TYPE_OGG, RPGMASD_FILE_TYPE_PNG, RPGMASD_HEADER_LENGTH,
    RPGMASD_KEY_BUFFER_LENGTH, RpgmasdDecrypter, RpgmasdStatus, rpgmasd_decrypt_asset_in_place,
    rpgmasd_decrypter_decrypt_in_place_keyed, rpgmasd_decrypter_encrypt_into, rpgmasd_decrypter_init,
    rpgmasd_decrypter_key, rpgmasd_decrypter_set_key_from_file, rpgmasd_decrypter_set_key_from_str,
    rpgmasd_encrypt_asset_in_place,
};
use std::{
    ffi::{CStr, CString, c_char},
    mem::MaybeUninit,
};

// The safe API's file type for a raw ABI value; `None` for values the ABI must reject.
fn core_file_type(file_type: u32) -> Option<FileType> {
    match file_type {
        RPGMASD_FILE_TYPE_PNG => Some(FileType::Png),
        RPGMASD_FILE_TYPE_OGG => Some(FileType::Ogg),
        RPGMASD_FILE_TYPE_M4A => Some(FileType::M4a),
        _ => None,
    }
}

// Content of `file_type` that the encrypt functions accept: its magic bytes, then `body`.
fn plain_for(file_type: u32, body: &[u8]) -> Vec<u8> {
    let magic: &[u8] = match file_type {
        RPGMASD_FILE_TYPE_PNG => b"\x89PNG\r\n\x1a\n",
        RPGMASD_FILE_TYPE_OGG => b"OggS",
        _ => b"\0\0\0\x1cftypM4A ",
    };
    [magic, body].concat()
}

// Whole-buffer decryption. Success must match the safe API byte for byte, and a failure must leave the buffer alone.
fn decrypt_in_place_whole(data: &[u8], file_type: u32, core: Option<FileType>) {
    let mut buffer = data.to_vec();
    let status = unsafe { rpgmasd_decrypt_asset_in_place(buffer.as_mut_ptr(), buffer.len(), file_type) };

    let Some(core) = core else {
        assert_eq!(status, RpgmasdStatus::InvalidFileType);
        assert!(buffer == data, "a rejected file type modified the buffer");
        return;
    };

    let expected = Decrypter::new().decrypt(data, core);
    assert_eq!(status == RpgmasdStatus::Ok, expected.is_ok());
    match expected {
        Ok(plain) => assert!(buffer[RPGMASD_HEADER_LENGTH..] == plain[..]),
        Err(_) => assert!(buffer == data, "a failed decryption modified the buffer"),
    }
}

// Key derivation from the file, the key string it reports, the keyed decryption after it, and the key buffer's size check.
fn derive_key_then_decrypt(data: &[u8], file_type: u32, core: Option<FileType>) {
    let Some(core) = core else {
        return;
    };

    let mut expected_decrypter = Decrypter::new();
    let derived = expected_decrypter.set_key_from_file(data, core).is_ok();

    let mut slot = MaybeUninit::<RpgmasdDecrypter>::uninit();
    // Heap buffers sized exactly, so ASan reports any write or read past their end.
    let mut key_out = vec![0 as c_char; RPGMASD_KEY_BUFFER_LENGTH];

    unsafe {
        assert_eq!(rpgmasd_decrypter_init(slot.as_mut_ptr()), RpgmasdStatus::Ok);
        let status = rpgmasd_decrypter_set_key_from_file(
            slot.as_mut_ptr(),
            data.as_ptr(),
            data.len(),
            file_type,
            key_out.as_mut_ptr(),
            key_out.len(),
        );
        assert_eq!(status == RpgmasdStatus::Ok, derived);
        if !derived {
            // A failed derivation leaves no key behind.
            assert_eq!(
                rpgmasd_decrypter_key(slot.as_ptr(), key_out.as_mut_ptr(), key_out.len()),
                RpgmasdStatus::KeyNotSet
            );
            return;
        }

        let key = CStr::from_ptr(key_out.as_ptr()).to_str().unwrap();
        assert_eq!(Some(key), expected_decrypter.key());

        // A buffer too small for the key and its NUL must be refused.
        let small_len = usize::from(data.first().copied().unwrap_or(0)) % RPGMASD_KEY_BUFFER_LENGTH;
        let mut small = vec![0 as c_char; small_len];
        assert_eq!(
            rpgmasd_decrypter_key(slot.as_ptr(), small.as_mut_ptr(), small.len()),
            RpgmasdStatus::BufferTooSmall
        );

        let mut copy = data.to_vec();
        let status = rpgmasd_decrypter_decrypt_in_place_keyed(slot.as_ptr(), copy.as_mut_ptr(), copy.len(), file_type);
        let mut scratch = data.to_vec();
        let expected = expected_decrypter
            .decrypt_in_place_keyed(&mut scratch, core)
            .map(<[u8]>::to_vec);
        assert_eq!(status == RpgmasdStatus::Ok, expected.is_ok());
        if let Ok(plain) = expected {
            assert!(copy[RPGMASD_HEADER_LENGTH..] == plain[..]);
        }
    }
}

// Encryption with a key taken from the input: its first 16 bytes as hex, so the key is always valid. The output buffer's
// capacity comes from the input too, so both the success and the `BufferTooSmall` paths run.
fn encrypt_with_key(data: &[u8], file_type: u32, core: Option<FileType>) {
    let Some(core) = core else {
        return;
    };
    if data.len() < 16 {
        return;
    }

    let key_hex: String = data[..16].iter().map(|byte| format!("{byte:02x}")).collect();
    let key = CString::new(key_hex.as_str()).unwrap();
    let plain = plain_for(file_type, &data[16..]);

    let mut reference = Decrypter::new();
    reference.set_key_from_str(&key_hex).unwrap();
    let encrypted = reference.encrypt(&plain, core).unwrap();

    let mut slot = MaybeUninit::<RpgmasdDecrypter>::uninit();
    let capacity = usize::from(data[0]) % (encrypted.len() + 1);
    let mut out = vec![0u8; capacity];
    let mut written = 0usize;

    unsafe {
        assert_eq!(rpgmasd_decrypter_init(slot.as_mut_ptr()), RpgmasdStatus::Ok);
        assert_eq!(
            rpgmasd_decrypter_set_key_from_str(slot.as_mut_ptr(), key.as_ptr()),
            RpgmasdStatus::Ok
        );

        let status = rpgmasd_decrypter_encrypt_into(
            slot.as_ptr(),
            plain.as_ptr(),
            plain.len(),
            file_type,
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        );
        assert_eq!(written, encrypted.len());
        if capacity == encrypted.len() {
            assert_eq!(status, RpgmasdStatus::Ok);
            assert!(out == encrypted, "encrypt_into disagrees with the safe API");
        } else {
            assert_eq!(status, RpgmasdStatus::BufferTooSmall);
        }

        let mut in_place = plain.clone();
        let status = rpgmasd_encrypt_asset_in_place(in_place.as_mut_ptr(), in_place.len(), file_type, key.as_ptr());
        assert_eq!(status, RpgmasdStatus::Ok);
        assert!(
            in_place == encrypted[RPGMASD_HEADER_LENGTH..],
            "encrypt_asset_in_place disagrees with the safe API"
        );
    }
}

fuzz_target!(|input: &[u8]| {
    // The first byte picks the operation, the second the file type. Raw values past M4A are out of range on purpose:
    // the ABI must reject them rather than misread them.
    let [operation, file_type, data @ ..] = input else {
        return;
    };
    let file_type = u32::from(file_type % 4);
    let core = core_file_type(file_type);

    match operation % 3 {
        0 => decrypt_in_place_whole(data, file_type, core),
        1 => derive_key_then_decrypt(data, file_type, core),
        _ => encrypt_with_key(data, file_type, core),
    }
});
