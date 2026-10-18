//! The C ABI and the Rust API must agree on every input, and both must match [`reference_payload`], which states the
//! format directly: the first 16 bytes of a payload are XORed with the key, and the rest is stored as it is.
use proptest::{collection::vec, prelude::*, sample::select, test_runner::Config as ProptestConfig};
use rpgm_asset_decrypter_lib::{FileType, HEADER_LENGTH, RPGM_HEADER, decrypt_in_place, encrypt_in_place};
use rpgmasd::{
    RPGMASD_FILE_TYPE_M4A, RPGMASD_FILE_TYPE_OGG, RPGMASD_FILE_TYPE_PNG, RpgmasdStatus, rpgmasd_decrypt_asset_in_place,
    rpgmasd_encrypt_asset_in_place,
};
use std::ffi::CString;

fn file_types() -> impl Strategy<Value = (u32, FileType)> {
    select(vec![
        (RPGMASD_FILE_TYPE_PNG, FileType::Png),
        (RPGMASD_FILE_TYPE_OGG, FileType::Ogg),
        (RPGMASD_FILE_TYPE_M4A, FileType::M4a),
    ])
}

fn key_hex(key: &[u8; 16]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

// The bytes every file of `file_type` starts with, followed by `body`.
fn with_magic(file_type: FileType, body: &[u8]) -> Vec<u8> {
    let magic: &[u8] = match file_type {
        FileType::Png => b"\x89PNG\r\n\x1a\n",
        FileType::Ogg => b"OggS",
        _ => b"\0\0\0\x1cftypM4A ",
    };
    [magic, body].concat()
}

// A PNG whose IHDR passes the checker (8-bit RGBA, not interlaced), followed by `tail`.
fn png(width: u32, height: u32, tail: &[u8]) -> Vec<u8> {
    let mut plain = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    plain.extend_from_slice(&width.to_be_bytes());
    plain.extend_from_slice(&height.to_be_bytes());
    plain.extend_from_slice(&[8, 6, 0, 0, 0]);
    plain.extend_from_slice(tail);
    plain
}

// The payload as the format describes it: the first 16 bytes XORed with the key, the rest unchanged.
fn reference_payload(payload: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let (head, tail) = payload.split_at(payload.len().min(16));
    let mut out: Vec<u8> = head.iter().zip(key).map(|(byte, key)| byte ^ key).collect();
    out.extend_from_slice(tail);
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(if cfg!(miri) { 4 } else { 256 }))]

    // Encrypting in place gives the same result through the C ABI and the Rust API, and both match the reference.
    #[test]
    fn encrypt_in_place_agrees_across_the_c_abi_and_the_rust_api(
        key in any::<[u8; 16]>(),
        (code, file_type) in file_types(),
        body in vec(any::<u8>(), 0..256),
    ) {
        let key_hex = key_hex(&key);
        let key_c = CString::new(key_hex.as_bytes()).unwrap();
        let plain = with_magic(file_type, &body);

        let mut rust = plain.clone();
        let rust_result = encrypt_in_place(&mut rust, file_type, &key_hex);

        let mut c = plain.clone();
        // SAFETY: `c` is readable and writable for `c.len()` bytes and nothing else touches it during the call;
        // `key_c` is a NUL-terminated string that lives past the call.
        let status = unsafe { rpgmasd_encrypt_asset_in_place(c.as_mut_ptr(), c.len(), code, key_c.as_ptr()) };

        match rust_result {
            Ok(()) => {
                prop_assert_eq!(status, RpgmasdStatus::Ok);
                prop_assert_eq!(&c, &reference_payload(&plain, &key));
                prop_assert_eq!(&c, &rust);
            }
            Err(_) => {
                prop_assert_ne!(status, RpgmasdStatus::Ok);
                prop_assert_eq!(&c, &plain);
            }
        }
    }

    // Arbitrary framed input is accepted by the C ABI exactly when the Rust API accepts it, and the bytes after the
    // header agree.
    #[test]
    fn decrypt_in_place_agrees_across_the_c_abi_and_the_rust_api(
        (code, file_type) in file_types(),
        body in vec(any::<u8>(), 0..512),
    ) {
        let input = [RPGM_HEADER, &body[..]].concat();

        let mut rust = input.clone();
        let rust_result = decrypt_in_place(&mut rust, file_type).map(<[u8]>::to_vec);

        let mut c = input.clone();
        // SAFETY: as in the encrypt test above, `c` is valid for its length and exclusively ours during the call.
        let status = unsafe { rpgmasd_decrypt_asset_in_place(c.as_mut_ptr(), c.len(), code) };

        match rust_result {
            Ok(_) => {
                prop_assert_eq!(status, RpgmasdStatus::Ok);
                prop_assert_eq!(&c[HEADER_LENGTH..], &rust[HEADER_LENGTH..]);
            }
            Err(_) => prop_assert_ne!(status, RpgmasdStatus::Ok),
        }
    }

    // A PNG encrypted with a known key decrypts back to the original through both APIs, and the key is derived from its
    // header, so no key is passed.
    #[test]
    fn encrypted_png_decrypts_to_the_original_through_both_apis(
        key in any::<[u8; 16]>(),
        width in any::<u32>(),
        height in any::<u32>(),
        tail in vec(any::<u8>(), 0..256),
    ) {
        let plain = png(width, height, &tail);
        let encrypted = [RPGM_HEADER, &reference_payload(&plain, &key)[..]].concat();

        let mut rust = encrypted.clone();
        prop_assert!(decrypt_in_place(&mut rust, FileType::Png).is_ok());
        prop_assert_eq!(&rust[HEADER_LENGTH..], &plain[..]);

        let mut c = encrypted.clone();
        // SAFETY: as in the tests above, `c` is valid for its length and exclusively ours during the call.
        let status = unsafe { rpgmasd_decrypt_asset_in_place(c.as_mut_ptr(), c.len(), RPGMASD_FILE_TYPE_PNG) };
        prop_assert_eq!(status, RpgmasdStatus::Ok);
        prop_assert_eq!(&c[HEADER_LENGTH..], &plain[..]);
    }
}
