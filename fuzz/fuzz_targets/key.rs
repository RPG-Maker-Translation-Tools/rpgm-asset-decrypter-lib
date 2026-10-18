#![no_main]
use libfuzzer_sys::fuzz_target;
use rpgm_asset_decrypter_lib::{Decrypter, FileType};

// Each file type with the bytes its files start with.
const TYPES: [(FileType, &[u8]); 3] = [
    (FileType::Png, b"\x89PNG\r\n\x1a\n"),
    (FileType::Ogg, b"OggS"),
    (FileType::M4a, b"\0\0\0\x1cftypM4A "),
];

// Whatever the key is, a file of every type encrypted with it must decrypt back to the original.
fn assert_round_trip(decrypter: &Decrypter, body: &[u8]) {
    for (file_type, magic) in TYPES {
        let plain = [magic, body].concat();
        let encrypted = decrypter.encrypt(&plain, file_type).unwrap();
        assert!(decrypter.decrypt_keyed(&encrypted, file_type).unwrap() == plain);
    }
}

fuzz_target!(|input: &[u8]| {
    // Any UTF-8 input as a key string: accepted only as 32 hex digits, and stored in lowercase.
    if let Ok(key) = std::str::from_utf8(input) {
        let mut decrypter = Decrypter::new();
        if decrypter.set_key_from_str(key).is_ok() {
            let stored = decrypter.key().unwrap();
            assert!(stored.eq_ignore_ascii_case(key) && stored.bytes().all(|byte| !byte.is_ascii_uppercase()));
            assert_round_trip(&decrypter, input);
        }
    }

    // Any 16 bytes are a valid key once hex-encoded.
    if input.len() >= 16 {
        let (key, body) = input.split_at(16);
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();

        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(&hex).unwrap();
        assert_eq!(decrypter.key(), Some(hex.as_str()));
        assert_round_trip(&decrypter, body);
    }
});
