#![no_main]
use libfuzzer_sys::fuzz_target;
use rpgm_asset_decrypter_lib::Decrypter;

fuzz_target!(|input: &[u8]| {
    let Ok(key) = std::str::from_utf8(input) else {
        return;
    };

    let mut decrypter = Decrypter::new();
    if decrypter.set_key_from_str(key).is_ok() {
        assert!(decrypter.key() == Some(key));

        let mut data = *b"0123456789abcdefXYZ";
        decrypter.encrypt_in_place(&mut data).unwrap();
        decrypter.encrypt_in_place(&mut data).unwrap();
        assert!(&data == b"0123456789abcdefXYZ", "xor twice must be identity");
    }
});
