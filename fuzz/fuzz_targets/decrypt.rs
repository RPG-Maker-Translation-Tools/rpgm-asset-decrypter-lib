#![no_main]
use libfuzzer_sys::fuzz_target;
use rpgm_asset_decrypter_lib::{Decrypter, FileType, RPGM_HEADER};

/// Minimal M4A-typed files whose box position (and so the guessed header size) differs.
fn m4a_with_moov_at(chunk: usize) -> Vec<u8> {
    let mut file = RPGM_HEADER.to_vec();
    file.resize(80, 0);
    file[16 + chunk * 4..][..4].copy_from_slice(b"moov");
    file
}

fuzz_target!(|input: &[u8]| {
    // First byte picks the file type, the rest is the file.
    let Some((&selector, file)) = input.split_first() else {
        return;
    };
    let file_type = [FileType::PNG, FileType::OGG, FileType::M4A][selector as usize % 3];

    let first = Decrypter::new().decrypt(file, file_type);

    // Decrypting other files in between must not change the result: no state may leak between calls.
    let _ = Decrypter::new().decrypt(&m4a_with_moov_at(6), FileType::M4A);
    let second = Decrypter::new().decrypt(file, file_type);
    let _ = Decrypter::new().decrypt(&m4a_with_moov_at(9), FileType::M4A);
    let third = Decrypter::new().decrypt(file, file_type);
    assert!(
        first.is_ok() == second.is_ok() && first.is_ok() == third.is_ok(),
        "result kind depends on earlier calls"
    );

    let mut in_place = file.to_vec();
    let in_place_result = Decrypter::new().decrypt_in_place(&mut in_place, file_type).map(<[u8]>::to_vec);

    let (Ok(first), Ok(second), Ok(third), Ok(in_place_result)) = (first, second, third, in_place_result) else {
        return;
    };
    assert!(first == second && first == third, "output depends on earlier calls");
    assert!(first == in_place_result, "decrypt and decrypt_in_place disagree");

    // Encrypting with the key just derived must give the original file back.
    let mut decrypter = Decrypter::new();
    decrypter.decrypt(file, file_type).unwrap();
    assert!(decrypter.encrypt(&first).unwrap() == file, "encrypt(decrypt(file)) != file");
});
