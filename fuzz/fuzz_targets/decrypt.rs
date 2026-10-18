#![no_main]
use libfuzzer_sys::fuzz_target;
use rpgm_asset_decrypter_lib::{Decrypter, Error, FileType, HEADER_LENGTH, RPGM_HEADER};

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
    let file_type = [FileType::Png, FileType::Ogg, FileType::M4a][selector as usize % 3];

    let first = Decrypter::new().decrypt(file, file_type);

    // Decrypting other files in between must not change the result: no state may leak between calls.
    let _ = Decrypter::new().decrypt(&m4a_with_moov_at(6), FileType::M4a);
    let second = Decrypter::new().decrypt(file, file_type);
    let _ = Decrypter::new().decrypt(&m4a_with_moov_at(9), FileType::M4a);
    let third = Decrypter::new().decrypt(file, file_type);
    assert!(
        first.is_ok() == second.is_ok() && first.is_ok() == third.is_ok(),
        "result kind depends on earlier calls"
    );

    let mut in_place = file.to_vec();
    let in_place_result = Decrypter::new().decrypt_in_place(&mut in_place, file_type).map(<[u8]>::to_vec);

    // A failed decryption must leave the buffer alone.
    if in_place_result.is_err() {
        assert!(in_place == file, "failed decrypt_in_place modified the buffer");
    }

    // Reusing the decrypter on the same file must succeed, `decrypt_keyed` must agree, and the same file encrypted with
    // another key must be reported as a mismatch - never panic.
    if let Ok(plain) = &first {
        let mut reused = Decrypter::new();
        reused.decrypt(file, file_type).unwrap();
        assert!(reused.decrypt(file, file_type).as_ref() == Ok(plain), "reusing the key changed the result");
        assert!(reused.decrypt_keyed(file, file_type).as_ref() == Ok(plain), "decrypt_keyed disagrees");

        // The same file with its encrypted header flipped is encrypted with another key, whatever the rest of it holds.
        let mut other = file.to_vec();
        for byte in &mut other[HEADER_LENGTH..HEADER_LENGTH * 2] {
            *byte ^= 0x5a;
        }
        assert_eq!(reused.decrypt(&other, file_type), Err(Error::KeyMismatch));
        assert_eq!(reused.decrypt_keyed(&other, file_type), Err(Error::KeyMismatch));
    }

    let (Ok(first), Ok(second), Ok(third), Ok(in_place_result)) = (first, second, third, in_place_result) else {
        return;
    };
    assert!(first == second && first == third, "output depends on earlier calls");
    assert!(first == in_place_result, "decrypt and decrypt_in_place disagree");

    // Encrypting with the key just derived must give the original file back, unless the decrypted data is not a file of the
    // declared type (a key that was only derived, not verified, can produce anything for M4A).
    let mut decrypter = Decrypter::new();
    decrypter.decrypt(file, file_type).unwrap();
    if let Ok(encrypted) = decrypter.encrypt(&first, file_type) {
        assert!(encrypted == file, "encrypt(decrypt(file)) != file");
    }
});
