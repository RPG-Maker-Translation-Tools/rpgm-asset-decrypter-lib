//! Run with `wasm-pack test --node wasm` (or `--headless --chrome` for a browser).
use rpgmasd_wasm::{Decrypter, FileType, decrypt_asset, default_key, encrypt_asset, file_type_from_extension};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

const PNG: &[u8] = include_bytes!("../../../tests/assets/mz/test-default.png_");
const PNG_OTHER_KEY: &[u8] = include_bytes!("../../../tests/assets/mz/test-aboba.png_");
const OGG: &[u8] = include_bytes!("../../../tests/assets/mz/test-aboba.ogg_");
const M4A: &[u8] = include_bytes!("../../../tests/assets/mz/test-default.m4a_");
const DEFAULT_KEY: &str = "d41d8cd98f00b204e9800998ecf8427e";

fn error_name(error: &JsValue) -> String {
    String::from(
        error
            .dyn_ref::<js_sys::Error>()
            .expect("thrown value is a JS Error")
            .name(),
    )
}

#[wasm_bindgen_test]
fn decrypt_derives_key_and_returns_png() {
    let mut decrypter = Decrypter::new();
    assert_eq!(decrypter.key(), None);

    let decrypted = decrypter.decrypt(PNG, FileType::Png).unwrap();
    assert_eq!(&decrypted[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(decrypter.key().as_deref(), Some(DEFAULT_KEY));
}

#[wasm_bindgen_test]
fn encrypt_includes_header_and_roundtrips() {
    let decrypted = decrypt_asset(PNG, FileType::Png).unwrap();
    assert_eq!(encrypt_asset(&decrypted, FileType::Png, DEFAULT_KEY).unwrap(), PNG);

    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
    assert_eq!(decrypter.encrypt(&decrypted, FileType::Png).unwrap(), PNG);
}

#[wasm_bindgen_test]
fn decrypt_keyed_needs_a_key() {
    let mut decrypter = Decrypter::new();
    let error = decrypter.decrypt_keyed(PNG, FileType::Png).unwrap_err();
    assert_eq!(error_name(&error), "KeyNotSet");

    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
    let decrypted = decrypter.decrypt_keyed(PNG, FileType::Png).unwrap();
    assert_eq!(&decrypted[..8], b"\x89PNG\r\n\x1a\n");
}

#[wasm_bindgen_test]
fn default_key_is_exported() {
    assert_eq!(default_key(), DEFAULT_KEY);
}

#[wasm_bindgen_test]
fn ogg_and_m4a_keys_are_derived() {
    let mut decrypter = Decrypter::new();
    let key = decrypter.set_key_from_file(OGG, FileType::Ogg).unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(decrypter.key(), Some(key));

    let decrypted = decrypt_asset(M4A, FileType::M4a).unwrap();
    assert_eq!(&decrypted[4..8], b"ftyp");
}

#[wasm_bindgen_test]
fn a_bad_key_string_is_a_js_error_and_keeps_the_previous_key() {
    let mut decrypter = Decrypter::default();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();

    let error = decrypter.set_key_from_str("abc").unwrap_err();
    assert_eq!(error_name(&error), "InvalidKeyLength");

    let error = decrypter
        .set_key_from_str("z41d8cd98f00b204e9800998ecf8427e")
        .unwrap_err();
    assert_eq!(error_name(&error), "InvalidKey");

    assert_eq!(decrypter.key().as_deref(), Some(DEFAULT_KEY));
}

#[wasm_bindgen_test]
fn keys_are_lowercase() {
    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(&DEFAULT_KEY.to_uppercase()).unwrap();
    assert_eq!(decrypter.key().as_deref(), Some(DEFAULT_KEY));
}

#[wasm_bindgen_test]
fn file_types_come_from_extensions() {
    assert!(file_type_from_extension("rpgmvp").unwrap() == FileType::Png);
    assert!(file_type_from_extension(".OGG_").unwrap() == FileType::Ogg);
    assert!(file_type_from_extension("m4a_").unwrap() == FileType::M4a);

    let error = file_type_from_extension("txt").err().unwrap();
    assert_eq!(error_name(&error), "UnsupportedExtension");
}

#[wasm_bindgen_test]
fn errors_are_js_errors_named_after_the_variant() {
    let mut decrypter = Decrypter::new();

    let error = decrypter.decrypt(b"not an rpg maker file", FileType::Png).unwrap_err();
    assert_eq!(error_name(&error), "InvalidHeader");

    let error = decrypter.set_key_from_str("short").unwrap_err();
    assert_eq!(error_name(&error), "InvalidKeyLength");

    let error = decrypter
        .set_key_from_str("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
        .unwrap_err();
    assert_eq!(error_name(&error), "InvalidKey");

    let error = decrypter.encrypt(b"data", FileType::Png).unwrap_err();
    assert_eq!(error_name(&error), "KeyNotSet");

    let error = decrypter.decrypt(&PNG[..20], FileType::Png).unwrap_err();
    assert_eq!(error_name(&error), "UnexpectedEOF");

    // Zeros after a valid header aren't an OGG.
    let mut garbage = PNG[..16].to_vec();
    garbage.resize(300, 0);
    let error = decrypter.decrypt(&garbage, FileType::Ogg).unwrap_err();
    assert_eq!(error_name(&error), "InvalidContent");
}

#[wasm_bindgen_test]
fn reusing_a_key_for_another_project_is_a_mismatch() {
    let mut decrypter = Decrypter::new();
    decrypter.decrypt(PNG, FileType::Png).unwrap();

    let error = decrypter.decrypt(PNG_OTHER_KEY, FileType::Png).unwrap_err();
    assert_eq!(error_name(&error), "KeyMismatch");
}

#[wasm_bindgen_test]
fn encrypt_rejects_the_wrong_file_type() {
    let decrypted = decrypt_asset(PNG, FileType::Png).unwrap();

    let error = encrypt_asset(&decrypted, FileType::Ogg, DEFAULT_KEY).unwrap_err();
    assert_eq!(error_name(&error), "InvalidContent");
}
