use rpgm_asset_decrypter_lib::{DEFAULT_KEY, Decrypter};
use std::fs::read;

fn is_valid_png(buf: &[u8]) -> bool {
    buf.starts_with(b"\x89PNG\r\n\x1a\n")
}

#[test]
fn decrypt_mv() {
    const TRACK_PATH: &str = "./tests/mv_sprite.rpgmvp";

    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    if !is_valid_png(&decrypted) {
        panic!("Decrypted data does not match the PNG header.")
    };
}

#[test]
fn encrypt_mv() {
    const TRACK_PATH: &str = "./tests/mv_sprite.rpgmvp";

    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    let encrypted = decrypter.encrypt(&decrypted).unwrap();
    let decrypted = decrypter.decrypt(&encrypted);

    if !is_valid_png(&decrypted) {
        panic!("Decrypted data does not match the PNG header.")
    };
}

#[test]
fn decrypt_mz() {
    const TRACK_PATH: &str = "./tests/mz_sprite.png_";

    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    if !is_valid_png(&decrypted) {
        panic!("Decrypted data does not match the PNG header.")
    };
}

#[test]
fn encrypt_mz() {
    const TRACK_PATH: &str = "./tests/mz_sprite.png_";

    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    let encrypted = decrypter.encrypt(&decrypted).unwrap();
    let decrypted = decrypter.decrypt(&encrypted);

    if !is_valid_png(&decrypted) {
        panic!("Decrypted data does not match the PNG header.")
    };
}
