use png::Decoder;
use rpgm_asset_decrypter_lib::{Decrypter, DEFAULT_KEY};
use std::fs::read;

fn is_valid_png(buf: &[u8]) {
    let decoder = Decoder::new(buf);
    let reader = decoder.read_info();

    reader.unwrap();
}

#[test]
fn decrypt_mv() {
    const TRACK_PATH: &str = "./tests/mv_sprite.rpgmvp";

    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    is_valid_png(&decrypted);
}

#[test]
fn encrypt_mv() {
    const TRACK_PATH: &str = "./tests/mv_sprite.rpgmvp";

    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    let encrypted = decrypter.encrypt(&decrypted).unwrap();
    let decrypted = decrypter.decrypt(&encrypted);

    is_valid_png(&decrypted);
}

#[test]
fn decrypt_mz() {
    const TRACK_PATH: &str = "./tests/mz_sprite.png_";

    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    is_valid_png(&decrypted);
}

#[test]
fn encrypt_mz() {
    const TRACK_PATH: &str = "./tests/mz_sprite.png_";

    let mut decrypter = Decrypter::new();
    decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    let encrypted = decrypter.encrypt(&decrypted).unwrap();
    let decrypted = decrypter.decrypt(&encrypted);

    is_valid_png(&decrypted);
}
