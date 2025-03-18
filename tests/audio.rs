use rpgm_asset_decrypter_lib::Decrypter;
use std::fs::read;

const OGG_SIGNATURE: &str = "OggS";

#[test]
fn decrypt_mv() {
    const TRACK_PATH: &str = "./tests/mv_audio.rpgmvo";

    let mut decrypter = Decrypter::new(Some(String::from("d41d8cd98f00b204e9800998ecf8427e")));
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    let signature = std::str::from_utf8(&decrypted[0..4]).unwrap();
    assert!(signature == OGG_SIGNATURE);
}

#[test]
fn encrypt_mv() {
    const TRACK_PATH: &str = "./tests/mv_audio.rpgmvo";

    let mut decrypter = Decrypter::new(Some(String::from("d41d8cd98f00b204e9800998ecf8427e")));
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    let encrypted = decrypter.encrypt(&decrypted);
    let decrypted = decrypter.decrypt(&encrypted);

    let signature = std::str::from_utf8(&decrypted[0..4]).unwrap();
    assert!(signature == OGG_SIGNATURE);
}

#[test]
fn decrypt_mz() {
    const TRACK_PATH: &str = "./tests/mz_audio.ogg_";

    let mut decrypter = Decrypter::new(Some(String::from("d41d8cd98f00b204e9800998ecf8427e")));
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    let signature = std::str::from_utf8(&decrypted[0..4]).unwrap();
    assert!(signature == OGG_SIGNATURE);
}

#[test]
fn encrypt_mz() {
    const TRACK_PATH: &str = "./tests/mz_audio.ogg_";

    let mut decrypter = Decrypter::new(Some(String::from("d41d8cd98f00b204e9800998ecf8427e")));
    let decrypted = decrypter.decrypt(&read(TRACK_PATH).unwrap());

    let encrypted = decrypter.encrypt(&decrypted);
    let decrypted = decrypter.decrypt(&encrypted);

    let signature = std::str::from_utf8(&decrypted[0..4]).unwrap();
    assert!(signature == OGG_SIGNATURE);
}
