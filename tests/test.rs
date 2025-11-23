use rpgm_asset_decrypter_lib::{Decrypter, FileType, RPGM_HEADER};
use std::fs::read;

fn is_valid_ogg(buf: &[u8]) -> bool {
    buf.starts_with(b"OggS")
}

fn is_valid_m4a(buf: &[u8]) -> bool {
    &buf[4..12] == b"ftypM4A "
}

fn is_valid_png(buf: &[u8]) -> bool {
    buf.starts_with(b"\x89PNG\r\n\x1a\n")
}

struct TestCase<'a> {
    path: &'a str,
    file_type: FileType,
    validator: fn(&[u8]) -> bool,
}

const MV_OGG_DEFAULT: &str = "./tests/assets/mv/test-default.rpgmvo";
const MV_OGG_ABOBA: &str = "./tests/assets/mv/test-aboba.rpgmvo";
const MZ_OGG_DEFAULT: &str = "./tests/assets/mz/test-default.ogg_";
const MZ_OGG_ABOBA: &str = "./tests/assets/mz/test-aboba.ogg_";

const MZ_M4A_DEFAULT: &str = "./tests/assets/mz/test-default.m4a_";
const MZ_M4A_ABOBA: &str = "./tests/assets/mz/test-aboba.m4a_";

const MV_PNG_DEFAULT: &str = "./tests/assets/mv/test-default.rpgmvp";
const MV_PNG_ABOBA: &str = "./tests/assets/mv/test-aboba.rpgmvp";
const MZ_PNG_DEFAULT: &str = "./tests/assets/mz/test-default.png_";
const MZ_PNG_ABOBA: &str = "./tests/assets/mz/test-aboba.png_";

fn ogg_cases() -> Vec<TestCase<'static>> {
    vec![
        TestCase {
            path: MV_OGG_DEFAULT,
            file_type: FileType::OGG,
            validator: is_valid_ogg,
        },
        TestCase {
            path: MV_OGG_ABOBA,
            file_type: FileType::OGG,
            validator: is_valid_ogg,
        },
        TestCase {
            path: MZ_OGG_DEFAULT,
            file_type: FileType::OGG,
            validator: is_valid_ogg,
        },
        TestCase {
            path: MZ_OGG_ABOBA,
            file_type: FileType::OGG,
            validator: is_valid_ogg,
        },
    ]
}

fn m4a_cases() -> Vec<TestCase<'static>> {
    vec![
        TestCase {
            path: MZ_M4A_DEFAULT,
            file_type: FileType::M4A,
            validator: is_valid_m4a,
        },
        TestCase {
            path: MZ_M4A_ABOBA,
            file_type: FileType::M4A,
            validator: is_valid_m4a,
        },
    ]
}

fn png_cases() -> Vec<TestCase<'static>> {
    vec![
        TestCase {
            path: MV_PNG_DEFAULT,
            file_type: FileType::PNG,
            validator: is_valid_png,
        },
        TestCase {
            path: MV_PNG_ABOBA,
            file_type: FileType::PNG,
            validator: is_valid_png,
        },
        TestCase {
            path: MZ_PNG_DEFAULT,
            file_type: FileType::PNG,
            validator: is_valid_png,
        },
        TestCase {
            path: MZ_PNG_ABOBA,
            file_type: FileType::PNG,
            validator: is_valid_png,
        },
    ]
}

fn run_decrypt(case: &TestCase) {
    let mut d = Decrypter::new();
    let decrypted = d
        .decrypt(&read(case.path).unwrap(), case.file_type)
        .unwrap();
    assert!((case.validator)(&decrypted));
}

fn run_encrypt_roundtrip(case: &TestCase) {
    let mut d = Decrypter::new();
    let original = d
        .decrypt(&read(case.path).unwrap(), case.file_type)
        .unwrap();

    let encrypted = d.encrypt(&original).unwrap();
    let decrypted = d.decrypt(&encrypted, case.file_type).unwrap();

    assert!((case.validator)(&decrypted));
}

fn run_decrypt_in_place(case: &TestCase) {
    let mut d = Decrypter::new();
    let mut buf = read(case.path).unwrap();

    let buf_slice = d.decrypt_in_place(&mut buf, case.file_type).unwrap();

    assert!((case.validator)(buf_slice));
}

fn run_encrypt_in_place_roundtrip(case: &TestCase) {
    let mut d = Decrypter::new();

    let clean = d
        .decrypt(&read(case.path).unwrap(), case.file_type)
        .unwrap();
    let mut buf = clean.clone();

    d.encrypt_in_place(&mut buf).unwrap();
    buf.splice(0..0, RPGM_HEADER);

    let decrypted = d.decrypt(&buf, case.file_type).unwrap();
    assert!((case.validator)(&decrypted));
}

macro_rules! generate_tests {
    ($group:ident, $cases_fn:ident) => {
        mod $group {
            use super::*;

            #[test]
            fn decrypt() {
                for c in $cases_fn() {
                    run_decrypt(&c);
                }
            }

            #[test]
            fn encrypt_roundtrip() {
                for c in $cases_fn() {
                    run_encrypt_roundtrip(&c);
                }
            }

            #[test]
            fn decrypt_in_place() {
                for c in $cases_fn() {
                    run_decrypt_in_place(&c);
                }
            }

            #[test]
            fn encrypt_in_place_roundtrip() {
                for c in $cases_fn() {
                    run_encrypt_in_place_roundtrip(&c);
                }
            }
        }
    };
}

generate_tests!(ogg, ogg_cases);
generate_tests!(m4a, m4a_cases);
generate_tests!(png, png_cases);
