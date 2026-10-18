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
            file_type: FileType::Ogg,
            validator: is_valid_ogg,
        },
        TestCase {
            path: MV_OGG_ABOBA,
            file_type: FileType::Ogg,
            validator: is_valid_ogg,
        },
        TestCase {
            path: MZ_OGG_DEFAULT,
            file_type: FileType::Ogg,
            validator: is_valid_ogg,
        },
        TestCase {
            path: MZ_OGG_ABOBA,
            file_type: FileType::Ogg,
            validator: is_valid_ogg,
        },
    ]
}

fn m4a_cases() -> Vec<TestCase<'static>> {
    vec![
        TestCase {
            path: MZ_M4A_DEFAULT,
            file_type: FileType::M4a,
            validator: is_valid_m4a,
        },
        TestCase {
            path: MZ_M4A_ABOBA,
            file_type: FileType::M4a,
            validator: is_valid_m4a,
        },
    ]
}

fn png_cases() -> Vec<TestCase<'static>> {
    vec![
        TestCase {
            path: MV_PNG_DEFAULT,
            file_type: FileType::Png,
            validator: is_valid_png,
        },
        TestCase {
            path: MV_PNG_ABOBA,
            file_type: FileType::Png,
            validator: is_valid_png,
        },
        TestCase {
            path: MZ_PNG_DEFAULT,
            file_type: FileType::Png,
            validator: is_valid_png,
        },
        TestCase {
            path: MZ_PNG_ABOBA,
            file_type: FileType::Png,
            validator: is_valid_png,
        },
    ]
}

#[cfg(feature = "alloc")]
fn run_decrypt(case: &TestCase) {
    let mut d = Decrypter::new();
    let decrypted = d.decrypt(&read(case.path).unwrap(), case.file_type).unwrap();
    assert!((case.validator)(&decrypted));
}

#[cfg(feature = "alloc")]
fn run_encrypt_roundtrip(case: &TestCase) {
    let mut d = Decrypter::new();
    let original = d.decrypt(&read(case.path).unwrap(), case.file_type).unwrap();

    let encrypted = d.encrypt(&original, case.file_type).unwrap();
    let decrypted = d.decrypt(&encrypted, case.file_type).unwrap();

    assert!((case.validator)(&decrypted));
}

fn run_decrypt_in_place(case: &TestCase) {
    let mut d = Decrypter::new();
    let mut buf = read(case.path).unwrap();

    let buf_slice = d.decrypt_in_place(&mut buf, case.file_type).unwrap();

    assert!((case.validator)(buf_slice));
}

#[cfg(feature = "alloc")]
fn run_encrypt_in_place_roundtrip(case: &TestCase) {
    let mut d = Decrypter::new();

    let clean = d.decrypt(&read(case.path).unwrap(), case.file_type).unwrap();
    let mut buf = clean.clone();

    d.encrypt_in_place(&mut buf, case.file_type).unwrap();
    buf.splice(0..0, RPGM_HEADER.to_owned());

    let decrypted = d.decrypt(&buf, case.file_type).unwrap();
    assert!((case.validator)(&decrypted));
}

macro_rules! generate_tests {
    ($group:ident, $cases_fn:ident) => {
        mod $group {
            use super::*;

            #[cfg(feature = "alloc")]
            #[test]
            fn decrypt() {
                for c in $cases_fn() {
                    run_decrypt(&c);
                }
            }

            #[cfg(feature = "alloc")]
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

            #[cfg(feature = "alloc")]
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

// Regression tests for bugs found by fuzzing (see `fuzz/`).
mod malformed {
    use super::*;
    use rpgm_asset_decrypter_lib::Error;

    // Used to panic in `u8::from_str_radix(..).unwrap()`.
    #[test]
    fn non_hex_key_is_rejected() {
        let mut decrypter = Decrypter::new();
        assert!(matches!(
            decrypter.set_key_from_str(&"z".repeat(32)),
            Err(Error::InvalidKey)
        ));
        // `from_str_radix` would have accepted the sign.
        assert!(matches!(
            decrypter.set_key_from_str(&"+f".repeat(16)),
            Err(Error::InvalidKey)
        ));
        assert!(decrypter.key().is_none());
    }

    // Used to panic on slicing past the end of the file.
    #[cfg(feature = "alloc")]
    #[test]
    fn truncated_ogg_is_an_error() {
        let mut file = RPGM_HEADER.to_vec();
        for len in 0..400 {
            file.resize(len.max(RPGM_HEADER.len()), 0);
            assert!(Decrypter::new().decrypt(&file, FileType::Ogg).is_err(), "len {len}");
        }
    }

    // Used to underflow `i - 1` when a box name sat in the first chunk. That name is not a box, so the file is rejected.
    #[cfg(feature = "alloc")]
    #[test]
    fn m4a_box_in_first_chunk() {
        let mut file = RPGM_HEADER.to_vec();
        file.extend_from_slice(b"moov");
        file.resize(80, 0);
        assert_eq!(
            Decrypter::new().decrypt(&file, FileType::M4a),
            Err(Error::InvalidContent)
        );
    }

    // The M4A type box size used to live in a `static mut`, so it leaked from one file into the next.
    #[cfg(feature = "alloc")]
    #[test]
    fn m4a_decryption_is_independent_of_earlier_files() {
        // A box of size 8 named `moov`, starting at original offset `start`.
        let with_box_at = |start: usize| {
            let mut file = RPGM_HEADER.to_vec();
            file.resize(80, 0);
            file[16 + start..][..8].copy_from_slice(&[0, 0, 0, 8, b'm', b'o', b'o', b'v']);
            file
        };

        let alone = Decrypter::new().decrypt(&with_box_at(28), FileType::M4a).unwrap();
        Decrypter::new().decrypt(&with_box_at(40), FileType::M4a).unwrap();
        assert_eq!(
            Decrypter::new().decrypt(&with_box_at(28), FileType::M4a).unwrap(),
            alone
        );
    }
}

mod api {
    use super::*;
    #[cfg(feature = "alloc")]
    use rpgm_asset_decrypter_lib::Error;

    #[test]
    fn extensions_are_case_insensitive() {
        assert_eq!(FileType::try_from("RPGMVP"), Ok(FileType::Png));
        assert_eq!(FileType::try_from("Ogg_"), Ok(FileType::Ogg));
        assert!(FileType::try_from("png").is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn extensions_from_os_strings_are_case_insensitive() {
        assert_eq!(FileType::try_from(std::ffi::OsStr::new("M4A_")), Ok(FileType::M4a));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn small_m4a_is_decryptable() {
        // 16 header + 28 bytes up to the box after the type box + that 8-byte `free` box: shorter than the old 80 bytes.
        let mut file = RPGM_HEADER.to_vec();
        file.resize(44, 0);
        file.extend_from_slice(&[0, 0, 0, 8, b'f', b'r', b'e', b'e']);
        assert!(Decrypter::new().decrypt(&file, FileType::M4a).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn encrypt_prepends_header_and_roundtrips() {
        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str("d41d8cd98f00b204e9800998ecf8427e").unwrap();

        let mut plain: Vec<u8> = (0..100).collect();
        plain[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        let encrypted = decrypter.encrypt(&plain, FileType::Png).unwrap();
        assert_eq!(&encrypted[..16], RPGM_HEADER);
        assert_eq!(encrypted.len(), 116);
        assert_eq!(&encrypted[32..], &plain[16..]);
        assert_eq!(decrypter.decrypt(&encrypted, FileType::Png).unwrap(), plain);
        assert_eq!(Decrypter::new().encrypt(&plain, FileType::Png), Err(Error::KeyNotSet));
    }
}

#[cfg(feature = "alloc")]
mod key_reuse {
    use super::*;
    use rpgm_asset_decrypter_lib::Error;

    fn read_asset(name: &str) -> Vec<u8> {
        read(format!("./tests/assets/mz/{name}")).unwrap()
    }

    #[test]
    fn same_key_is_reused() {
        let mut decrypter = Decrypter::new();
        decrypter
            .decrypt(&read_asset("test-default.png_"), FileType::Png)
            .unwrap();
        assert!(
            decrypter
                .decrypt(&read_asset("test-default.png_"), FileType::Png)
                .is_ok()
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn other_key_is_rejected_for_every_file_type() {
        for (name, file_type) in [
            ("png_", FileType::Png),
            ("ogg_", FileType::Ogg),
            ("m4a_", FileType::M4a),
        ] {
            let mut decrypter = Decrypter::new();
            decrypter
                .decrypt(&read_asset(&format!("test-default.{name}")), file_type)
                .unwrap();

            let other = read_asset(&format!("test-aboba.{name}"));
            assert_eq!(decrypter.decrypt(&other, file_type), Err(Error::KeyMismatch), "{name}");

            let mut in_place = other.clone();
            assert_eq!(
                decrypter.decrypt_in_place(&mut in_place, file_type),
                Err(Error::KeyMismatch),
                "{name}"
            );
            // A rejected file must stay untouched.
            assert_eq!(in_place, other, "{name}");
        }
    }
}

mod derivation {
    use super::*;
    use rpgm_asset_decrypter_lib::{DEFAULT_KEY, Error, decrypt_in_place, encrypt_in_place};
    #[cfg(feature = "alloc")]
    use rpgm_asset_decrypter_lib::{decrypt, encrypt};

    #[cfg(feature = "alloc")]
    fn asset(name: &str) -> Vec<u8> {
        read(format!("./tests/assets/mz/{name}")).unwrap()
    }

    // An M4A whose type box is `ftyp_size` bytes long and is followed by named boxes at the given original offsets.
    fn m4a(ftyp_size: u32, boxes: &[(usize, u32, &[u8; 4])]) -> Vec<u8> {
        let mut plain = vec![0u8; 400];
        plain[..4].copy_from_slice(&ftyp_size.to_be_bytes());
        plain[4..12].copy_from_slice(b"ftypM4A ");
        for &(offset, size, name) in boxes {
            plain[offset..offset + 4].copy_from_slice(&size.to_be_bytes());
            plain[offset + 4..offset + 8].copy_from_slice(name);
        }
        plain
    }

    // The size of the type box as the decrypter finds it, or the error it reports.
    fn guessed_ftyp_size(plain: &[u8]) -> Result<u32, Error> {
        let mut buffer = plain.to_vec();
        encrypt_in_place(&mut buffer, FileType::M4a, DEFAULT_KEY).unwrap();
        buffer.splice(0..0, RPGM_HEADER.to_owned());
        let decrypted = decrypt_in_place(&mut buffer, FileType::M4a)?;
        Ok(u32::from_be_bytes(decrypted[..4].try_into().unwrap()))
    }

    #[test]
    fn m4a_type_box_size_is_found_for_any_size() {
        assert_eq!(guessed_ftyp_size(&m4a(28, &[(28, 100, b"moov")])), Ok(28));
        assert_eq!(guessed_ftyp_size(&m4a(32, &[(32, 100, b"mdat")])), Ok(32));
        // Long compatible brand lists used to push the next box out of the search window.
        assert_eq!(guessed_ftyp_size(&m4a(60, &[(60, 100, b"moov")])), Ok(60));
        assert_eq!(guessed_ftyp_size(&m4a(64, &[(64, 100, b"free")])), Ok(64));
        assert_eq!(guessed_ftyp_size(&m4a(72, &[(72, 100, b"moov")])), Ok(72));
        assert_eq!(guessed_ftyp_size(&m4a(200, &[(200, 100, b"moov")])), Ok(200));
    }

    #[test]
    fn m4a_box_names_inside_other_boxes_are_ignored() {
        // `free` inside the payload of an unlisted `meta` box has no plausible size in front of it.
        let plain = m4a(28, &[(28, 100, b"meta"), (52, 0, b"free")]);
        assert_eq!(guessed_ftyp_size(&plain), Err(Error::InvalidContent));
        // A size that doesn't fit into the file is not a box.
        let plain = m4a(48, &[(40, 0xffff_ffff, b"moov"), (48, 100, b"mdat")]);
        assert_eq!(guessed_ftyp_size(&plain), Ok(48));
        // No recognized box at all: rejected, since a guessed size would give a wrong key.
        assert_eq!(
            guessed_ftyp_size(&m4a(40, &[(40, 100, b"uuid")])),
            Err(Error::InvalidContent)
        );
    }

    #[test]
    fn m4a_box_size_limit_is_inclusive() {
        // A box may end exactly at the end of the file, but not past it.
        assert_eq!(guessed_ftyp_size(&m4a(100, &[(100, 300, b"moov")])), Ok(100));
        assert_eq!(
            guessed_ftyp_size(&m4a(100, &[(100, 301, b"moov")])),
            Err(Error::InvalidContent)
        );
    }

    #[test]
    fn m4a_box_at_the_edge_of_the_search_window() {
        // The search covers 256 bytes from original offset 16, so the last box header that fits starts at 264.
        assert_eq!(guessed_ftyp_size(&m4a(28, &[(264, 136, b"moov")])), Ok(264));
        assert_eq!(
            guessed_ftyp_size(&m4a(28, &[(268, 132, b"moov")])),
            Err(Error::InvalidContent)
        );
    }

    // The key derived from an M4A is wrong when its brand (bytes 8..12) isn't `M4A `. It must not be used for a PNG.
    #[cfg(feature = "alloc")]
    #[test]
    fn m4a_key_is_not_reused_for_other_types() {
        let mut real = Decrypter::new();
        real.set_key_from_str(DEFAULT_KEY).unwrap();

        let mut m4a_plain = m4a(28, &[(28, 100, b"moov")]);
        m4a_plain[8..12].copy_from_slice(b"isom");
        let m4a_file = real.encrypt(&m4a_plain, FileType::M4a).unwrap();

        let mut png_plain = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        png_plain.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0]);
        png_plain.extend_from_slice(&[0; 20]);
        let png_file = real.encrypt(&png_plain, FileType::Png).unwrap();

        let mut decrypter = Decrypter::new();
        decrypter.decrypt(&m4a_file, FileType::M4a).unwrap();
        // The M4A key can't vouch for a PNG, so the keyed method refuses the file.
        assert_eq!(
            decrypter.decrypt_keyed(&png_file, FileType::Png),
            Err(Error::KeyMismatch)
        );
        // The mutable method derives the PNG's own key, which decrypts it exactly.
        assert_eq!(decrypter.decrypt(&png_file, FileType::Png).unwrap(), png_plain);
        assert_eq!(decrypter.key(), Some(DEFAULT_KEY));
    }

    #[test]
    fn garbage_does_not_derive_a_key() {
        let mut file = RPGM_HEADER.to_vec();
        file.resize(300, 0);

        for file_type in [FileType::Png, FileType::Ogg] {
            let mut decrypter = Decrypter::new();
            assert_eq!(
                decrypter.set_key_from_file(&file, file_type),
                Err(Error::InvalidContent),
                "{file_type}"
            );
            assert_eq!(decrypter.key(), None);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn short_png_is_an_error() {
        let mut file = RPGM_HEADER.to_vec();
        file.resize(40, 0);
        assert_eq!(
            Decrypter::new().decrypt(&file, FileType::Png),
            Err(Error::UnexpectedEOF)
        );
    }

    #[test]
    fn failed_key_derivation_keeps_the_previous_key() {
        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(DEFAULT_KEY).unwrap();

        let mut garbage = RPGM_HEADER.to_vec();
        garbage.resize(300, 0);
        assert!(decrypter.set_key_from_file(&garbage, FileType::Png).is_err());
        assert!(decrypter.set_key_from_file(b"nope", FileType::Png).is_err());
        assert_eq!(decrypter.key(), Some(DEFAULT_KEY));
    }

    #[test]
    fn key_is_always_lowercase() {
        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(&DEFAULT_KEY.to_uppercase()).unwrap();
        assert_eq!(decrypter.key(), Some(DEFAULT_KEY));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn header_only_file_is_an_error() {
        assert_eq!(
            Decrypter::new().decrypt(RPGM_HEADER, FileType::Png),
            Err(Error::UnexpectedEOF)
        );

        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
        assert_eq!(decrypter.decrypt(RPGM_HEADER, FileType::Png), Err(Error::UnexpectedEOF));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn free_functions_roundtrip() {
        let original = asset("test-default.png_");
        let decrypted = decrypt(&original, FileType::Png).unwrap();
        assert_eq!(&decrypted[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(encrypt(&decrypted, FileType::Png, DEFAULT_KEY).unwrap(), original);

        let mut buf = original.clone();
        assert_eq!(decrypt_in_place(&mut buf, FileType::Png).unwrap(), decrypted);

        let mut payload = decrypted.clone();
        encrypt_in_place(&mut payload, FileType::Png, DEFAULT_KEY).unwrap();
        assert_eq!(payload, original[16..]);

        assert_eq!(
            encrypt(&decrypted, FileType::Png, "short"),
            Err(Error::InvalidKeyLength)
        );
        assert_eq!(
            encrypt_in_place(&mut payload, FileType::Png, &"z".repeat(32)),
            Err(Error::InvalidKey)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn encrypt_checks_the_file_type() {
        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(DEFAULT_KEY).unwrap();

        let png = decrypt(&asset("test-default.png_"), FileType::Png).unwrap();
        assert_eq!(decrypter.encrypt(&png, FileType::Ogg), Err(Error::InvalidContent));
        assert_eq!(decrypter.encrypt(&png[..4], FileType::Png), Err(Error::UnexpectedEOF));

        let mut buf = png.clone();
        assert_eq!(
            decrypter.encrypt_in_place(&mut buf, FileType::M4a),
            Err(Error::InvalidContent)
        );
        assert_eq!(buf, png, "a rejected buffer must stay untouched");
        assert!(decrypter.encrypt_in_place(&mut buf, FileType::Png).is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn keyed_methods_share_a_decrypter() {
        let original = asset("test-aboba.png_");

        let mut decrypter = Decrypter::new();
        assert_eq!(decrypter.decrypt_keyed(&original, FileType::Png), Err(Error::KeyNotSet));
        let expected = decrypter.decrypt(&original, FileType::Png).unwrap();

        // The key is known now, so the decrypter can be shared between threads.
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    assert_eq!(decrypter.decrypt_keyed(&original, FileType::Png).unwrap(), expected);

                    let mut buf = original.clone();
                    assert_eq!(
                        decrypter.decrypt_in_place_keyed(&mut buf, FileType::Png).unwrap(),
                        expected
                    );
                });
            }
        });

        let mut clone = decrypter.clone();
        assert_eq!(clone.key(), decrypter.key());
        assert_eq!(
            clone.decrypt(&asset("test-default.png_"), FileType::Png),
            Err(Error::KeyMismatch)
        );
        assert_eq!(
            decrypter.decrypt_keyed(&asset("test-default.png_"), FileType::Png),
            Err(Error::KeyMismatch)
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn file_type_from_os_str() {
        use std::ffi::OsStr;

        assert_eq!(FileType::try_from(OsStr::new("OGG_")), Ok(FileType::Ogg));
    }

    #[test]
    fn file_type_helpers() {
        assert_eq!("rpgmvm".parse(), Ok(FileType::M4a));
        assert_eq!("txt".parse::<FileType>(), Err(Error::UnsupportedExtension));

        for file_type in [FileType::Png, FileType::Ogg, FileType::M4a] {
            assert_eq!(file_type.to_string(), file_type.decrypted_extension());
            assert_eq!(file_type.encrypted_extension(true).parse(), Ok(file_type));
            assert_eq!(file_type.encrypted_extension(false).parse(), Ok(file_type));
        }
        assert_eq!(FileType::Png.encrypted_extension(false), "rpgmvp");
        assert_eq!(FileType::Ogg.encrypted_extension(true), "ogg_");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn errors_roundtrip_through_serde() {
        for error in [Error::KeyMismatch, Error::InvalidContent, Error::UnexpectedEOF] {
            let json = serde_json::to_string(&error).unwrap();
            assert_eq!(serde_json::from_str::<Error>(&json).unwrap(), error);
        }
    }
}

mod validation {
    use super::*;
    #[cfg(feature = "alloc")]
    use rpgm_asset_decrypter_lib::DEFAULT_KEY;
    use rpgm_asset_decrypter_lib::{DECRYPTED_ASSET_EXTS, ENCRYPTED_ASSET_EXTS, Error};

    // Offset of the second Ogg page: the first page's header, segment table and body come before it.
    fn second_ogg_page(file: &[u8]) -> usize {
        let segments = &file[16 + 27..][..usize::from(file[16 + 26])];
        16 + 27 + segments.len() + segments.iter().map(|&len| usize::from(len)).sum::<usize>()
    }

    // The PNG fixture with its IHDR fields (bit depth, color type, compression, filter, interlace) replaced.
    #[cfg(feature = "alloc")]
    fn png_with_ihdr(ihdr: [u8; 5]) -> Vec<u8> {
        let mut plain = Decrypter::new()
            .decrypt(&read(MZ_PNG_DEFAULT).unwrap(), FileType::Png)
            .unwrap();
        plain[24..29].copy_from_slice(&ihdr);

        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
        decrypter.encrypt(&plain, FileType::Png).unwrap()
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn invalid_header_is_reported_by_every_entry_point() {
        let file = vec![0u8; 300];
        assert_eq!(Decrypter::new().decrypt(&[], FileType::Png), Err(Error::InvalidHeader));

        for file_type in [FileType::Png, FileType::Ogg, FileType::M4a] {
            assert_eq!(
                Decrypter::new().decrypt(&file, file_type),
                Err(Error::InvalidHeader),
                "{file_type}"
            );
            assert_eq!(
                Decrypter::new().set_key_from_file(&file, file_type),
                Err(Error::InvalidHeader),
                "{file_type}"
            );

            let mut buffer = file.clone();
            assert_eq!(
                Decrypter::new().decrypt_in_place(&mut buffer, file_type),
                Err(Error::InvalidHeader),
                "{file_type}"
            );
            assert_eq!(buffer, file);
        }

        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
        assert_eq!(decrypter.decrypt_keyed(&file, FileType::Png), Err(Error::InvalidHeader));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn png_ihdr_fields_are_checked() {
        let original = read(MZ_PNG_DEFAULT).unwrap();
        let plain = Decrypter::new().decrypt(&original, FileType::Png).unwrap();
        let valid: [u8; 5] = plain[24..29].try_into().unwrap();
        assert_eq!(
            Decrypter::new().set_key_from_file(&original, FileType::Png),
            Ok(DEFAULT_KEY)
        );
        assert_eq!(
            Decrypter::new().set_key_from_file(&png_with_ihdr(valid), FileType::Png),
            Ok(DEFAULT_KEY)
        );

        // One invalid value per field: bit depth, color type, compression method, filter method, interlace method.
        for (field, value) in [(0, 0), (1, 1), (2, 1), (3, 1), (4, 2)] {
            let mut ihdr = valid;
            ihdr[field] = value;
            assert_eq!(
                Decrypter::new().set_key_from_file(&png_with_ihdr(ihdr), FileType::Png),
                Err(Error::InvalidContent),
                "field {field}"
            );
        }
    }

    #[test]
    fn ogg_second_page_must_start_with_oggs() {
        let mut file = read(MZ_OGG_DEFAULT).unwrap();
        let second = second_ogg_page(&file);
        assert_eq!(&file[second..][..4], b"OggS");

        file[second] = b'X';
        assert_eq!(
            Decrypter::new().set_key_from_file(&file, FileType::Ogg),
            Err(Error::InvalidContent)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn truncated_ogg_before_its_second_header_is_unexpected_eof() {
        let file = read(MZ_OGG_DEFAULT).unwrap();
        let second = second_ogg_page(&file);
        let header_end = second + 27 + usize::from(file[second + 26]);

        for len in 16..header_end {
            assert_eq!(
                Decrypter::new().decrypt(&file[..len], FileType::Ogg),
                Err(Error::UnexpectedEOF),
                "len {len}"
            );
        }
        assert!(Decrypter::new().decrypt(&file[..header_end], FileType::Ogg).is_ok());
    }

    #[test]
    fn file_type_predicates_and_extension_tables() {
        assert!(FileType::Png.is_png() && !FileType::Png.is_ogg() && !FileType::Png.is_m4a());
        assert!(!FileType::Ogg.is_png() && FileType::Ogg.is_ogg() && !FileType::Ogg.is_m4a());
        assert!(!FileType::M4a.is_png() && !FileType::M4a.is_ogg() && FileType::M4a.is_m4a());

        assert_eq!(ENCRYPTED_ASSET_EXTS.len(), 6);
        assert_eq!(DECRYPTED_ASSET_EXTS.len(), 3);
        for file_type in [FileType::Png, FileType::Ogg, FileType::M4a] {
            assert!(ENCRYPTED_ASSET_EXTS.contains(&file_type.encrypted_extension(true)));
            assert!(ENCRYPTED_ASSET_EXTS.contains(&file_type.encrypted_extension(false)));
            assert!(DECRYPTED_ASSET_EXTS.contains(&file_type.decrypted_extension()));
        }
    }

    #[test]
    fn check_plain_looks_at_the_magic_bytes() {
        assert_eq!(FileType::Png.check_plain(b"\x89PNG\r\n\x1a\n"), Ok(()));
        assert_eq!(FileType::Png.check_plain(b"\x89PNG\r\n\x1a"), Err(Error::UnexpectedEOF));
        assert_eq!(FileType::Png.check_plain(b"OggS\0\0\0\0"), Err(Error::InvalidContent));
        assert_eq!(FileType::Ogg.check_plain(b"OggS\0\0"), Ok(()));
        assert_eq!(FileType::M4a.check_plain(b"\0\0\0\x1cftypM4A "), Ok(()));
        assert_eq!(FileType::M4a.check_plain(b"\0\0\0\x1c"), Err(Error::UnexpectedEOF));
        assert_eq!(FileType::M4a.check_plain(b"\0\0\0\x1cfree"), Err(Error::InvalidContent));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn in_place_errors_leave_the_buffer_alone() {
        let plain = Decrypter::new()
            .decrypt(&read(MZ_PNG_DEFAULT).unwrap(), FileType::Png)
            .unwrap();
        let mut buffer = plain.clone();
        assert_eq!(
            Decrypter::new().encrypt_in_place(&mut buffer, FileType::Png),
            Err(Error::KeyNotSet)
        );
        assert_eq!(buffer, plain);

        let other = read(MZ_PNG_ABOBA).unwrap();
        let mut buffer = other.clone();
        assert_eq!(
            Decrypter::new().decrypt_in_place_keyed(&mut buffer, FileType::Png),
            Err(Error::KeyNotSet)
        );
        assert_eq!(buffer, other);

        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(DEFAULT_KEY).unwrap();
        assert_eq!(
            decrypter.decrypt_in_place_keyed(&mut buffer, FileType::Png),
            Err(Error::KeyMismatch)
        );
        assert_eq!(buffer, other);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn keyed_decrypt_rejects_a_file_of_another_type() {
        let mut decrypter = Decrypter::new();
        decrypter
            .set_key_from_file(&read(MZ_OGG_DEFAULT).unwrap(), FileType::Ogg)
            .unwrap();
        assert_eq!(
            decrypter.decrypt_keyed(&read(MZ_PNG_DEFAULT).unwrap(), FileType::Ogg),
            Err(Error::KeyMismatch)
        );
    }

    // `TryFrom<&OsStr>` exists only with the `std` feature, so this test is skipped in `no_std` and `alloc` builds.
    #[cfg(all(unix, feature = "std"))]
    #[test]
    fn non_utf8_extension_is_unsupported() {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
        assert_eq!(
            FileType::try_from(OsStr::from_bytes(b"\xffpng")),
            Err(Error::UnsupportedExtension)
        );
    }
}
