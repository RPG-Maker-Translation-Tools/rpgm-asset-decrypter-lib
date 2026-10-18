#[cfg(feature = "alloc")]
use proptest::{collection::vec, sample::select};
use proptest::{prelude::*, test_runner::Config as ProptestConfig};
use rpgm_asset_decrypter_lib::Decrypter;
#[cfg(feature = "alloc")]
use rpgm_asset_decrypter_lib::{FileType, RPGM_HEADER};

#[cfg(feature = "alloc")]
const DEFAULT_KEY: &str = "d41d8cd98f00b204e9800998ecf8427e";

#[cfg(feature = "alloc")]
fn file_type() -> impl Strategy<Value = FileType> {
    select(vec![FileType::Png, FileType::Ogg, FileType::M4a])
}

#[cfg(feature = "alloc")]
fn key_hex(key: &[u8; 16]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

// The bytes every file of `file_type` starts with, followed by `body`.
#[cfg(feature = "alloc")]
fn with_magic(file_type: FileType, body: &[u8]) -> Vec<u8> {
    let magic: &[u8] = match file_type {
        FileType::Png => b"\x89PNG\r\n\x1a\n",
        FileType::Ogg => b"OggS",
        _ => b"\0\0\0\x1cftypM4A ",
    };
    [magic, body].concat()
}

// A PNG whose IHDR passes the checker: the signature, the IHDR chunk header and fields, then `tail`.
#[cfg(feature = "alloc")]
fn png(depth: u8, color: u8, interlace: u8, width: u32, height: u32, tail: &[u8]) -> Vec<u8> {
    let mut plain = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    plain.extend_from_slice(&width.to_be_bytes());
    plain.extend_from_slice(&height.to_be_bytes());
    plain.extend_from_slice(&[depth, color, 0, 0, interlace]);
    plain.extend_from_slice(tail);
    plain
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(if cfg!(miri) { 4 } else { 256 }))]

    // Any key and any content survive encrypt, then decrypt. The copying and in-place paths agree with each other.
    #[cfg(feature = "alloc")]
    #[test]
    fn encrypt_then_decrypt_restores_the_content(
        key in any::<[u8; 16]>(),
        file_type in file_type(),
        body in vec(any::<u8>(), 0..512),
    ) {
        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(&key_hex(&key)).unwrap();
        let plain = with_magic(file_type, &body);

        let encrypted = decrypter.encrypt(&plain, file_type).unwrap();
        prop_assert_eq!(decrypter.decrypt_keyed(&encrypted, file_type).unwrap(), plain.clone());

        let mut in_place = encrypted.clone();
        let restored = decrypter.decrypt_in_place_keyed(&mut in_place, file_type).unwrap();
        prop_assert_eq!(restored, &plain[..]);

        let mut payload = plain.clone();
        decrypter.encrypt_in_place(&mut payload, file_type).unwrap();
        prop_assert_eq!(&payload[..], &encrypted[RPGM_HEADER.len()..]);
    }

    // The key is recovered exactly from any PNG with a valid IHDR, whatever follows the header.
    #[cfg(feature = "alloc")]
    #[test]
    fn png_key_is_recovered_from_its_header(
        key in any::<[u8; 16]>(),
        depth in select(vec![1u8, 2, 4, 8, 16]),
        color in select(vec![0u8, 2, 3, 4, 6]),
        interlace in 0u8..=1,
        width in any::<u32>(),
        height in any::<u32>(),
        tail in vec(any::<u8>(), 0..256),
    ) {
        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(&key_hex(&key)).unwrap();
        let plain = png(depth, color, interlace, width, height, &tail);
        let encrypted = decrypter.encrypt(&plain, FileType::Png).unwrap();

        let derived = Decrypter::new().set_key_from_file(&encrypted, FileType::Png).map(str::to_owned);
        prop_assert_eq!(derived, Ok(key_hex(&key)));
        prop_assert_eq!(Decrypter::new().decrypt(&encrypted, FileType::Png).unwrap(), plain);
    }

    // Arbitrary bytes, with or without the RPG Maker header, never panic. A failed in-place call leaves the buffer alone.
    #[cfg(feature = "alloc")]
    #[test]
    fn arbitrary_input_never_panics(
        file_type in file_type(),
        body in vec(any::<u8>(), 0..600),
        framed in any::<bool>(),
    ) {
        let input = if framed { [RPGM_HEADER, &body[..]].concat() } else { body };

        let copied = Decrypter::new().decrypt(&input, file_type);
        let mut buffer = input.clone();
        let in_place = Decrypter::new().decrypt_in_place(&mut buffer, file_type).map(<[u8]>::to_vec);
        let failed = in_place.is_err();
        prop_assert_eq!(copied, in_place);
        if failed {
            prop_assert_eq!(buffer, input.clone());
        }

        let _ = Decrypter::new().set_key_from_file(&input, file_type);
        let mut keyed = Decrypter::new();
        keyed.set_key_from_str(DEFAULT_KEY).unwrap();
        let _ = keyed.decrypt_keyed(&input, file_type);
        let _ = keyed.encrypt(&input, file_type);
    }

    // A key string is accepted exactly when it is 32 hexadecimal digits, in either case, and rejected otherwise.
    #[test]
    fn key_string_is_accepted_exactly_when_it_is_32_hex_digits(
        key in prop_oneof![any::<String>(), "[0-9a-fA-F]{32}"],
    ) {
        let valid = key.len() == 32 && key.bytes().all(|byte| byte.is_ascii_hexdigit());
        prop_assert_eq!(Decrypter::new().set_key_from_str(&key).is_ok(), valid);
    }
}
