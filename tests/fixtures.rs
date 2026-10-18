// Real encoder output from `tests/assets/variants`, made by `generate.ts`. Each encrypted file has its plain counterpart,
// encrypted there with an independent implementation of the format.
use rpgm_asset_decrypter_lib::{Decrypter, FileType};
use std::fs::read;

struct Variant {
    encrypted: &'static str,
    #[cfg(feature = "alloc")]
    plain: &'static str,
    file_type: FileType,
    key: &'static str,
}

const VARIANTS: [Variant; 5] = [
    Variant {
        encrypted: "png-interlaced-palette.rpgmvp",
        #[cfg(feature = "alloc")]
        plain: "png-interlaced-palette.png",
        file_type: FileType::Png,
        key: "d41d8cd98f00b204e9800998ecf8427e",
    },
    Variant {
        encrypted: "png-rgba16.png_",
        #[cfg(feature = "alloc")]
        plain: "png-rgba16.png",
        file_type: FileType::Png,
        key: "00112233445566778899aabbccddeeff",
    },
    Variant {
        encrypted: "ogg-multipage.ogg_",
        #[cfg(feature = "alloc")]
        plain: "ogg-multipage.ogg",
        file_type: FileType::Ogg,
        key: "0123456789abcdef0123456789abcdef",
    },
    Variant {
        encrypted: "m4a-moov-last.rpgmvm",
        #[cfg(feature = "alloc")]
        plain: "m4a-moov-last.m4a",
        file_type: FileType::M4a,
        key: "d41d8cd98f00b204e9800998ecf8427e",
    },
    Variant {
        encrypted: "m4a-moov-first.rpgmvm",
        #[cfg(feature = "alloc")]
        plain: "m4a-moov-first.m4a",
        file_type: FileType::M4a,
        key: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    },
];

fn asset(name: &str) -> Vec<u8> {
    read(format!("./tests/assets/variants/{name}")).unwrap()
}

// Without the key, an M4A keeps its first 8 bytes and everything from offset 16. Bytes 8..16 come from the header the
// derivation assumes, so they may differ from the plain file (see `Decrypter::set_key_from_file`).
#[cfg(feature = "alloc")]
fn assert_restored(decrypted: &[u8], plain: &[u8], file_type: FileType, name: &str) {
    if file_type.is_m4a() {
        assert_eq!(decrypted[..8], plain[..8], "{name}");
        assert_eq!(decrypted[16..], plain[16..], "{name}");
    } else {
        assert_eq!(decrypted, plain, "{name}");
    }
}

#[cfg(feature = "alloc")]
#[test]
fn derived_key_restores_every_variant() {
    for variant in &VARIANTS {
        let decrypted = Decrypter::new()
            .decrypt(&asset(variant.encrypted), variant.file_type)
            .unwrap();
        assert_restored(&decrypted, &asset(variant.plain), variant.file_type, variant.encrypted);
    }
}

#[cfg(feature = "alloc")]
#[test]
fn known_key_restores_every_variant_exactly() {
    for variant in &VARIANTS {
        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(variant.key).unwrap();
        let decrypted = decrypter.decrypt(&asset(variant.encrypted), variant.file_type).unwrap();
        assert_eq!(decrypted, asset(variant.plain), "{}", variant.encrypted);
    }
}

#[cfg(feature = "alloc")]
#[test]
fn encrypting_the_plain_file_reproduces_the_fixture() {
    for variant in &VARIANTS {
        let mut decrypter = Decrypter::new();
        decrypter.set_key_from_str(variant.key).unwrap();
        let encrypted = decrypter.encrypt(&asset(variant.plain), variant.file_type).unwrap();
        assert_eq!(encrypted, asset(variant.encrypted), "{}", variant.encrypted);
    }
}

#[test]
fn png_and_ogg_keys_are_derived_exactly() {
    for variant in VARIANTS.iter().filter(|variant| !variant.file_type.is_m4a()) {
        let key = Decrypter::new()
            .set_key_from_file(&asset(variant.encrypted), variant.file_type)
            .map(str::to_owned);
        assert_eq!(key.as_deref(), Ok(variant.key), "{}", variant.encrypted);
    }
}
