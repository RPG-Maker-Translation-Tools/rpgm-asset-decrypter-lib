//! Writes the fuzz corpora from the tracked test assets. `decrypt` and `capi` get each file behind its selector byte,
//! `capi` once per operation; `key` gets a few keys. Run from `fuzz/`: `cargo run --locked --example make_seeds`
use std::{fs, path::Path};

// Selector byte per extension: 0 = PNG, 1 = OGG, 2 = M4A, the file types the targets pick between.
const SELECTORS: [(&str, u8); 5] = [("png_", 0), ("rpgmvp", 0), ("ogg_", 1), ("rpgmvo", 1), ("m4a_", 2)];

// The key target takes any UTF-8 text, and a key is accepted only as 32 hex digits, in either case.
const KEYS: [&str; 2] = ["0123456789abcdef0123456789abcdef", "0123456789ABCDEF0123456789ABCDEF"];

fn main() {
    for target in ["decrypt", "key", "capi"] {
        fs::create_dir_all(format!("corpus/{target}")).unwrap();
    }

    for (index, key) in KEYS.iter().enumerate() {
        fs::write(format!("corpus/key/key-{index}"), key).unwrap();
    }

    let assets = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/assets"));
    for directory in ["mv", "mz"] {
        for entry in fs::read_dir(assets.join(directory)).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let extension = name.rsplit('.').next().unwrap_or_default();
            let Some(&(_, selector)) = SELECTORS.iter().find(|(known, _)| *known == extension) else {
                continue;
            };
            let file = fs::read(entry.path()).unwrap();

            // decrypt: the selector byte, then the file.
            let mut decrypt_seed = vec![selector];
            decrypt_seed.extend_from_slice(&file);
            fs::write(format!("corpus/decrypt/{directory}-{name}"), &decrypt_seed).unwrap();

            // capi: the operation byte (decrypt, derive key, encrypt), the file type byte, then the file.
            for operation in 0..3u8 {
                let mut capi_seed = vec![operation, selector];
                capi_seed.extend_from_slice(&file);
                fs::write(format!("corpus/capi/{directory}-{name}-{operation}"), &capi_seed).unwrap();
            }
        }
    }
}
