## 5.0.0

- **Breaking:** `FileType` variants are renamed to `Png`, `Ogg` and `M4a`.
- **Breaking:** `encrypt` and `encrypt_in_place` now take a `FileType` as their second argument, and the data is checked against it.
- **Breaking:** `FileType` and `Error` are now `#[non_exhaustive]`.
- **Breaking:** `DECRYPTED_ASSETS_EXTS` is renamed to `DECRYPTED_ASSET_EXTS`.
- **Breaking:** Converting a string to a `FileType` now fails with `Error::UnsupportedExtension` instead of a string error.
- Decrypting a file encrypted with a different key than the decrypter's now returns `KeyMismatch` instead of corrupt output.
- Encrypting data that doesn't look like its declared file type now fails with `InvalidContent`.
- Parsing a `FileType` from an extension now ignores case, so `RPGMVP` is accepted.
- Added `decrypt_keyed` and `decrypt_in_place_keyed`, which take `&self`, so a keyed decrypter can be shared between threads.
- Added `decrypted_extension` and `encrypted_extension` to `FileType`.
- `key()` now always returns lowercase hex, even if the key was set in uppercase.
- The free `decrypt_in_place` function now returns the decrypted data as a slice.
- The minimum supported Rust version is now 1.81, up from 1.77.
- Fixed: a key derived from an M4A file could corrupt PNG and OGG files decrypted after it with the same `Decrypter`. Those files now derive their own key, and the `*_keyed` methods return `KeyMismatch` for them.
- Deriving a key from an M4A file now fails with `InvalidContent` when no box follows the type box, instead of assuming a 28-byte header.
