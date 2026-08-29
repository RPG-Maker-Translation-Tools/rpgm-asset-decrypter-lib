# rpgmasd-capi

C bindings for [`rpgm-asset-decrypter-lib`](https://github.com/RPG-Maker-Translation-Tools/rpgm-asset-decrypter-lib). Installable via [`cargo-c`](https://github.com/lu-zero/cargo-c). Produces a shared/static library (`librpgmasd`), a C header (`rpgmasd.h`), and a `pkg-config` file.

## Building / installing

```bash
cd crates/rpgmasd-capi
cargo install cargo-c # or cargo binstall cargo-c
cargo cbuild --release
cargo cinstall --release --prefix=/usr/local
```

## API

The C API never allocates - it wraps the in-place `encrypt_in_place`/`decrypt_in_place` operations only. The Vec-returning `encrypt`/`decrypt` convenience methods on the Rust side exist for Rust callers with a heap; they don't carry over the FFI boundary.

```c
#include <rpgmasd/rpgmasd.h>

RpgmasdDecrypter decrypter;
rpgmasd_decrypter_init(&decrypter);

RpgmasdStatus status = rpgmasd_decrypter_decrypt_in_place(&decrypter, file_content, file_content_len,
                                                            RPGMASD_FILE_TYPE_PNG);
if (status == RPGMASD_STATUS_OK) {
    // decrypted data is valid starting at file_content + RPGMASD_HEADER_LENGTH
}
```

Every fallible function returns an `RpgmasdStatus` (`RPGMASD_STATUS_OK` on success).

Free-function equivalents that spin up a throwaway `Decrypter` internally are also provided, mirroring the Rust crate's convenience wrappers: `rpgmasd_decrypt_asset_in_place`, `rpgmasd_encrypt_asset_in_place`.

The header (`assets/rpgmasd.h`) is hand-written. See [`src/lib.rs`](src/lib.rs) for the same surface with full documentation.

## `no_std`

Because this crate never allocates, disabling its default `std` feature is enough for a `no_std` build:

```bash
cargo build --release --no-default-features -p rpgmasd-capi
```

With `std` off there is no other Rust code around to supply a panic handler, so the crate provides a minimal abort-on-panic one itself, gated `#[cfg(not(feature = "std"))]` to avoid a duplicate lang item when `std` (and its own panic handler) is linked in.
