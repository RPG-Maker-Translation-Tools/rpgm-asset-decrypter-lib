# rpgmasd-capi

C bindings for `rpgm-asset-decrypter-lib`.

## Install

```bash
cargo install cargo-c
cargo cinstall --release --prefix=/usr/local
```

Installs `librpgmasd` (shared and static), `rpgmasd/rpgmasd.h` and a `pkg-config` file. The header documents every function.

## Usage

The library never allocates: everything works on buffers you own. Every fallible function returns an `RpgmasdStatus` (`RPGMASD_STATUS_OK` on success).

`RpgmasdDecrypter` is an opaque type, so reserve storage for it as `RPGMASD_DECRYPTER_SIZE` bytes and initialize it with `rpgmasd_decrypter_init`. There is nothing to free.

```c
#include <rpgmasd/rpgmasd.h>
#include <stdalign.h>

alignas(RPGMASD_DECRYPTER_ALIGN) uint8_t storage[RPGMASD_DECRYPTER_SIZE];
RpgmasdDecrypter *decrypter = (RpgmasdDecrypter *)storage;
rpgmasd_decrypter_init(decrypter);

// The key is derived from the first file and checked against the following ones
// (RPGMASD_STATUS_KEY_MISMATCH), so use one decrypter per encryption key.
RpgmasdStatus status = rpgmasd_decrypter_decrypt_in_place(decrypter, file_content, file_content_len,
                                                          RPGMASD_FILE_TYPE_PNG);
if (status == RPGMASD_STATUS_OK) {
    // decrypted data is valid starting at file_content + RPGMASD_HEADER_LENGTH
}
```

`file_type` is one of `RPGMASD_FILE_TYPE_PNG`, `RPGMASD_FILE_TYPE_OGG` and `RPGMASD_FILE_TYPE_M4A`; anything else gives `RPGMASD_STATUS_INVALID_FILE_TYPE`.

Once a decrypter has a key, `rpgmasd_decrypter_decrypt_in_place_keyed` takes it as `const`, so several threads can share it.

### Keys

- `rpgmasd_decrypter_set_key_from_str` sets the key from the game's `encryptionKey` in `System.json`: a NUL-terminated string of 32 hex characters, any case.
- `rpgmasd_decrypter_set_key_from_file` derives the key from an encrypted file and writes it out as hex.
- `rpgmasd_decrypter_key` reads the current key back.

Keys written out go into a buffer of `RPGMASD_KEY_BUFFER_LENGTH` bytes (32 hex characters and a NUL). `rpgmasd_decrypter_key` and `rpgmasd_decrypter_set_key_from_file` take the buffer length and never write past it.

For storage whose size is only known at run time, `rpgmasd_decrypter_size()` and `rpgmasd_decrypter_align()` return the values of the `RPGMASD_DECRYPTER_*` macros.

### Encrypting

Encrypting needs a key: set one with `rpgmasd_decrypter_set_key_from_str` or `rpgmasd_decrypter_set_key_from_file` first. The example below assumes it.

`rpgmasd_decrypter_encrypt_into` writes a complete encrypted file (header and payload) into a separate buffer of `RPGMASD_HEADER_LENGTH + data_len` bytes. If the buffer is too small, it returns `RPGMASD_STATUS_BUFFER_TOO_SMALL` and stores the required size in `out_len`.

```c
size_t needed = 0;
status = rpgmasd_decrypter_encrypt_into(decrypter, png, png_len, RPGMASD_FILE_TYPE_PNG, out, out_cap, &needed);
```

The `*_encrypt_in_place` functions produce only the encrypted payload; prepend the header from `rpgmasd_header`. They check the data's magic bytes against `file_type` first: `RPGMASD_STATUS_INVALID_CONTENT` if they don't match, `RPGMASD_STATUS_UNEXPECTED_EOF` if the data is too short to have them.

`rpgmasd_default_key()` returns the key RPG Maker uses when a project's encryption key is empty, as a static NUL-terminated string.

For one-shot calls there are `rpgmasd_decrypt_asset_in_place` and `rpgmasd_encrypt_asset_in_place`, which use a throwaway decrypter internally.

## `no_std`

The library never allocates, so `no_std` needs no allocator, only a panic handler that aborts, which the crate provides. On a host target that's enough:

```bash
cargo build --release --no-default-features -p rpgmasd-capi
```

A target without a prebuilt `core` (bare metal, for example) needs `core` built from source, which takes nightly with `rust-src`:

```bash
cargo +nightly build --release --no-default-features -p rpgmasd-capi -Zbuild-std=core --target <your-target-triple>
```
