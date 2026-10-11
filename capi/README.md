# rpgmasd-capi

C bindings for `rpgm-asset-decrypter-lib`.

## Install

```bash
cargo install cargo-c
cargo cinstall --release --prefix=/usr/local
```

Installs `librpgmasd` (shared and static), `rpgmasd/rpgmasd.h` and a `pkg-config` file. The header documents every function.

## Usage

The library never allocates: everything works in place on your buffer. Every fallible function returns an `RpgmasdStatus` (`RPGMASD_STATUS_OK` on success).

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

For one-shot calls there are `rpgmasd_decrypt_asset_in_place` and `rpgmasd_encrypt_asset_in_place`, which use a throwaway decrypter internally.

## `no_std`

Because the library never allocates, `--no-default-features` is all a `no_std` build needs:

```bash
cargo build --release --no-default-features -p rpgmasd-capi
```
