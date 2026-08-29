#ifndef RPGMASD_H
#define RPGMASD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The original, decrypted asset kind. */
typedef enum RpgmasdFileType {
    RPGMASD_FILE_TYPE_PNG = 0,
    RPGMASD_FILE_TYPE_OGG = 1,
    RPGMASD_FILE_TYPE_M4A = 2,
} RpgmasdFileType;

/* Status code returned by every fallible rpgmasd_* function.
 * RPGMASD_STATUS_OK is the only success value. */
typedef enum RpgmasdStatus {
    RPGMASD_STATUS_OK = 0,
    RPGMASD_STATUS_KEY_NOT_SET = 1,
    RPGMASD_STATUS_INVALID_KEY_LENGTH = 2,
    RPGMASD_STATUS_INVALID_HEADER = 3,
    RPGMASD_STATUS_UNEXPECTED_EOF = 4,
    /* A pointer argument that must not be null (decrypter, data, key,
     * out_key) was null. */
    RPGMASD_STATUS_NULL_ARGUMENT = 5,
    /* `key` was not valid UTF-8. */
    RPGMASD_STATUS_INVALID_UTF8 = 6,
} RpgmasdStatus;

/* Opaque Decrypter instance. Carries no heap allocation - it is a
 * fixed-size, fixed-alignment value the caller owns directly. Reserve
 * storage for it (e.g. a local variable, or a buffer sized/aligned per
 * rpgmasd_decrypter_size/rpgmasd_decrypter_align) and initialize it with
 * rpgmasd_decrypter_init. There is no corresponding free function - once
 * you are done with the storage, simply reclaim it. */
typedef struct RpgmasdDecrypter RpgmasdDecrypter;

/* The size, in bytes, of a RpgmasdDecrypter instance - the minimum size of
 * the storage passed to rpgmasd_decrypter_init. */
size_t rpgmasd_decrypter_size(void);

/* The required alignment, in bytes, of the storage passed to
 * rpgmasd_decrypter_init. */
size_t rpgmasd_decrypter_align(void);

/* Initializes a RpgmasdDecrypter into caller-provided storage. `out` must
 * point to at least rpgmasd_decrypter_size() writable bytes, aligned to
 * rpgmasd_decrypter_align(). */
RpgmasdStatus rpgmasd_decrypter_init(RpgmasdDecrypter* out);

/* Writes the decrypter's key as a NUL-terminated 32-character hex string
 * into `out_key`, which must point to a buffer of at least 33 bytes. */
RpgmasdStatus rpgmasd_decrypter_key(const RpgmasdDecrypter* decrypter, char* out_key);

/* Sets the decrypter's key from a NUL-terminated 32-character hex string. */
RpgmasdStatus rpgmasd_decrypter_set_key_from_str(RpgmasdDecrypter* decrypter, const char* key);

/* Sets the key of the decrypter from encrypted `data`, writing the derived
 * 32-character hex key as a NUL-terminated string into `out_key`, which
 * must point to a buffer of at least 33 bytes. */
RpgmasdStatus rpgmasd_decrypter_set_key_from_file(
    RpgmasdDecrypter* decrypter,
    const uint8_t* data,
    size_t data_len,
    RpgmasdFileType file_type,
    char* out_key
);

/* Decrypts RPG Maker file content in place. Auto-determines the key from
 * `data` if the decrypter doesn't already have one set. Decrypted data is
 * valid starting at byte offset 16 of `data`. */
RpgmasdStatus rpgmasd_decrypter_decrypt_in_place(
    RpgmasdDecrypter* decrypter,
    uint8_t* data,
    size_t data_len,
    RpgmasdFileType file_type
);

/* Encrypts file content in place. Requires the decrypter to already have a
 * key set. Produces the raw encrypted payload, without the RPG Maker
 * header. */
RpgmasdStatus rpgmasd_decrypter_encrypt_in_place(const RpgmasdDecrypter* decrypter, uint8_t* data, size_t data_len);

/* Decrypts RPG Maker file content in place using a temporary Decrypter
 * instance. */
RpgmasdStatus rpgmasd_decrypt_asset_in_place(uint8_t* data, size_t data_len, RpgmasdFileType file_type);

/* Encrypts file content in place using a NUL-terminated key string and a
 * temporary Decrypter instance. */
RpgmasdStatus rpgmasd_encrypt_asset_in_place(uint8_t* data, size_t data_len, const char* key);

/* The fixed 16-byte length of the RPG Maker encryption header. */
extern const size_t RPGMASD_HEADER_LENGTH;

/* The fixed 32-character length of a hex-encoded key string. */
extern const size_t RPGMASD_KEY_STR_LENGTH;

#ifdef __cplusplus
}
#endif

#endif /* RPGMASD_H */
