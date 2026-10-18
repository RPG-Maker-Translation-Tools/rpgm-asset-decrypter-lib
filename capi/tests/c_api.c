// Exercises the handle-based part of the C API, which the Rust tests reach only through the fuzz target.
// Built against the cbindgen header, so it also checks that the header declares what the library exports.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rpgmasd.h"

#define CHECK(expr)                                                                    \
  do {                                                                                 \
    if (!(expr)) {                                                                     \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #expr);         \
      exit(1);                                                                         \
    }                                                                                  \
  } while (0)

int main(void) {
  // The storage is only as big and as aligned as the header says the decrypter needs.
  _Alignas(RPGMASD_DECRYPTER_ALIGN) unsigned char storage[RPGMASD_DECRYPTER_SIZE];
  RpgmasdDecrypter *decrypter = (RpgmasdDecrypter *)storage;

  CHECK(rpgmasd_decrypter_size() == RPGMASD_DECRYPTER_SIZE);
  CHECK(rpgmasd_decrypter_align() == RPGMASD_DECRYPTER_ALIGN);

  unsigned char header[RPGMASD_HEADER_LENGTH];
  CHECK(rpgmasd_header(header) == RPGMASD_STATUS_OK);
  CHECK(rpgmasd_header(NULL) == RPGMASD_STATUS_NULL_ARGUMENT);

  CHECK(rpgmasd_decrypter_init(decrypter) == RPGMASD_STATUS_OK);
  CHECK(rpgmasd_decrypter_set_key_from_str(decrypter, rpgmasd_default_key()) == RPGMASD_STATUS_OK);

  char key[RPGMASD_KEY_BUFFER_LENGTH];
  CHECK(rpgmasd_decrypter_key(decrypter, key, sizeof key) == RPGMASD_STATUS_OK);
  CHECK(strlen(key) == RPGMASD_KEY_STR_LENGTH);
  CHECK(strcmp(key, rpgmasd_default_key()) == 0);

  // A PNG magic followed by filler, so the magic check in the encrypt functions passes.
  unsigned char plain[32];
  static const unsigned char png_magic[8] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
  memcpy(plain, png_magic, sizeof png_magic);
  for (size_t at = sizeof png_magic; at < sizeof plain; at++) {
    plain[at] = (unsigned char)at;
  }

  // Too small: the status says so, and the required size is still reported.
  unsigned char small[RPGMASD_HEADER_LENGTH];
  size_t needed = 0;
  CHECK(rpgmasd_decrypter_encrypt_into(decrypter, plain, sizeof plain, RPGMASD_FILE_TYPE_PNG, small, sizeof small,
                                       &needed) == RPGMASD_STATUS_BUFFER_TOO_SMALL);
  CHECK(needed == RPGMASD_HEADER_LENGTH + sizeof plain);

  // A complete file: the header, then the payload, which must decrypt back to the plaintext.
  unsigned char file[RPGMASD_HEADER_LENGTH + sizeof plain];
  size_t file_len = 0;
  CHECK(rpgmasd_decrypter_encrypt_into(decrypter, plain, sizeof plain, RPGMASD_FILE_TYPE_PNG, file, sizeof file,
                                       &file_len) == RPGMASD_STATUS_OK);
  CHECK(file_len == RPGMASD_HEADER_LENGTH + sizeof plain);
  CHECK(memcmp(file, header, RPGMASD_HEADER_LENGTH) == 0);

  // Decryption takes the whole file; the plaintext is valid from offset RPGMASD_HEADER_LENGTH on.
  unsigned char decrypted[RPGMASD_HEADER_LENGTH + sizeof plain];
  memcpy(decrypted, file, file_len);
  CHECK(rpgmasd_decrypter_decrypt_in_place_keyed(decrypter, decrypted, file_len, RPGMASD_FILE_TYPE_PNG) ==
        RPGMASD_STATUS_OK);
  CHECK(memcmp(decrypted + RPGMASD_HEADER_LENGTH, plain, sizeof plain) == 0);

  // The encrypt-in-place path produces the same payload as encrypt_into.
  unsigned char in_place[sizeof plain];
  memcpy(in_place, plain, sizeof plain);
  CHECK(rpgmasd_decrypter_encrypt_in_place(decrypter, in_place, sizeof in_place, RPGMASD_FILE_TYPE_PNG) ==
        RPGMASD_STATUS_OK);
  CHECK(memcmp(in_place, file + RPGMASD_HEADER_LENGTH, sizeof in_place) == 0);

  puts("rpgmasd C API: ok");
  return 0;
}
