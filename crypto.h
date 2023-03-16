#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/aes.h>

char* generate_key(size_t size);
size_t encrypt(const char* plaintext, size_t plaintext_len, const char* key, size_t key_size, 
  const char* iv, char* ciphertext);
size_t decrypt(const char* ciphertext, size_t ciphertext_len, const char* key, const char* iv,
 char* plaintext);
char* base_64_encode(const unsigned char* buffer, size_t length);
char* base_64_decode(const char* buffer, size_t length, size_t* resulr_len);

#endif // CRYPTO_H
