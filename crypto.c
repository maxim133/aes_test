#include "crypto.h"
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>

#include "pass_manager.h"

char* base_64_decode(const char* buffer, size_t length, size_t* resulr_len) 
{
  assert(buffer);
  assert(length);

  /* Calculate original lenght of the string*/
  size_t padding = 0;
  if (buffer[length-1] == '=' && buffer[length-2] == '=')
  {
    padding = 2;
  }
  else if (buffer[length-1] == '=')
  {
    padding = 1;
  }

  size_t original_length = (length * 3) / 4 - padding;

  char* encoded_text = malloc(original_length + 1);
  assert(encoded_text);

  BIO* bio = BIO_new_mem_buf(buffer, -1);
  BIO* b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  size_t len = BIO_read(bio, encoded_text, length);
  if (len != original_length)
  {
    free(encoded_text);
    encoded_text = NULL;
  }
  else
  {
    encoded_text[len] = '\0';
  }

  *resulr_len = len;

  BIO_free_all(bio);

  return encoded_text;
}

char* base_64_encode(const unsigned char* buffer, size_t length) 
{
  assert(buffer);
  assert(length);

  BUF_MEM *bufferPtr;

  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* out = BIO_new(BIO_s_mem());
  out = BIO_push(b64, out);

  BIO_set_flags(out, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(out, buffer, length);
  BIO_flush(out);
  BIO_get_mem_ptr(out, &bufferPtr);

  char* encoded_text = malloc(bufferPtr->length + 1);
  strncpy(encoded_text, bufferPtr->data, bufferPtr->length);
  encoded_text[bufferPtr->length] = '\0';

  BIO_set_close(out, BIO_NOCLOSE);
  BIO_free_all(out);

  return encoded_text;
}

char* generate_key(size_t size)
{
  assert(size);
  /* 32 bytes is enough for the AES*/
  assert(size < 33);
  char* bytes = NULL;
  int chunk;
  BUF_MEM *bptr = NULL;

  unsigned char *buff = malloc(size + 1);

  BIO* b64 = BIO_new(BIO_f_base64());
  if (b64 == NULL) 
  {
    return NULL;
  }

  BIO* out = BIO_new(BIO_s_mem());
  if (out == NULL) 
  {
    return NULL;
  }

  out = BIO_push(b64, out);
  BIO_set_flags(out, BIO_FLAGS_BASE64_NO_NL);

  RAND_bytes(buff, size);

  BIO_write(out, buff, size);
  BIO_flush(out);

  out = BIO_pop(b64);

  BIO_write(out, "\0", 1);
  BIO_get_mem_ptr(out, &bptr);

  char* key = malloc(size);
  strncpy(key, bptr->data, size);
  key[size] = '\0';

  BIO_set_close(out, BIO_CLOSE);
  BIO_free_all(out);
  free(buff);

  return key;
}

static const EVP_CIPHER* get_cipher_type(size_t key_len)
{
  const EVP_CIPHER* type = NULL;
  switch (key_len) 
  {
    case 16:
      type = EVP_aes_128_cbc();
      break;
    case 24:
      type = EVP_aes_192_cbc();
      break;
    case 32:
      type = EVP_aes_256_cbc();
      break;
    default:
      //error
      break;
  }

  return type;
}

size_t encrypt(const char* plaintext, size_t plaintext_len, const char* key, size_t key_size, 
  const char* iv, char* ciphertext)
{
  assert(plaintext);
  assert(plaintext_len);
  assert(key);
  assert(iv);
  assert(ciphertext);

  int len;
  int ciphertext_len = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if(ctx == NULL)
  {
    return 0;
  }

  const EVP_CIPHER* type = get_cipher_type(key_size);
  if (type == NULL)
  {
    return 0;
  }

  int ret = EVP_EncryptInit_ex(ctx, type, NULL, 
    (unsigned char*)key, (unsigned char*)iv);
  if(ret !=1)
  {
    goto exit;
  }

  ret = EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext, &len, 
    (unsigned char*)plaintext, plaintext_len);
  if(ret !=1)
  {
    goto exit;
  }

  ciphertext_len = len;

  ret = EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext + len, &len);
  if(ret !=1)
  {
    goto exit;
  }

  ciphertext_len += len;

exit:
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

size_t decrypt(const char* ciphertext, size_t ciphertext_len, const char* key,
  const char* iv, char* plaintext)
{
  assert(plaintext);
  assert(ciphertext_len);
  assert(key);
  assert(iv);
  assert(ciphertext);
  int len;

  int plaintext_len;

  size_t key_len = strlen(key);
  const EVP_CIPHER* type = get_cipher_type(key_len);
  if (type == NULL)
  {
    return 0;
  }

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if(ctx == NULL)
  {
    return 0;
  }

  int ret = EVP_DecryptInit_ex(ctx, type, NULL, (const unsigned char*)key, 
    (const unsigned char*)iv);
  if(ret != 1)
  {
    goto exit;
  }

  ret = EVP_DecryptUpdate(ctx, (unsigned char*)plaintext, &len, (unsigned char*)ciphertext, 
    ciphertext_len);
  if(ret != 1)
  {
    goto exit;
  }

  plaintext_len = len;

  ret = EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext + len, &len);
  if(ret != 1)
  {
    goto exit;
  }

  plaintext_len += len;
  plaintext[plaintext_len] = '\0';

exit:
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}