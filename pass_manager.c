#include "pass_manager.h"
#include "crypto.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void sanityze_memory(void* mem, size_t lenght)
{
  memset(mem, 0, lenght);
}

pass_t* create_pass_struct()
{
  pass_t* pass = malloc(sizeof(pass_t));
  assert(pass);

  return pass;
}

void delete_pass_struct(pass_t* obj)
{
  if (obj == NULL)
  {
    return;
  }

  sanityze_memory((void*)obj, sizeof(pass_t));
  free(obj);
}

encrypted_pass_t* create_encrypted_pass_struct()
{
  encrypted_pass_t* encrypted_pass = malloc(sizeof(encrypted_pass_t));
  assert(encrypted_pass);

  return encrypted_pass;
}

encrypted_pass_t* create_encrypted_pass_buffer()
{
  encrypted_pass_t* buffer  = create_encrypted_pass_struct();
  assert(buffer);

  buffer->username = malloc(PASS_BUFFER_LEN);
  assert(buffer->username);

  buffer->password = malloc(PASS_BUFFER_LEN);
  assert(buffer->password);

  buffer->iv = malloc(PASS_BUFFER_LEN);
  assert(buffer->iv);

  buffer->key = malloc(PASS_BUFFER_LEN);
  assert(buffer->key);

  return buffer;
}

void delete_encrypted_pass_struct(encrypted_pass_t* obj)
{
  if (obj == NULL)
  {
    return;
  }

  free(obj->password);
  free(obj->username);

  if (obj->iv)
  {
    sanityze_memory((void*)obj->iv, strlen(obj->iv));
    free(obj->iv);
  }

  if (obj->key)
  {
    sanityze_memory((void*)obj->key, strlen(obj->key));
    free(obj->key);
  }

  free(obj);
}

encrypted_pass_t* encrypt_passdata(const pass_t* input, key_size_t key_size)
{
  encrypted_pass_t* encrypted_pass = create_encrypted_pass_struct();

  encrypted_pass->key = generate_key(key_size);
  if (encrypted_pass->key == NULL)
  {
    goto exit;
  }

  encrypted_pass->iv = generate_key(key_size);
  if (encrypted_pass->iv == NULL)
  {
    goto exit;
  }

  char buffer[PASS_BUFFER_LEN];
  int len = encrypt(input->username, strlen(input->username), encrypted_pass->key, 
    key_size, encrypted_pass->iv, buffer);
  if (len == 0)
  {
    goto exit;
  }

  encrypted_pass->username = base_64_encode((unsigned char*)buffer, len);
  if (encrypted_pass->username == NULL)
  {
    goto exit;
  }

  len = encrypt(input->password, strlen(input->password), encrypted_pass->key, 
    key_size, encrypted_pass->iv, buffer);
  if (len == 0)
  {
    goto exit;
  }

  encrypted_pass->password = base_64_encode((unsigned char*)buffer, len);
  if (encrypted_pass->password == NULL)
  {
    goto exit;
  }

  return encrypted_pass;

  exit:
  delete_encrypted_pass_struct(encrypted_pass);
  return NULL;
}

pass_t* decrypt_passdata(const encrypted_pass_t* input)
{
  char* password_buffer = NULL;
  char* username_buffer = NULL;
  size_t decoded_len = 0;

  username_buffer = base_64_decode(input->username, 
    strlen(input->username), &decoded_len);
  if (username_buffer == NULL)
  {
    return NULL;
  }

  pass_t* decrypted_pass = create_pass_struct();

  int len = decrypt(username_buffer, decoded_len, input->key, 
    input->iv, decrypted_pass->username);
  if (len == 0)
  {
    goto exit;
  }

  password_buffer = base_64_decode(input->password, 
  strlen(input->password), &decoded_len);
    if (username_buffer == NULL)
  {
    goto exit;
  }

  len = decrypt(password_buffer, decoded_len, input->key, 
    input->iv, decrypted_pass->password);
  if (len == 0)
  {
    goto exit;
  }

  free(username_buffer);
  free(password_buffer);

  return decrypted_pass;

  exit:
  free(username_buffer);
  free(password_buffer);
  delete_pass_struct(decrypted_pass);
  return NULL;
}