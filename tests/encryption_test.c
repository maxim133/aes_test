#include "../pass_manager.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(int argc, char const *argv[])
{
  const char* decrypted_username = "root";
  const char* decrypted_password = "root";

  assert(strlen(decrypted_username) <= USERNAME_LENGHT);
  assert(strlen(decrypted_password) <= PASSWORD_LENGHT);

  pass_t* pass_data = create_pass_struct();

  strcpy(pass_data->username, decrypted_username);
  strcpy(pass_data->password, decrypted_password);

  encrypted_pass_t* encrypted_pass = encrypt_passdata(pass_data, aes_128_bit);
  if (encrypted_pass == NULL)
  {
    printf("Encryption error\n");

    return 1;
  }

  pass_t* result = decrypt_passdata(encrypted_pass);
  if (result == NULL)
  {
    printf("Decryption error\n");

    return 1;
  }

  if (strncmp(result->username, decrypted_username, strlen(decrypted_username)) != 0)
  {
    printf("Username fields isn't equals\n");

    return 1;
  }

  if (strncmp(result->password, decrypted_password, strlen(decrypted_username)) != 0)
  {
    printf("Password fields isn't equals\n");

    return 1;
  }

  return 0;
}