#ifndef PASS_MANAGER_H
#define PASS_MANAGER_H

#include <stdint.h>

#define USERNAME_LENGHT 128
#define PASSWORD_LENGHT 128

#define PASS_BUFFER_LEN 1024

typedef struct
{
    char username[USERNAME_LENGHT];
    char password[PASSWORD_LENGHT];
} pass_t;

typedef struct
{
    char* password;
    char* username;
    char* key;
    char* iv;
} encrypted_pass_t;

typedef enum 
{
    aes_128_bit = 16,
    aes_192_bit = 24,
    aes_256_bit = 32
} key_size_t;

pass_t* create_pass_struct();
void delete_pass_struct(pass_t* obj);

encrypted_pass_t* create_encrypted_pass_struct();
encrypted_pass_t* create_encrypted_pass_buffer();
void delete_encrypted_pass_struct(encrypted_pass_t* obj);

encrypted_pass_t* encrypt_passdata(const pass_t* input, key_size_t key_size);
pass_t* decrypt_passdata(const encrypted_pass_t* input);

#endif // PASS_MANAGER_H
