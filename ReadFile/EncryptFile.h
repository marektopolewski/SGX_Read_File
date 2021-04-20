#ifndef ENCRYPT_FILE_H_
#define ENCRYPT_FILE_H_

#define KEYLEN  16
#define IVLEN   12
#define GMACLEN 16

#include <stdint.h>

struct EncryptionConfig
{
	uint8_t key[KEYLEN];
	uint8_t iv[IVLEN];
	uint8_t gmac[GMACLEN];
};

EncryptionConfig get_enc_config();
void make_encrypted_file(const char * path, const char * enc_path);

#endif // ENCRYPT_FILE_H_
