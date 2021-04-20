#include "EncryptFile.h"
#include "Constants.h"

#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include <stdio.h>

/*EncryptionConfig get_enc_config()
{
	uint8_t key[KEYLEN], iv[IVLEN], gmac[GMACLEN];
	sgx_read_rand(key, KEYLEN);
	sgx_read_rand(iv, IVLEN);
	for (int i = 0; i < GMACLEN; ++i)
		gmac[i] = 0;
	return { key[0], iv, gmac };
}

void make_encrypted_file(const char * path, const char * enc_path)
{
	// Open file with data to encrypt
	FILE * raw_file;
	fopen_s(&raw_file, path, "rb");
	if (raw_file == NULL) {
		return;
	}

	// Open file to save encrypted data
	FILE * enc_file;
	fopen_s(&enc_file, FILE_ENC_PATH, "wb");
	if (enc_file == NULL) {
		fclose(raw_file);
		return;
	}
	enc_path = FILE_ENC_PATH;

	// Create encryption metadata
	const uint8_t key[KEYLEN] = { '1' };
	const EncryptionConfig config = get_enc_config();

	// Read and encrypt data in block mode
	uint8_t raw_buffer[READ_BUFFER_SIZE] = "";
	uint8_t enc_buffer[READ_BUFFER_SIZE] = "";
	while (!feof(raw_file)) {
		size_t size_read = fread(raw_buffer, sizeof(char), READ_BUFFER_SIZE, raw_file);
		sgx_rijndael128GCM_encrypt(key, raw_buffer, READ_BUFFER_SIZE, enc_buffer, &(config.iv)[0], 12, NULL, 0, &(config.gmac)[0]);
	}
	fclose(raw_file);
	fclose(enc_file);
}*/
