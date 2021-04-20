#include "Enclave_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"

#include <string.h>

sgx_ecc_state_handle_t ctx;
sgx_ec256_private_t privkey;
sgx_ec256_public_t pubkey;

int ecall_init_ecc()
{
	sgx_status_t status;
	status = sgx_ecc256_open_context(&ctx);
	if (status != SGX_SUCCESS)
		return -1;

	status = sgx_ecc256_create_key_pair(&privkey, &pubkey, ctx);
	if (status != SGX_SUCCESS)
		return -1;
	
	return 0;
}

void ecall_decrypt_file(const char * path)
{
	ocall_printf(path);
	int result;
	ocall_decrypt_file(path, &result);
	ocall_save_result(&result);
}

void ecall_decrypt_block(char * buffer, int * result, size_t cnt)
{
	ocall_printf(buffer);
	*result = 1;
}
