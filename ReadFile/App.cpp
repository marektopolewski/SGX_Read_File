#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "App.h"
#include "Constants.h"
#include "ErrorSignal.h"

#include "Enclave_u.h"

sgx_enclave_id_t global_eid = 0;

int initialize_enclave()
{
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		ErrorSignal::print_error_message(ret);
		return -1;
	}
	return 0;
}

int destroy_enclave()
{
	sgx_destroy_enclave(global_eid);
	return 0;
}


int SGX_CDECL main(int argc, char *argv[])
{
	// Start enclave
	if (initialize_enclave() < 0)
		goto end_program;
	printf("Enclave started...\n");

	// Decrypt in-enclave
	ecall_decrypt_file(global_eid, FILE_RAW_PATH);

	// Destroy enclave
	destroy_enclave();

end_program:
	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}

