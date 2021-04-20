#include "Constants.h"
#include "OCalls.h"

#include <stdio.h>

void ocall_printf(const char * str)
{
	printf("[ENCLAVE] %s\n", str);
}

void ocall_decrypt_file(const char * path, int * result)
{
	FILE * file_to_read;
	fopen_s(&file_to_read, path, "rb");
	if (file_to_read == NULL) {
		*result = 0;
		return;
	}

	int acc_res = 0;
	char read_buffer[READ_BUFFER_SIZE + 1] = "";
	while (!feof(file_to_read)) {
		size_t size_read = fread(read_buffer, sizeof(char), READ_BUFFER_SIZE, file_to_read);
		read_buffer[size_read * sizeof(char)] = '\0';
		int block_res;
		ecall_decrypt_block(global_eid, read_buffer, &block_res, size_read + 1);
		acc_res += block_res;
	}
	fclose(file_to_read);

	*result = acc_res;
}

void ocall_save_result(const int * value)
{
	FILE * file_to_write;
	fopen_s(&file_to_write, "result.txt", "w");
	if (file_to_write == NULL) {
		printf("Could not save the result.");
		return;
	}
	printf("[ENCLAVE] result = %d\n", *value);
	fprintf(file_to_write, "%d", *value);
	fclose(file_to_write);
}