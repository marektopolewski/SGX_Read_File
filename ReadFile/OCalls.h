#ifndef OCALLS_H_
#define OCALLS_H_

#include "Enclave_u.h"

void ocall_printf(const char * str);
void ocall_decrypt_file(const char * path, int * result);
void ocall_save_result(const int * value);

#endif // OCALLS_H_
