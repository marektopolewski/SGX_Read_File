#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_init_ecc_t {
	int ms_retval;
} ms_ecall_init_ecc_t;

typedef struct ms_ecall_decrypt_file_t {
	const char* ms_path;
	size_t ms_path_len;
} ms_ecall_decrypt_file_t;

typedef struct ms_ecall_decrypt_block_t {
	char* ms_buffer;
	int* ms_result;
	size_t ms_cnt;
} ms_ecall_decrypt_block_t;

typedef struct ms_ocall_printf_t {
	const char* ms_str;
} ms_ocall_printf_t;

typedef struct ms_ocall_decrypt_file_t {
	const char* ms_path;
	int* ms_result;
} ms_ocall_decrypt_file_t;

typedef struct ms_ocall_save_result_t {
	const int* ms_value;
} ms_ocall_save_result_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_printf(void* pms)
{
	ms_ocall_printf_t* ms = SGX_CAST(ms_ocall_printf_t*, pms);
	ocall_printf(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_decrypt_file(void* pms)
{
	ms_ocall_decrypt_file_t* ms = SGX_CAST(ms_ocall_decrypt_file_t*, pms);
	ocall_decrypt_file(ms->ms_path, ms->ms_result);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_save_result(void* pms)
{
	ms_ocall_save_result_t* ms = SGX_CAST(ms_ocall_save_result_t*, pms);
	ocall_save_result(ms->ms_value);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[8];
} ocall_table_Enclave = {
	8,
	{
		(void*)(uintptr_t)Enclave_ocall_printf,
		(void*)(uintptr_t)Enclave_ocall_decrypt_file,
		(void*)(uintptr_t)Enclave_ocall_save_result,
		(void*)(uintptr_t)Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t ecall_init_ecc(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_init_ecc_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_decrypt_file(sgx_enclave_id_t eid, const char* path)
{
	sgx_status_t status;
	ms_ecall_decrypt_file_t ms;
	ms.ms_path = path;
	ms.ms_path_len = path ? strlen(path) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_decrypt_block(sgx_enclave_id_t eid, char* buffer, int* result, size_t cnt)
{
	sgx_status_t status;
	ms_ecall_decrypt_block_t ms;
	ms.ms_buffer = buffer;
	ms.ms_result = result;
	ms.ms_cnt = cnt;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

