#include "Enclave1_u.h"
#include <errno.h>

typedef struct ms_ecall_add_t {
	int* ms_result;
	int ms_a;
	int ms_b;
} ms_ecall_add_t;

typedef struct ms_ecall_returnInner_t {
	int ms_retval;
} ms_ecall_returnInner_t;

typedef struct ms_ecall_generate_report_t {
	sgx_target_info_t* ms_target_info;
	sgx_report_t* ms_report;
} ms_ecall_generate_report_t;

typedef struct ms_print_call_t {
	sgx_status_t ms_ret;
	int ms_result;
	const char* ms_str;
} ms_print_call_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_sub_t {
	int ms_retval;
	int ms_a;
	int ms_b;
} ms_ocall_sub_t;

static sgx_status_t SGX_CDECL Enclave1_print_call(void* pms)
{
	ms_print_call_t* ms = SGX_CAST(ms_print_call_t*, pms);
	print_call(ms->ms_ret, ms->ms_result, ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave1_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave1_ocall_sub(void* pms)
{
	ms_ocall_sub_t* ms = SGX_CAST(ms_ocall_sub_t*, pms);
	ms->ms_retval = ocall_sub(ms->ms_a, ms->ms_b);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_Enclave1 = {
	3,
	{
		(void*)Enclave1_print_call,
		(void*)Enclave1_ocall_print,
		(void*)Enclave1_ocall_sub,
	}
};
sgx_status_t Enclave1_ecall_add(sgx_enclave_id_t eid, int* result, int a, int b)
{
	sgx_status_t status;
	ms_ecall_add_t ms;
	ms.ms_result = result;
	ms.ms_a = a;
	ms.ms_b = b;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave1, &ms);
	return status;
}

sgx_status_t Enclave1_ecall_returnInner(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_returnInner_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave1, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Enclave1_ecall_main(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave1, NULL);
	return status;
}

sgx_status_t Enclave1_ecall_generate_report(sgx_enclave_id_t eid, sgx_target_info_t* target_info, sgx_report_t* report)
{
	sgx_status_t status;
	ms_ecall_generate_report_t ms;
	ms.ms_target_info = target_info;
	ms.ms_report = report;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave1, &ms);
	return status;
}

