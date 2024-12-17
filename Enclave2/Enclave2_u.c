#include "Enclave2_u.h"
#include <errno.h>

typedef struct ms_ecall_verify_report_t {
	const sgx_report_t* ms_report;
} ms_ecall_verify_report_t;

typedef struct ms_ecall_get_target_info_t {
	sgx_target_info_t* ms_target_info;
} ms_ecall_get_target_info_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL Enclave2_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave2 = {
	1,
	{
		(void*)Enclave2_ocall_print,
	}
};
sgx_status_t Enclave2_ecall_verify_report(sgx_enclave_id_t eid, const sgx_report_t* report)
{
	sgx_status_t status;
	ms_ecall_verify_report_t ms;
	ms.ms_report = report;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave2, &ms);
	return status;
}

sgx_status_t Enclave2_ecall_get_target_info(sgx_enclave_id_t eid, sgx_target_info_t* target_info)
{
	sgx_status_t status;
	ms_ecall_get_target_info_t ms;
	ms.ms_target_info = target_info;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave2, &ms);
	return status;
}

