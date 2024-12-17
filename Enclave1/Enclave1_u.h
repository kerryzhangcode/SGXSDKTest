#ifndef ENCLAVE1_U_H__
#define ENCLAVE1_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PRINT_CALL_DEFINED__
#define PRINT_CALL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_call, (sgx_status_t ret, int result, const char* str));
#endif
#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif
#ifndef OCALL_SUB_DEFINED__
#define OCALL_SUB_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sub, (int a, int b));
#endif

sgx_status_t Enclave1_ecall_add(sgx_enclave_id_t eid, int* result, int a, int b);
sgx_status_t Enclave1_ecall_returnInner(sgx_enclave_id_t eid, int* retval);
sgx_status_t Enclave1_ecall_main(sgx_enclave_id_t eid);
sgx_status_t Enclave1_ecall_generate_report(sgx_enclave_id_t eid, sgx_target_info_t* target_info, sgx_report_t* report);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
