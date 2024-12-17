#ifndef ENCLAVE1_T_H__
#define ENCLAVE1_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_add(int* result, int a, int b);
int ecall_returnInner(void);
void ecall_main(void);
void ecall_generate_report(sgx_target_info_t* target_info, sgx_report_t* report);

sgx_status_t SGX_CDECL print_call(sgx_status_t ret, int result, const char* str);
sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL ocall_sub(int* retval, int a, int b);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
