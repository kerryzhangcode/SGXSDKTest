#ifndef ENCLAVE2_U_H__
#define ENCLAVE2_U_H__

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

#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (const char* str));
#endif

sgx_status_t Enclave2_ecall_verify_report(sgx_enclave_id_t eid, const sgx_report_t* report);
sgx_status_t Enclave2_ecall_get_target_info(sgx_enclave_id_t eid, sgx_target_info_t* target_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
