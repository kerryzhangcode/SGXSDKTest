#include "Enclave2_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_verify_report_t {
	const sgx_report_t* ms_report;
} ms_ecall_verify_report_t;

typedef struct ms_ecall_get_target_info_t {
	sgx_target_info_t* ms_target_info;
} ms_ecall_get_target_info_t;

typedef struct ms_ocall_print_t {
	const char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL sgx_ecall_verify_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_verify_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_verify_report_t* ms = SGX_CAST(ms_ecall_verify_report_t*, pms);
	ms_ecall_verify_report_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_verify_report_t), ms, sizeof(ms_ecall_verify_report_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	const sgx_report_t* _tmp_report = __in_ms.ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;

	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_report != NULL && _len_report != 0) {
		_in_report = (sgx_report_t*)malloc(_len_report);
		if (_in_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_report, _len_report, _tmp_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	ecall_verify_report((const sgx_report_t*)_in_report);

err:
	if (_in_report) free(_in_report);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_target_info(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_target_info_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_target_info_t* ms = SGX_CAST(ms_ecall_get_target_info_t*, pms);
	ms_ecall_get_target_info_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_target_info_t), ms, sizeof(ms_ecall_get_target_info_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_target_info_t* _tmp_target_info = __in_ms.ms_target_info;
	size_t _len_target_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_target_info = NULL;

	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_target_info != NULL && _len_target_info != 0) {
		if ((_in_target_info = (sgx_target_info_t*)malloc(_len_target_info)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_target_info, 0, _len_target_info);
	}
	ecall_get_target_info(_in_target_info);
	if (_in_target_info) {
		if (memcpy_verw_s(_tmp_target_info, _len_target_info, _in_target_info, _len_target_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_target_info) free(_in_target_info);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_ecall_verify_report, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_target_info, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][2];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

