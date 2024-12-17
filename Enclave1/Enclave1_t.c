#include "Enclave1_t.h"

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

static sgx_status_t SGX_CDECL sgx_ecall_add(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_t* ms = SGX_CAST(ms_ecall_add_t*, pms);
	ms_ecall_add_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_add_t), ms, sizeof(ms_ecall_add_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_result = __in_ms.ms_result;
	size_t _len_result = sizeof(int);
	int* _in_result = NULL;

	CHECK_UNIQUE_POINTER(_tmp_result, _len_result);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_result != NULL && _len_result != 0) {
		if ( _len_result % sizeof(*_tmp_result) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_result = (int*)malloc(_len_result)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_result, 0, _len_result);
	}
	ecall_add(_in_result, __in_ms.ms_a, __in_ms.ms_b);
	if (_in_result) {
		if (memcpy_verw_s(_tmp_result, _len_result, _in_result, _len_result)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_result) free(_in_result);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_returnInner(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_returnInner_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_returnInner_t* ms = SGX_CAST(ms_ecall_returnInner_t*, pms);
	ms_ecall_returnInner_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_returnInner_t), ms, sizeof(ms_ecall_returnInner_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_returnInner();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_main(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_main();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_generate_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_report_t* ms = SGX_CAST(ms_ecall_generate_report_t*, pms);
	ms_ecall_generate_report_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_generate_report_t), ms, sizeof(ms_ecall_generate_report_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	sgx_target_info_t* _tmp_target_info = __in_ms.ms_target_info;
	size_t _len_target_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_target_info = NULL;
	sgx_report_t* _tmp_report = __in_ms.ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;

	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);
	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_target_info != NULL && _len_target_info != 0) {
		_in_target_info = (sgx_target_info_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_target_info, _len_target_info, _tmp_target_info, _len_target_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	ecall_generate_report(_in_target_info, _in_report);
	if (_in_report) {
		if (memcpy_verw_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_target_info) free(_in_target_info);
	if (_in_report) free(_in_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_add, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_returnInner, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_main, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_generate_report, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][4];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL print_call(sgx_status_t ret, int result, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_print_call_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_print_call_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_print_call_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_print_call_t));
	ocalloc_size -= sizeof(ms_print_call_t);

	if (memcpy_verw_s(&ms->ms_ret, sizeof(ms->ms_ret), &ret, sizeof(ret))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_result, sizeof(ms->ms_result), &result, sizeof(result))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

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

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sub(int* retval, int a, int b)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sub_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sub_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sub_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sub_t));
	ocalloc_size -= sizeof(ms_ocall_sub_t);

	if (memcpy_verw_s(&ms->ms_a, sizeof(ms->ms_a), &a, sizeof(a))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_b, sizeof(ms->ms_b), &b, sizeof(b))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

