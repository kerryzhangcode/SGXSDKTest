#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "Enclave2_t.h" // 包含 ECALL 的声明
#include "sgx_utils.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>  // for malloc, free
#include <string.h>  // for memcpy, strlen
// Encalve Printf
void enclave_printf(const char* format, ...) {
    va_list args;

    // 计算所需的缓冲区大小
    va_start(args, format);
    int required_size = vsnprintf(NULL, 0, format, args) + 1; // 加1以容纳终止符
    va_end(args);

    // 动态分配缓冲区
    char* buffer = (char*)malloc(required_size);
    if (!buffer) {
        // 如果分配失败，直接返回
        return;
    }

    // 格式化字符串
    va_start(args, format);
    vsnprintf(buffer, required_size, format, args);
    va_end(args);

    // 调用 OCALL
    ocall_print(buffer);

    // 释放缓冲区
    free(buffer);
}

void ecall_get_target_info(sgx_target_info_t* target_info) {
    sgx_status_t status = sgx_self_target(target_info);
    if (status != SGX_SUCCESS) {
        ocall_print("Failed to get target info from Enclave2.");
    } else {
        ocall_print("Target info retrieved successfully.");
    }
}

void ecall_verify_report(const sgx_report_t* report) {
    // 验证报告的真实性
    sgx_status_t status = sgx_verify_report(report);
    if (status != SGX_SUCCESS) {
        // 报告验证失败
        enclave_printf("(B) Report verification failed.");
        return;
    }

    // 验证通过，解析自定义数据
    enclave_printf("(B) Report verification succeeded.");

    // 解析报告中的自定义数据
    const sgx_report_data_t* report_data = &report->body.report_data;
    char custom_data[64] = {0};
    memcpy(custom_data, report_data->d, sizeof(custom_data));

    enclave_printf("(B) Custom data received: %s", custom_data);
}