#include "Enclave1_t.h" // 自动生成的文件
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"
// #include "sgx_report.h"
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


// ECALL 实现
void ecall_add(int *result, int a, int b) {
    *result = a + b; // 简单的加法
}

const int innerNumber = 2;
int ecall_returnInner(){
    return innerNumber;
}

// Seal 实现
sgx_status_t seal(uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data) {
    const size_t sealed_size = sizeof(sgx_sealed_data_t) + plaintext_len;
    sgx_status_t status = sgx_seal_data(0, NULL, plaintext_len, plaintext, sealed_size, sealed_data);
    return status;
}

// Unseal 实现
sgx_status_t unseal(sgx_sealed_data_t* sealed_data, uint8_t* plaintext, uint32_t plaintext_len) {
    sgx_status_t status = sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)plaintext, &plaintext_len);
    return status;
}

void seal_unseal(){
    sgx_status_t status;
    sgx_sealed_data_t sealed_data;
    const int data = 1024;
    const size_t data_size = sizeof(data);
    
    status = seal((uint8_t*)&data, data_size, &sealed_data);
    enclave_printf("Sealed");

    int unsealed_data;
    status = unseal(&sealed_data, (uint8_t*)&unsealed_data, data_size);
    enclave_printf("Unsealed");
    
    if(unsealed_data == data){
        enclave_printf("Success: Sealed(%d) == Unsealed(%d)", data, unsealed_data);
    }
}

// Enclave Report
void ecall_generate_report(sgx_target_info_t* target_info, sgx_report_t* report) {
    sgx_report_data_t report_data = {0};

    // 填充自定义数据（可选）
    const char* custom_data = "I am A";
    memcpy(report_data.d, custom_data, strlen(custom_data));

    // 生成报告
    sgx_status_t status = sgx_create_report(target_info, &report_data, report);
    if (status != SGX_SUCCESS) {
        enclave_printf("(A) Failed to create report");
        return;
    }

    enclave_printf("(A) Report generated successfully");
}


void ecall_main(){
    int res = 0;
    sgx_status_t ret;
    ret = ocall_sub(&res, 10, 4);
    print_call(ret, res, "ocall_sub");
    seal_unseal();
}