#include <stdio.h>
#include <iostream>
#include <iomanip> // 用于格式化输出
#include "sgx_urts.h"
#include "sgx_utils.h"
#include "sgx_uae_service.h"
#include "sgx_quote.h"
#include "App.h"
#include "../Enclave1/Enclave1_u.h" // 自动生成的Enclave文件
#include "../Enclave2/Enclave2_u.h" // 自动生成的Enclave文件
#include "./Network.h"

#define ENCLAVE_FILE "enclave1.signed.so"
#define ENCLAVE2_FILE "enclave2.signed.so"

// 全局 Enclave ID
static sgx_enclave_id_t global_eid1 = 1;
static sgx_enclave_id_t global_eid2 = 2;

// 错误处理函数
void print_error_message(sgx_status_t ret) {
    printf("SGX Error: 0x%X\n", ret);
}

void print_token(const uint8_t* arr) {
    for (int i = 0; i < sizeof(arr); i++) {
        printf("%02x ", arr[i]);
    }
    printf("\n");
}

void print_call(sgx_status_t ret, int result, const char* str){
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
    } else {
        printf("%s: %d\n", str, result);
    }
}

// 定义 print 函数
void ocall_print(const char *str) {
     printf("%s\n", str);
}

void print_quote_info(const sgx_quote_t* quote) {
    // 1. Quote Header
    std::cout << "Quote Version: " << quote->version << std::endl;
    std::cout << "Signature Type: " << quote->sign_type << std::endl;

    // 2. ISV Enclave Report
   std::cout << "Report Data: ";
   const sgx_report_data_t& report_data = quote->report_body.report_data;
    for (int i = 0; i < 64; ++i) {
        if (report_data.d[i] == '\0') break; // 碰到 \0 结束打印
        std::cout << static_cast<char>(report_data.d[i]);
    }
    std::cout << std::endl;
}


// 主函数
using namespace std;
int main() {
    printf("start");
    sgx_status_t ret;
    sgx_launch_token_t token = {0};
    int updated = 0;

    // 创建 Enclave
    ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &global_eid1, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }


    sgx_status_t ret2;
    sgx_launch_token_t token2 = {0};
    int updated2 = 0;
    // 创建 Enclave2
    ret2 = sgx_create_enclave(ENCLAVE2_FILE, SGX_DEBUG_FLAG, &token2, &updated2, &global_eid2, NULL);
    if (ret2 != SGX_SUCCESS) {
        print_error_message(ret2);
        return -1;
    }

    // 调用 Enclave1 主函数
    Enclave1_ecall_main(global_eid1);

    // 调用 Enclave 内函数（ECALL）
    int result = 0;
    ret = Enclave1_ecall_add(global_eid1, &result, 8, 4); // 调用 Enclave 的加法函数
    print_call(ret, result, "ecall_add");

    int inner = 0;
    ret = Enclave1_ecall_returnInner(global_eid1, &inner);
    print_call(ret, inner, "ecall_returnInner");

    // 令牌
    // print_token(token);
    // cout << "Updated: " << updated << endl;
    // cout << "Eid: " << global_eid << endl;

    std::cout << "====== SGX Local Attestation ======" << std::endl;
    // Attestation Enclave1 -> Enclave2
    sgx_target_info_t target_info;
    Enclave2_ecall_get_target_info(global_eid2, &target_info);
    // printf("%d\n", target_info.mr_enclave.m[0]);
    sgx_report_t report;
    Enclave1_ecall_generate_report(global_eid1, &target_info, &report);

    char custom_data[64] = {0};
    memcpy(custom_data, report.body.report_data.d, sizeof(custom_data));
    printf("(App) Enclave1 Data: %s\n", custom_data);

    Enclave2_ecall_verify_report(global_eid2, &report);


    std::cout << "====== SGX Quote ======" << std::endl;
    // 获取目标信息
    sgx_report_t report_quote;
    sgx_target_info_t target_info_quote;
    sgx_epid_group_id_t gid;
    sgx_status_t status = sgx_init_quote(&target_info_quote, &gid);
    if (status != SGX_SUCCESS) {
        printf("Failed to initialize quote.\n");
        return -1;
    }
    Enclave1_ecall_generate_report(global_eid1, &target_info_quote, &report_quote);
    // 使用 AESM 服务生成 Quote
    printf("Generating Quote...\n");
    uint32_t quote_size = 0;
    status = sgx_calc_quote_size(NULL, 0, &quote_size);
    if (status != SGX_SUCCESS) {
        printf("Failed to calculate quote size.\n");
        return -1;
    }

    sgx_quote_t *quote;
    sgx_quote_sign_type_t sign_type = SGX_LINKABLE_SIGNATURE;
    quote = (sgx_quote_t*)malloc(quote_size);
    sgx_spid_t spid = {0};          // Service provider ID (replace with your SPID in production mode)
    status = sgx_get_quote(&report_quote, sign_type, &spid, NULL, NULL, NULL, NULL, quote, quote_size);
    if (status != SGX_SUCCESS) {
        printf("Failed to generate quote.\n");
        return -1;
    }

    printf("Quote generated successfully! Size: %u bytes\n", quote_size);

    // send_quote_to_ias(reinterpret_cast<const uint8_t*>(quote), quote_size);
    print_quote_info(quote);

    free(quote);
    // 销毁 Enclave
    sgx_destroy_enclave(global_eid1);
    sgx_destroy_enclave(global_eid2);
    return 0;
}

// 外部减法
int ocall_sub(int a, int b){
    return a - b;
}
