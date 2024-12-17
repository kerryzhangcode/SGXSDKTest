#include <curl/curl.h>
#include <stdio.h>
#include <iostream>

#define IAS_URL "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report"
#define API_KEY "xxxx"

std::string base64_encode(const uint8_t *data, size_t input_length) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    int i = 0, j = 0;
    uint8_t char_array_3[3], char_array_4[4];

    while (input_length--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                encoded += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            encoded += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            encoded += '=';
    }

    return encoded;
}

int send_quote_to_server(const uint8_t *quote, uint32_t quote_size) {
    CURL *curl;
    CURLcode res;
    std::string response_string;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        printf("Failed to initialize CURL.\n");
        return -1;
    }

    // Convert quote to base64 or hex string if required
    // char *encoded_quote = base64_encode(quote, quote_size);
    std::string encoded_quote = base64_encode(reinterpret_cast<const uint8_t*>(quote), quote_size);

    // Set up HTTP POST request
    curl_easy_setopt(curl, CURLOPT_URL, "https://your-service-provider/verify_quote");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encoded_quote.size());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, encoded_quote.size());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

    // Perform the request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("Failed to send quote: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }
     else {
        // 打印 HTTP 响应结果
        std::cout << "HTTP Response:\n" << response_string << std::endl;
    }

    printf("Quote successfully sent to service provider.\n");

    // Cleanup
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}

// 发送 Quote 的函数
int send_quote_to_ias(const uint8_t *quote, uint32_t quote_size) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;

    // 将 Quote 编码为 Base64
    std::string encoded_quote = base64_encode(quote, quote_size);

    // 设置 HTTP 头
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ("Ocp-Apim-Subscription-Key: " + std::string(API_KEY)).c_str());

    // 构建 JSON 请求体
    std::string json_payload = "{\"isvEnclaveQuote\":\"" + encoded_quote + "\"}";

    // 初始化 CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL.\n";
        return -1;
    }

    // 设置 CURL 选项
    curl_easy_setopt(curl, CURLOPT_URL, IAS_URL);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, json_payload.size());

    // 启用调试输出
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    // 执行 HTTP 请求
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "Failed to send Quote to IAS: " << curl_easy_strerror(res) << "\n";
    } else {
        std::cout << "Quote successfully sent to IAS.\n";
    }

    // 清理资源
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return res == CURLE_OK ? 0 : -1;
}