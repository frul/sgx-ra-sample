#include "enclave_t.h"
#include <sgx_utils.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <string>

int myAtoi(char* str, int len)
{
    // Initialize result
    int res = 0;
 
    // Iterate through all characters
    // of input string and update result
    // take ASCII character of corosponding digit and
    // subtract the code from '0' to get numerical
    // value and multiply res by 10 to shuffle
    // digits left to update running total
    for (int i = 0; i < len; ++i)
        res = res * 10 + str[i] - '0';
 
    // return result.
    return res;
}

sgx_status_t ecall_initialize_ra(
    sgx_ra_context_t *ctx,
    uint8_t *key, size_t len) {
    sgx_status_t ra_status;

    sgx_ec256_public_t service_public_key;
    memcpy(service_public_key.gx, key, 32);
    memcpy(service_public_key.gy, &key[32], 32);

    ra_status = sgx_ra_init(&service_public_key, 0, ctx);
    return ra_status;
}

int score;

void ecall_score_element(uint8_t *arr, size_t len, uint8_t *mac, size_t mac_len) {
    sgx_ra_key_128_t k;
    sgx_ra_context_t ctx;
    sgx_status_t op_status;

    op_status = sgx_ra_get_keys(ctx, SGX_RA_KEY_MK, &k);
    if (op_status != SGX_SUCCESS) {
        ocall_print_string("problem with getting key");
        ocall_print_number(op_status);
    }

    uint8_t aes_gcm_iv[12] = {0};

    uint8_t decrypted_message[128] = {0};

    uint8_t my_mac[16];
    memcpy(my_mac, mac, 16);

    op_status = sgx_rijndael128GCM_decrypt(
        &k,
        arr,
        len,
        decrypted_message,
        &aes_gcm_iv[0],
        SGX_AESGCM_IV_SIZE,
        NULL,
        0,
        (const sgx_aes_gcm_128bit_tag_t *)my_mac);
    if (op_status != SGX_SUCCESS) {
        ocall_print_string("problem with decryption");
        ocall_print_number(op_status);
    }
    
    
    std::string decrypted_message_as_string((char*) decrypted_message);
    int element = myAtoi((char*)decrypted_message_as_string.c_str(), 
        strlen(decrypted_message_as_string.c_str()));

    score += element;

    memset(k, 0, sizeof(k));
}

void ecall_start_scoring() {
    score = 0;
}

int ecall_receive_score() {
    int result = score;
    score = 0;
    return result;
}