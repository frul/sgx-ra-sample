#include "enclave_t.h"
#include <sgx_utils.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <string>


int generate_random_number() {
    return 420;
}

static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

sgx_status_t ecall_initialize_ra(sgx_ra_context_t *ctx) {
    sgx_status_t ra_status;
    ra_status = sgx_ra_init(&def_service_public_key, 0, ctx);
    return ra_status;
}

int ecall_compute_score(char **arr, size_t len) {
    sgx_ra_key_128_t k;
    sgx_ra_context_t ctx;
    sgx_ra_get_keys(ctx, SGX_RA_KEY_MK, &k);

    int score;

    for (int i = 0; i < len; ++i) {
        std::string s = arr[i];
        uint8_t *encrypted_message = (uint8_t *)s.c_str();
        uint8_t decrypted_message[128] = {0};

        sgx_rijndael128GCM_decrypt(
            &k,
            encrypted_message + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
            128,
            decrypted_message,
            encrypted_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
            NULL, 0,
            (sgx_aes_gcm_128bit_tag_t *) encrypted_message);
        
        std::string decrypted_message_as_string((char*)decrypted_message);
        int element = std::stoi(decrypted_message_as_string);
        score += element;
    }

    memset(k, 0, sizeof(k));
    return score;
}