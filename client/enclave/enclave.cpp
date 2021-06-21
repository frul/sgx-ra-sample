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

sgx_status_t ecall_initialize_ra(sgx_ra_context_t *ctx) {
    sgx_status_t ra_status;
    ra_status = sgx_ra_init(&def_service_public_key, 0, ctx);
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

    //uint8_t a = (uint8_t)"aaa";
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

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
	sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash)
{
	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().

	*get_keys_ret= sgx_ra_get_keys(ctx, type, &k);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

    /*char * out_key = new char[129];
    memset(out_key, 0, 129);
    memcpy(out_key, k, 16);
    ocall_print_string(out_key);*/

	/* Now generate a SHA hash */

	sha_ret = sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) hash); // Sigh.
    


	/* Let's be thorough */

	return sha_ret;
}

