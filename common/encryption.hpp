#include "key.hpp"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors() {
    std::cout << "there was an error in cypher" << std::endl;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    unsigned char iv_[16];
    memset(iv_, 0, 16);

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv_))
        handleErrors();

    /*  
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    /*std::string plain(plaintext, plaintext + plaintext_len);
    std::string out(ciphertext, ciphertext +ciphertext_len);
    std::cout << "in: " << plain << std::endl;
    std::cout << "out: ";
    //print_hexstring(out.c_str(),ciphertext_len );
    std::cout << "out_len : " << ciphertext_len << std::endl;*/

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    unsigned char iv_[16];
    memset(iv_, 0, 16);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv_))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

std::string encrypt_message(const std::string& str, unsigned char *key) {
    unsigned char ciphertext[128];
    //std::cout << str << " ";
    int ciphertext_len = encrypt ((unsigned char*)str.c_str(), str.length(), key, nullptr,
                              ciphertext);
    ciphertext[ciphertext_len] = '\0';
    //std::cout << ciphertext_len << std::endl;
    return (char*)ciphertext;
}

int decrypt_message(const std::string& str, unsigned char *key) {
    unsigned char decryptedtext[128];
    int decryptedtext_len = decrypt((unsigned char*)str.c_str(), str.length(), key, nullptr,
                                decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';
    int num;
    std::stringstream ss((char*)decryptedtext);
    ss >> num;
    return num;
}

void encrypt_example()
{
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char *key = getPublicKey();

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"20";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext);


    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);
}




void my_encrypt(const uint8_t *p_key, const uint8_t *p_src, uint32_t src_len,
                uint8_t *p_dst, int &out_len, uint8_t *p_out_mac)
{
	/*if ((src_len >= INT_MAX) ||  || (p_key == NULL) || ((src_len > 0) && (p_dst == NULL)) || ((src_len > 0) && (p_src == NULL))
		|| (p_out_mac == NULL) || (iv_len != SGX_AESGCM_IV_SIZE) || ((aad_len > 0) && (p_aad == NULL))
		|| (p_iv == NULL) || ((p_src == NULL) && (p_aad == NULL)))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}*/
	EVP_CIPHER_CTX * pState = NULL;
    int ciphertext_len;

	do {
		// Create and init ctx
		//
		if (!(pState = EVP_CIPHER_CTX_new())) {
			std::cout << "out of memory" << std::endl;
			break;
		}

		// Initialise encrypt, key and IV
		//
        uint8_t iv[12];
        memset(iv, 0, 12);
		if (1 != EVP_EncryptInit_ex(pState, EVP_aes_128_gcm(), NULL, (unsigned char*)p_key, iv)) {
			std::cout << "bad" << std::endl;
            break;
		}

        if (src_len > 0) {
            // Provide the message to be encrypted, and obtain the encrypted output.
            //
            if (1 != EVP_EncryptUpdate(pState, p_dst, &out_len, p_src, src_len)) {
                std::cout << "bad bad" << std::endl;
                break;
            }
            ciphertext_len = out_len;    
        }
		// Finalise the encryption
		//
		if (1 != EVP_EncryptFinal_ex(pState, p_dst + out_len, &out_len)) {
			std::cout << "bad 3" << std::endl;
            break;
		}
        ciphertext_len += out_len;
        out_len = ciphertext_len;

		// Get tag
		//
		if (1 != EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_GCM_GET_TAG, 16, p_out_mac)) {
            std::cout << "bad 4" << std::endl;
			break;
		}
	} while (0);

	// Clean up and return
	//
	if (pState) {
			EVP_CIPHER_CTX_free(pState);
	}
}

void my_encrypt_cpp(const std::string& in, std::string& out, std::string& mac, uint8_t* key) {
    const uint8_t* p_src = (uint8_t*)in.c_str();
    uint32_t src_len = strlen(in.c_str());
    uint8_t p_dst[128] = {0};
    int out_len = 0;
    uint8_t p_mac[16] = {0};

    my_encrypt(key, p_src, src_len, p_dst, out_len, p_mac);
    out = std::string(p_dst, p_dst + out_len);

    mac = std::string(p_mac, p_mac + 16);
}