//
// Created by metho on 23.08.2023.
//

#include "openssl_aes.h"

EVP_CIPHER_CTX *en, *de;

// gen 256bit key
int openssl_aes::AES_initialization(const char* keydata, int keydata_len, unsigned char* salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx) {
    int i, nrounds = 14;
    unsigned char aes_key[32];
    unsigned char iv[32];
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt,
                       reinterpret_cast<const unsigned char *>(keydata), keydata_len, nrounds, aes_key, iv);
    if (i != 32) {
        LOGE("Key size is %d bits - should be 256 bits\n", i);
        return -1;
    }

    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit(e_ctx, EVP_aes_256_cbc(), aes_key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit(d_ctx, EVP_aes_256_cbc(), aes_key, iv);

    return 0;
}

unsigned char* openssl_aes::encryptAES(openssl_aes toEnc) {
    unsigned int salt[] = {12345, 54321};

    if( nullptr == toEnc.text )
        return nullptr;

    unsigned char ciphertext[16];
    int ciphertext_len = sizeof ciphertext;

    en = EVP_CIPHER_CTX_new();
    de = EVP_CIPHER_CTX_new();

    if (AES_initialization(toEnc.key, strlen(toEnc.key), (unsigned char *)salt, en, de)) {
        LOGE("Couldn't initialize AES cipher\n");
        LOGV("initializing aes failed");
        return nullptr;
    }
//    LOGI("Initializing AES success");

    encrypted_len = ciphertext_len;

    EVP_EncryptUpdate(en, encrypted_text, &encrypted_len, toEnc.text, toEnc.text_len);

//     EVP_EncryptFinal_ex(en, ciphertext, &ciphertext_len);
//    for(int i = 0; i < ciphertext_len; ++i) {
//        LOGI("EncryptedText[%d]: %c", i, ciphertext[i]);
//    }

    EVP_CIPHER_CTX_free(en);

    return encrypted_text;
}

unsigned char* openssl_aes::decryptAES(openssl_aes toDec) {

    unsigned char plaintext[16];
    int plaintext_len = sizeof plaintext;

    decrypted_len = toDec.text_len;

    //EVP_DecryptInit_ex(de, nullptr, nullptr, nullptr, nullptr);
    EVP_DecryptUpdate(de, decrypted_text, &plaintext_len, toDec.text, toDec.text_len);
    //EVP_DecryptFinal_ex(de, plaintext, &plaintext_len);
//    for(int i = 0; i < plaintext_len; ++i) {
//        LOGV("DecryptedText[%d]: %c", i, plaintext[i]);
//    }
    //LOGV("DecryptedText: %s", plaintext);

    EVP_CIPHER_CTX_free(de);

    return decrypted_text;
}