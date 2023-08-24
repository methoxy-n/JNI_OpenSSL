//
// Created by metho on 23.08.2023.
//

#ifndef MY_APPLICATION_OPENSSL_AES_H
#define MY_APPLICATION_OPENSSL_AES_H

#include <jni.h>
#include <string>
#include <cstdio>

#include "logdebug.h"
#include "openssl/evp.h"
#include "openssl/err.h"


class openssl_aes {
public:
    unsigned char* text;
    unsigned char* encrypted_text;
    unsigned char* decrypted_text;
    int text_len;
    int encrypted_len;
    int decrypted_len;
    const char* key;

    openssl_aes() {
        text = nullptr;
        encrypted_text = nullptr;
        decrypted_text = nullptr;
        text_len = 0;
        encrypted_len = 0;
        decrypted_len = 0;
        key = "";
    }

    openssl_aes(unsigned char* other_text, int length, const char* key1) {
        text = new unsigned char[length];
        text = other_text;
        encrypted_text = new unsigned char [256];
        decrypted_text = new unsigned char [length];
        text_len = length;
        encrypted_len = 0;
        decrypted_len = 0;
        key = key1;
    }

    openssl_aes& operator = (const openssl_aes& other) {
        if(this != &other) {
            delete[] text;
            delete[] encrypted_text;
            delete[] decrypted_text;
            text = other.text;
            encrypted_text = other.encrypted_text;
            decrypted_text = other.decrypted_text;
            text_len = other.text_len;
            encrypted_len = other.encrypted_len;
            decrypted_len = other.decrypted_len;
            key = other.key;

            return *this;
        }
        return *this;
    }

    openssl_aes(const openssl_aes& other) {
        text = other.text;
        encrypted_text = other.encrypted_text;
        decrypted_text = other.decrypted_text;
        text_len = other.text_len;
        encrypted_len = other.encrypted_len;
        decrypted_len = other.decrypted_len;
        key = other.key;
    }

    static int AES_initialization(const char* keydata, int keydata_len, unsigned char* salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
    void encryptAES(const openssl_aes& set_of_data);
    void decryptAES(const openssl_aes& set_of_data);
};


#endif //MY_APPLICATION_OPENSSL_AES_H
