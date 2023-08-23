//
// Created by metho on 23.08.2023.
//

#ifndef MY_APPLICATION_OPENSSL_TDES_H
#define MY_APPLICATION_OPENSSL_TDES_H

#include <jni.h>
#include <string>
#include <mntent.h>
#include <unistd.h>
#include <cstdio>

#include "logdebug.h"
#include "openssl/des.h"
#include "openssl/rand.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/bio.h"

class openssl_tdes {
public:
    unsigned char* text;
    unsigned char* encrypted_text;
    unsigned char* decrypted_text;
    int text_len;
    int encrypted_len;
    int decrypted_len;

    openssl_tdes() {
        text = nullptr;
        encrypted_text = nullptr;
        decrypted_text = nullptr;
        text_len = 0;
        encrypted_len = 0;
        decrypted_len = 0;
    }

    openssl_tdes(unsigned char* other_text, int length) {
        text = new unsigned char[length];
        text = other_text;
        encrypted_text = new unsigned char [256];
        decrypted_text = new unsigned char [length];
        text_len = length;
        encrypted_len = 0;
        decrypted_len = 0;
    }

    openssl_tdes& operator = (const openssl_tdes& other) {
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

            return *this;
        }
        return *this;
    }

    openssl_tdes(const openssl_tdes& other) {
        text = other.text;
        encrypted_text = other.encrypted_text;
        decrypted_text = other.decrypted_text;
        text_len = other.text_len;
        encrypted_len = other.encrypted_len;
        decrypted_len = other.decrypted_len;
    }

    int TDES_initialization(EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
    unsigned char* encryptTDES(openssl_tdes set_of_data);
    unsigned char* decryptTDES(openssl_tdes set_of_data);
};


#endif //MY_APPLICATION_OPENSSL_TDES_H
