//
// Created by metho on 21.08.2023.
//

#ifndef MY_APPLICATION_OPENSSL_RSA_H
#define MY_APPLICATION_OPENSSL_RSA_H

#include <jni.h>
#include <string>
#include <mntent.h>
#include <unistd.h>
#include <cstdio>

#include "logdebug.h"
#include "openssl/rand.h"
#include "openssl/sha.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/ossl_typ.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/des.h"

class openssl_rsa {
public:
    unsigned char* text;
    unsigned char* encrypted_text;
    unsigned char* decrypted_text;
    int text_len;
    int encrypted_len;
    int decrypted_len;
    std::string key;

    openssl_rsa() {
        text = nullptr;
        encrypted_text = nullptr;
        decrypted_text = nullptr;
        text_len = 0;
        encrypted_len = 0;
        decrypted_len = 0;
        key = "";
    }

    openssl_rsa(unsigned char* other_text, int length, std::string key1) {
        text = new unsigned char[length];
        text = other_text;
        encrypted_text = new unsigned char [256];
        decrypted_text = new unsigned char [length];
        text_len = length;
        encrypted_len = 0;
        decrypted_len = 0;
        key = key1;
    }

    openssl_rsa& operator = (const openssl_rsa& other) {
        if(this != &other) {
            text = other.text;
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

    openssl_rsa(const openssl_rsa& other) {
        text = other.text;
        text = other.text;
        encrypted_text = other.encrypted_text;
        decrypted_text = other.decrypted_text;
        text_len = other.text_len;
        encrypted_len = other.encrypted_len;
        decrypted_len = other.decrypted_len;
        key = other.key;
    }

    RSA * createRSApriv(std::string sKey);
    RSA * createRSApub(std::string sKey);
    unsigned char* encryptRSA(openssl_rsa set_of_data, std::string mode);
    unsigned char* decryptRSA(openssl_rsa set_of_data, std::string mode);

//    ~openssl_rsa() {
//        delete[] text;
//        text = nullptr;
//        delete[] encrypted_text;
//        encrypted_text = nullptr;
//        delete decrypted_text;
//        decrypted_text = nullptr;
//    };
};

#endif //MY_APPLICATION_OPENSSL_RSA_H
