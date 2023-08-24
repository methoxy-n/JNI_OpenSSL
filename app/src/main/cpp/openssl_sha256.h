//
// Created by metho on 24.08.2023.
//

#ifndef MY_APPLICATION_OPENSSL_SHA256_H
#define MY_APPLICATION_OPENSSL_SHA256_H

#include "openssl/sha.h"

class openssl_sha256 {
    public:
        unsigned char* text;
        int text_length;
        unsigned char hash[SHA256_DIGEST_LENGTH];

        openssl_sha256() {
            text = nullptr;
            text_length = 0;
        }
        openssl_sha256(unsigned char* param, int length) {
            text = param;
            text_length = length;
        }
        openssl_sha256& operator = (const openssl_sha256& other) {
            if(this != &other) {
                delete[] text;
                text = nullptr;
                text = other.text;
                text_length = other.text_length;
                for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                    hash[i] = other.hash[i];
                return *this;
            }
            return *this;
        }

        openssl_sha256(const openssl_sha256& other) {
            text = other.text;
            text_length = other.text_length;
            for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                hash[i] = other.hash[i];
        }

        void SHA256(openssl_sha256 obj);
};


#endif //MY_APPLICATION_OPENSSL_SHA256_H
