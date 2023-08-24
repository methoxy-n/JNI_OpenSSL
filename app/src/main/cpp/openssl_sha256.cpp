//
// Created by metho on 24.08.2023.
//

#include "openssl_sha256.h"

void openssl_sha256::SHA256(openssl_sha256 obj) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, obj.text, obj.text_length);
    SHA256_Final(hash, &sha256);
}