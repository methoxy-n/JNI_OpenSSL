//
// Created by metho on 23.08.2023.
//

#include "openssl_tdes.h"

void select_random_key(unsigned char *key, int b) {
    int i;
    RAND_bytes(key, b);
    for (i = 0; i < b - 1; i++)
        printf("%02X:",key[i]);
    printf("%02X\n\n", key[b - 1]);
}

void select_random_iv (unsigned char *iv, int b) {
    RAND_bytes (iv, b);
}

EVP_CIPHER_CTX *enc, *dec;

// gen 256bit key
int openssl_tdes::TDES_initialization(EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx) {
//    int i, nrounds = 32;
    unsigned char key_data[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    select_random_key(key_data, EVP_MAX_KEY_LENGTH);
    select_random_iv(iv, EVP_MAX_IV_LENGTH);

//    i = EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), salt,key_data, EVP_MAX_KEY_LENGTH, nrounds, key_data, iv);
//    if (i != 32) {
//        LOGE("Key size is %d bits - should be %d bits\n", i, EVP_MAX_KEY_LENGTH);
//        return -1;
//    }

    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit(e_ctx, EVP_des_ede3_cbc(), key_data, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit(d_ctx, EVP_des_ede3_cbc(), key_data, iv);

    return 0;
}

void openssl_tdes::encryptTDES(const openssl_tdes& toEnc) {
    //unsigned int salt[] = {12345, 54321};
    if( nullptr == toEnc.text )
        return;

    enc = EVP_CIPHER_CTX_new();
    dec = EVP_CIPHER_CTX_new();

    TDES_initialization(enc, dec);
//    LOGI("Initializing TDES success");

    encrypted_len = toEnc.text_len;

    EVP_EncryptUpdate(enc, encrypted_text, &encrypted_len, toEnc.text, toEnc.text_len);

//     EVP_EncryptFinal_ex(en, ciphertext, &ciphertext_len);
//    for(int i = 0; i < ciphertext_len; ++i) {
//        LOGI("EncryptedText[%d]: %c", i, ciphertext[i]);
//    }
    EVP_CIPHER_CTX_free(enc);
    //return encrypted_text;
}

void openssl_tdes::decryptTDES(const openssl_tdes& toDec) {

    decrypted_len = toDec.text_len;

    //EVP_DecryptInit_ex(de, nullptr, nullptr, nullptr, nullptr);
    EVP_DecryptUpdate(dec, decrypted_text, &decrypted_len, toDec.text, toDec.text_len);
    //EVP_DecryptFinal_ex(de, plaintext, &plaintext_len);
//    for(int i = 0; i < plaintext_len; ++i) {
//        LOGV("DecryptedText[%d]: %c", i, plaintext[i]);
//    }
    //LOGV("DecryptedText: %s", plaintext);

    EVP_CIPHER_CTX_free(dec);

    //return decrypted_text;
}