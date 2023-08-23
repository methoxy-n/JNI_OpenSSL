//
// Created by metho on 18.08.2023.
//

#include "openssl_rsa.h"

/********************************* RSA ENC/DEC *********************************/

RSA *openssl_rsa::createRSApriv(std::string sKey) {
    RSA *rsa = nullptr;
    BIO *keybio;
    keybio = BIO_new_mem_buf(sKey.c_str(), sKey.length());
    if (keybio == nullptr) {
        printf( "Failed to create key BIO");
        return nullptr;
    }
    else rsa = PEM_read_bio_RSAPrivateKey(keybio, nullptr,nullptr, nullptr);
    if(RSA_check_key(rsa) == 1)
        LOGI("Private key is valid = %d", RSA_check_key(rsa));
    else
        LOGE("Invalid private key");

    return rsa;
}
RSA *openssl_rsa::createRSApub(std::string sKey) {
    RSA *rsa = nullptr;
    BIO *keybio;
    keybio = BIO_new_mem_buf(sKey.c_str(), sKey.length());

    if (keybio == nullptr) {
        printf( "Failed to create key BIO");
        return nullptr;
    }
    else  rsa = PEM_read_bio_RSA_PUBKEY(keybio, nullptr,nullptr, nullptr);

    return rsa;
}

unsigned char* openssl_rsa::encryptRSA(openssl_rsa plain, std::string mode) {
    //unsigned char* plain_text = plain;

    if(text == nullptr) {
        LOGE("No text");
        return nullptr;
    }

    unsigned char chEncryptedData[256] = {};
    int chEncryptedData_len = sizeof chEncryptedData;
    encrypted_len = chEncryptedData_len;
    for(int i = 0; i < 256; ++i)
        encrypted_text[i] = 0;
    //for(int i = 0; i < chEncryptedData_len; ++i) chEncryptedData[i] = 0;

    std::string pub_mode((char*) "Public");
    std::string priv_mode((char*) "Private");

    int iResult;

    if(mode == pub_mode)
        iResult = RSA_public_encrypt(plain.text_len, plain.text, encrypted_text, createRSApub(plain.key), RSA_PKCS1_PADDING);
    if(mode == priv_mode)
        iResult = RSA_private_encrypt(plain.text_len, plain.text, encrypted_text, createRSApriv(plain.key), RSA_PKCS1_PADDING);
    //else LOGE("Choose right mode --- Public / Private");
//    env->ReleaseStringUTFChars(env, inData, cData);

// If encryption fails, returns nullptr string, else returns encrypted string

    if(-1 == iResult) {
        char *chErrMsg = (char*)malloc(256);
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), chErrMsg);
        LOGE("The data Encryption failed due to the reason : %s", chErrMsg);
        free(chErrMsg);
        return nullptr;
    }

   // encrypted_text = chEncryptedData;
//    strcpy(reinterpret_cast<char *const>(plain.encrypted_text),
//           reinterpret_cast<const char *>(chEncryptedData));

    //LOGV("Encrypted: %s", plain.encrypted_text);

    return encrypted_text;
}

unsigned char* openssl_rsa::decryptRSA(openssl_rsa set_of_data, std::string mode) {
//    unsigned char chDecryptedData[256];
//    int chDecryptedData_len = sizeof chDecryptedData;

    std::string pub_mode((char*) "Public");
    std::string priv_mode((char*) "Private");

    set_of_data.encrypted_len = set_of_data.text_len;
    decrypted_len = set_of_data.text_len - 11; // -11 because of RSA_PKCS1_PADDING

    int result;
    if(mode == pub_mode)
        result = RSA_public_decrypt(set_of_data.encrypted_len,set_of_data.text, decrypted_text, createRSApub(set_of_data.key), RSA_PKCS1_PADDING);
    if(mode == priv_mode)
        result = RSA_private_decrypt(set_of_data.encrypted_len,set_of_data.text, decrypted_text, createRSApriv(set_of_data.key), RSA_PKCS1_PADDING);
//    else
//        LOGE("Choose right mode --- Public / Private");

    if(-1 == result) {
        char *chErrMsg = (char*)malloc(256);
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), chErrMsg);
        LOGE("The data Decryption failed due to the reason : %s", chErrMsg);
        free(chErrMsg);
        return nullptr;
    }

//      set_of_data.decrypted_text = chDecryptedData;
//    strcpy(reinterpret_cast<char *const>(set_of_data.decrypted_text),
//           reinterpret_cast<const char *>(chDecryptedData));

    return decrypted_text;
}


/********************************* END RSA *********************************/
