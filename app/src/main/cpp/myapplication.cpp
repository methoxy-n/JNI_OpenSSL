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


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_MainActivity_calculateHash(JNIEnv *env, jobject thiz,
                                                          jbyteArray plain_array) {
    (void)thiz;

    jsize len = env->GetArrayLength(plain_array);

    //jbyte into c++ char
    jboolean isCopy;
    jbyte* a = env->GetByteArrayElements(plain_array,&isCopy);
    char* b;
    b = (char*) a;

    // make hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, b, len);
    SHA256_Final(hash, &sha256);

//    for (int i = 0; i < 32; ++i) {
//        LOGI("%02X", hash[i]); // print each hash byte via log
//    }

    // unsigned char hash into jbyteArray j_hash_array
    jbyteArray j_hash_array = env->NewByteArray(SHA256_DIGEST_LENGTH);
    env->SetByteArrayRegion(j_hash_array, 0, SHA256_DIGEST_LENGTH, (jbyte *) hash);

    // return hash as result
    return j_hash_array;
}

/********************************* AES_256 ENC/DEC *********************************/

EVP_CIPHER_CTX *en, *de;

// gen 256bit key
int AES_initialization(const char* keydata, int keydata_len, unsigned char* salt, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx) {
    int i, nrounds = 14;
    unsigned char key[32];
    unsigned char iv[32];
    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt,
                       reinterpret_cast<const unsigned char *>(keydata), keydata_len, nrounds, key, iv);
    if (i != 32) {
        LOGE("Key size is %d bits - should be 256 bits\n", i);
        return -1;
    }

    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit(e_ctx, EVP_aes_256_cbc(), key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit(d_ctx, EVP_aes_256_cbc(), key, iv);

    return 0;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_MainActivity_encryptAes256(JNIEnv *env, jobject thiz, jbyteArray key,
                                                          jbyteArray plain_text) {
    unsigned int salt[] = {12345, 54321};

    jboolean isCopy;
    jbyte* keyData = env->GetByteArrayElements(key, &isCopy);
    const char* key_data;
    key_data = (const char*) keyData;
    int key_data_len = strlen(key_data);

    int plainText_len = env->GetArrayLength(plain_text);
    jbyte* temp = env->GetByteArrayElements(plain_text,&isCopy);
    unsigned char* plainText;
    plainText = (unsigned char*) temp;
    plainText_len = strlen((char*)plainText);

    if( nullptr == plainText )
        return nullptr;

    unsigned char ciphertext[16];
    int ciphertext_len = sizeof ciphertext;

    en = EVP_CIPHER_CTX_new();
    de = EVP_CIPHER_CTX_new();

    if (AES_initialization(key_data, key_data_len, (unsigned char *)salt, en, de)) {
        LOGE("Couldn't initialize AES cipher\n");
        LOGV("initializing aes failed");
        return nullptr;
    }
    LOGD("initializing aes success");

    EVP_EncryptUpdate(en, ciphertext, &ciphertext_len, plainText, plainText_len);
   // EVP_EncryptFinal_ex(en, ciphertext, &ciphertext_len);
    for(int i = 0; i < ciphertext_len; ++i) {
        LOGI("EncryptedText[%d]: %c", i, ciphertext[i]);
    }
    // LOGV("EncryptedData: %s", ciphertext);
    jbyteArray encryptedByteArray = env->NewByteArray(ciphertext_len);
    env->SetByteArrayRegion(encryptedByteArray, 0, ciphertext_len, (jbyte *) ciphertext);

    EVP_CIPHER_CTX_free(en);

    return encryptedByteArray;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_MainActivity_decryptAes256(JNIEnv *env, jobject thiz, jbyteArray key,
                                                          jbyteArray enc_text) {
    jboolean isCopy;
    jbyte* keyData = env->GetByteArrayElements(key, &isCopy);
    const char* key_data;
    key_data = (const char*) keyData;
    int key_data_len = strlen(key_data);

    jbyte* encryptedText = env->GetByteArrayElements(enc_text, &isCopy);
    unsigned char * encText;
    encText = (unsigned char*) encryptedText;
    int encText_len = strlen((char*)encText);

    unsigned char plaintext[16];
    int plaintext_len = sizeof plaintext;

    //EVP_DecryptInit_ex(de, nullptr, nullptr, nullptr, nullptr);
    EVP_DecryptUpdate(de, plaintext, &plaintext_len, encText, encText_len);
    //EVP_DecryptFinal_ex(de, plaintext, &plaintext_len);
    for(int i = 0; i < plaintext_len; ++i) {
        LOGV("DecryptedText[%d]: %c", i, plaintext[i]);
    }
    //LOGV("DecryptedText: %s", plaintext);

    jbyteArray decryptedByteArray = env->NewByteArray(plaintext_len);
    env->SetByteArrayRegion(decryptedByteArray, 0, plaintext_len, (jbyte *) plaintext);

    EVP_CIPHER_CTX_free(de);

    return decryptedByteArray;
}
/********************************* END AES *********************************/

/********************************* RSA ENC/DEC *********************************/

void replace_first(
        std::string& s,
        std::string const& toReplace,
        std::string const& replaceWith
) {
    std::size_t pos = s.find(toReplace);
    if (pos == std::string::npos) return;
    s.replace(pos, toReplace.length(), replaceWith);
}

//RSA * createRSA(unsigned char* key, int mode) {
//    RSA *rsa= NULL;
//    BIO *keybio ;
//    keybio = BIO_new_mem_buf(key, -1);
//    if (keybio==NULL)
//    {
//        LOGE( "Failed to create key BIO");
//        return 0;
//    }
//    if(mode)
//    {
//        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
//    }
//    else
//    {
//        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
//    }
//
//    return rsa;
//}

RSA * createRSApub(std::string sKey) {
     //std::string sKey((char*) key);
//    replace_first(sKey, "-----BEGIN RSA PUBLIC KEY-----", "");
//    replace_first(sKey, "-----END RSA PUBLIC KEY-----", "");
     RSA *rsa = nullptr;
     BIO *keybio; //  BIO_new( BIO_s_mem() );
//     BIO_write( keybio, sKey.c_str(),sKey.length());
     keybio = BIO_new_mem_buf(sKey.c_str(), sKey.length());

    if (keybio == nullptr) {
        printf( "Failed to create key BIO");
        return nullptr;
    }
//    if (mode) {
//        RSA *rsa = nullptr;
    else  rsa = PEM_read_bio_RSA_PUBKEY(keybio, nullptr,nullptr, nullptr);
//        RSA* public_key;
//        BIO* bo = BIO_new(BIO_s_mem());
//        BIO_write(bo, sKey.c_str(), sKey.length());
//        RSA* rsa = PEM_read_bio_RSA_PUBKEY(bo, &public_key, nullptr, nullptr);;
//        return rsa;
//    }
//    else {
//        EVP_PKEY* pkey = 0;
//        PEM_read_bio_PrivateKey(keybio, &pkey,nullptr, nullptr);
//        RSA* rsa = EVP_PKEY_get1_RSA(pkey);
//        rsa = PEM_read_bio_RSAPrivateKey(keybio, nullptr,nullptr, nullptr);
//        LOGI("RSA_check_key(rsa) = %d", RSA_check_key(rsa));
//        return rsa;
//    }
//    BIO_free(keybio);

    return rsa;
}

RSA * createRSApriv(std::string sKey) {
    //std::string sKey((char*) key);
//    replace_first(sKey, "-----BEGIN RSA PRIVATE KEY-----", "");
//    replace_first(sKey, "-----END RSA PRIVATE KEY-----", "");
    RSA *rsa = nullptr;
    BIO *keybio; //  BIO_new( BIO_s_mem() );
//     BIO_write( keybio, sKey.c_str(),sKey.length());
    keybio = BIO_new_mem_buf(sKey.c_str(), sKey.length());

    if (keybio == nullptr) {
        printf( "Failed to create key BIO");
        return nullptr;
    }
    else rsa = PEM_read_bio_RSAPrivateKey(keybio, nullptr,nullptr, nullptr);
    LOGI("RSA_check_key(rsa) = %d", RSA_check_key(rsa));
    return rsa;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_MainActivity_publicencryptRsa(JNIEnv *env, jobject thiz, jstring key,
                                                       jbyteArray plain_text) {
      jboolean isCopy;
//    jbyte* keyData = env->GetByteArrayElements(public_key, &isCopy);
//    const char* key_data;
//    key_data = (const char*) keyData;
//    int key_data_len = strlen(key_data);
    unsigned char *key_data = (unsigned char *) (env)->GetStringUTFChars(key, &isCopy);
    std::string sKey((char*) key_data);
   // int key_data_len = strlen((char*)key_data);
//    std::string key_data_string = std::string(key_data, key_data_len);

    int plainText_len = env->GetArrayLength(plain_text);
    jbyte* temp = env->GetByteArrayElements(plain_text,&isCopy);
    unsigned char* plainText;
    plainText = (unsigned char *) temp;
//    plainText_len = strlen((char*)plainText);

    if(nullptr == plainText)
        return nullptr;

    LOGV("The data to encrypt is: %s", plainText);

    unsigned char chEncryptedData[256] = {};
    int chEncryptedData_len = sizeof chEncryptedData;
    //for(int i = 0; i < chEncryptedData_len; ++i) chEncryptedData[i] = 0;

    int iResult = RSA_public_encrypt(plainText_len, plainText, chEncryptedData, createRSApub(sKey), RSA_PKCS1_PADDING);

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
    std::string encd((char*) chEncryptedData);

        LOGD("The Encrypted data is: %s", chEncryptedData);

    jbyteArray EncryptedByteArray = env->NewByteArray(iResult);
    env->SetByteArrayRegion(EncryptedByteArray, 0, iResult, (jbyte *) chEncryptedData);

    return EncryptedByteArray;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_MainActivity_privatedecryptRsa(JNIEnv *env, jobject thiz,
                                                       jstring private_key,
                                                       jbyteArray enc_text) {
    jboolean isCopy;
    unsigned char *key_data = (unsigned char *) (env)->GetStringUTFChars(private_key, &isCopy);
    std::string sKey((char*) key_data);
    int key_data_len = strlen((char*)key_data);

    int encText_len = env->GetArrayLength(enc_text);
    jbyte* a = env->GetByteArrayElements(enc_text,&isCopy);
    const unsigned char* encText;
    encText = (unsigned char *) a;
    //encText_len = strlen((char*)encText);

   // RSA* myRSA = RSA_generate_key_ex(2048, 65537, NULL, NULL);

    //RSA * rsa = createRSA(key_data,1);

    unsigned char chDecryptedData[256] = {};
    int chDecryptedData_len = sizeof chDecryptedData;

    int result = RSA_private_decrypt(chDecryptedData_len,encText, chDecryptedData, createRSApriv(sKey), RSA_PKCS1_PADDING);

    if(-1 == result) {
        char *chErrMsg = (char*)malloc(256);
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), chErrMsg);
        LOGE("The data Decryption failed due to the reason : %s", chErrMsg);
        free(chErrMsg);
        return nullptr;
    }
        LOGD("The Decrypted data is: %s", chDecryptedData);

    jbyteArray DecryptedByteArray = env->NewByteArray(result);
    env->SetByteArrayRegion(DecryptedByteArray, 0, result, (jbyte *) chDecryptedData);

    return DecryptedByteArray;
}
/********************************* END RSA *********************************/

//extern "C"
//JNIEXPORT jbyteArray JNICALL
//Java_com_example_myapplication_MainActivity_encrypt_1w_1aes(JNIEnv *env, jobject thiz, jbyteArray plain_array, jint mode) {
//    (void)thiz;
//    int len = env->GetArrayLength(plain_array);
//
//    //jbyte into c++ char
//    jboolean isCopy;
//    jbyte* a = env->GetByteArrayElements(plain_array,&isCopy);
//    unsigned char* input_data;
//    input_data = (unsigned char*) a;
//    const unsigned char ukey[] = { 'H','A','R','D','C','O','D','E','D',' ','K','E','Y','1','2','3'};
//    unsigned char *output_data = nullptr;
//    output_data = (unsigned char *)(malloc(len));
//    AES_KEY key;
//    memset(&key, 0, 16);
//
//
//    if(mode == AES_ENCRYPT)
//        AES_set_encrypt_key(ukey, 128, &key);
//    else
//        AES_set_decrypt_key(ukey, 128, &key);
//
//    AES_ecb_encrypt(input_data, output_data, &key, mode);
//
//
//    jbyteArray resArray = env->NewByteArray(len);
//    void *decrypteddata = env->GetPrimitiveArrayCritical((jarray)resArray, &isCopy);
//    memcpy(decrypteddata, output_data, len);
//    env->ReleasePrimitiveArrayCritical(resArray, decrypteddata, 0);
//
//    LOGI("EncryptSuccess, %s", output_data);
//    return resArray;
//}
//extern "C"
//JNIEXPORT jbyteArray JNICALL
//Java_com_example_myapplication_MainActivity_decrypt_1w_1aes(JNIEnv *env, jobject thiz,
//                                                            jbyteArray plain_array, jint mode) {
//    (void)thiz;
//    int len = env->GetArrayLength(plain_array);
//
//    //jbyte into c++ char
//    jboolean isCopy;
//    jbyte* a = env->GetByteArrayElements(plain_array,&isCopy);
//    unsigned char* input_data;
//    input_data = (unsigned char*) a;
//    const unsigned char ukey[] = { 'H','A','R','D','C','O','D','E','D',' ','K','E','Y','1','2','3'};
//    unsigned char *output_data = nullptr;
//    output_data = (unsigned char *)(malloc(len));
//    AES_KEY key;
//    memset(&key, 0, 16);
//
//
//    if(mode == AES_ENCRYPT)
//        AES_set_encrypt_key(ukey, 128, &key);
//    else
//        AES_set_decrypt_key(ukey, 128, &key);
//
//    AES_decrypt(input_data, output_data, &key);
//
//
//    jbyteArray resArray = env->NewByteArray(len);
//    void *decrypteddata = env->GetPrimitiveArrayCritical((jarray)resArray, &isCopy);
//    memcpy(decrypteddata, output_data, len);
//    env->ReleasePrimitiveArrayCritical(resArray, decrypteddata, 0);
//
//    LOGI("DecryptSuccess, %s", output_data);
//    return resArray;
//}


//unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char* plaintext, int* len) {
//    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
//    unsigned char* ciphertext = static_cast<unsigned char *>(malloc(c_len));
//
//    EVP_EncryptInit_ex(e, nullptrptr, nullptrptr, nullptrptr, nullptrptr);
//    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
//    EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);
//
//    *len = c_len + f_len;
//    return ciphertext;
//}
//
//unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, const unsigned char *ciphertext, int *len)
//{
//    /* because we have padding ON, we must allocate an extra cipher block size of memory */
//    int p_len = *len, f_len = 0;
//    unsigned char *plaintext = static_cast<unsigned char *>(malloc(p_len + AES_BLOCK_SIZE));
//
//    EVP_DecryptInit_ex(e, nullptr, nullptr, nullptr, nullptr);
//    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
//    EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);
//
//    *len = p_len + f_len;
//    return plaintext;
//}


//extern "C"
//JNIEXPORT jint JNICALL
//Java_com_example_myapplication_MainActivity_startAes(JNIEnv *env, jobject obj) {

//    unsigned int salt[] = {12345, 54321};
//    const char key_data[] = "Amir 2002";
//    int key_data_len;
//    unsigned char plaintext[] = {'2','3','4','5','5','6','2','3','4','5','5','6','2','3','4','5'}; //,'5','6','2','3','4','5','5','6','2','3','4','5','5','6','2','3'};
//    int plaintext_len = 16;
//    key_data_len = (int) strlen(key_data);
//    en = EVP_CIPHER_CTX_new();
//    de = EVP_CIPHER_CTX_new();
//    unsigned char ciphertext[16];
//    unsigned char decryptedtext[16];
//    int ciphertext_len = 16;
//    int decryptedtext_len;

    /* gen key and iv. init the cipher ctx object */
//    if (AES_initialization(key_data, key_data_len, (unsigned char *)salt, en, de)) {
//        LOGE("Couldn't initialize AES cipher\n");
//        LOGV("initializing aes failed");
//        return 0;
//    }
//    LOGD("initializing aes success");
    //EVP_EncryptUpdate(en, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    //EVP_EncryptUpdate(en, ciphertext, &ciphertext_len, plaintext, plaintext_len);
//    for(int i = 0; i < ciphertext_len; ++i) {
//        LOGV("EncUpd[%d]: %c", i, ciphertext[i]);
//    }
//    LOGD("EncUpdLen: %d", ciphertext_len);

    //LOGI("EncUpd: %s --- %d\nplaintext: %s --- %d", ciphertext, ciphertext_len, plaintext, plaintext_len);
//    EVP_EncryptFinal_ex(en, ciphertext, &ciphertext_len);
//    for(int i = 0; i < ciphertext_len; ++i) {
//        LOGV("EncFinal[%d]: %c", i, ciphertext[i]);
//    }
//
//    LOGD("EncFinalLen: %d", ciphertext_len);

    //EVP_DecryptUpdate(de, plaintext, &plaintext_len, ciphertext, ciphertext_len);


    //LOGI("EncFinal: %s --- %d\nplaintext: %s --- %d", ciphertext, ciphertext_len, plaintext, plaintext_len);
    //===== encrypt, decrypt here ============
//    for(int i = 0; i < plaintext_len; ++i) {
//        LOGV("PlainText[%d]: %c", i, plaintext[i]);
//    }
//
//    LOGD("PlainTextLen: %d", plaintext_len);
//    EVP_CIPHER_CTX_free(en);
//    EVP_CIPHER_CTX_free(de);
//    return 1;
//}

//extern "C"
//JNIEXPORT jbyteArray JNICALL
//Java_com_example_myapplication_MainActivity_StartingEncryption(JNIEnv *env, jobject thiz,
//                                                       jobject to_encrypt) {
//    const char *plainText = env->GetStringUTFChars(static_cast<jstring>(to_encrypt), 0);
//    int len = strlen(plainText) + 1;
//    unsigned char *ciphertext = aes_encrypt(en, (unsigned char *)plainText, &len);
//
//    jbyteArray byteArray=env->NewByteArray(strlen(reinterpret_cast<const char *const>(ciphertext)));
//    env->SetByteArrayRegion(byteArray, 0, strlen(
//            reinterpret_cast<const char *const>(ciphertext)), (const jbyte*)ciphertext);
//
//    env->ReleaseStringUTFChars(static_cast<jstring>(to_encrypt), plainText);
//    LOGI("success");
//    return byteArray;
//}
//
//
//extern "C"
//JNIEXPORT jbyteArray JNICALL
//Java_com_example_myapplication_MainActivity_StartingDecryption(JNIEnv *env, jobject thiz,
//                                                       jobject to_decrypt) {
//    const  unsigned char *cipherText = reinterpret_cast<const unsigned char *>(env->GetStringUTFChars(
//            static_cast<jstring>(to_decrypt), nullptr));
//    int len = sizeof(cipherText) + 1;
//    char *plainText = (char *)aes_decrypt(de, cipherText, &len);
//    jbyteArray byteArray = env->NewByteArray(strlen(plainText));
//    env->SetByteArrayRegion(byteArray, 0, strlen(plainText), (const jbyte*)plainText);
//
//    env->ReleaseStringUTFChars(static_cast<jstring>(to_decrypt),
//                               reinterpret_cast<const char *>(cipherText));
//
//    return byteArray;
//}


//extern "C"
//JNIEXPORT jstring JNICALL
//
//Java_com_example_myapplication_MainActivity_invertMyString(JNIEnv *env, jobject thiz) {
//
//    (void) thiz;
//    //const char *name = env->GetStringUTFChars(string, nullptr);//Java String to C Style string
//    char msg[60] = "Tashkent ";
//    char name[60] = "is the capital of Uzbekistan";
//    char res[120] = "";
//    jstring result;
//
//    LOGD("Original msg: %s \n Original name: %s", msg, name);
//    //result = env->NewStringUTF(msg); // C style string to Java String
//    size_t lengthmsgbefore = strlen(msg);
//    size_t lengthname = strlen(name);
//    strcat(msg, name);
//
//    LOGW("msg + name (res): %s", msg);
//    LOGV("Size: msg - %db \n\t name - %db", (int) lengthmsgbefore, (int) lengthname);
//
//    size_t lengthmsgafter = strlen(msg);
//    int j = 0;
//    for (int i = lengthmsgafter - 1; i >= 0; --i) {
//        size_t lengthres = strlen(res);
//        for (; j <= lengthres; ++j) {
//            res[j] = msg[i];
//        }
//    }
//
//    result = env->NewStringUTF(res);
//
//    LOGE("Invert msg + name (res): %s", res);
//    LOGI("Size: msg - %db \n\t res - %db", (int) lengthmsgafter, j); // j - res size
//
//    unsigned char key[16], iv[16];
//
//    if (!RAND_bytes(key, sizeof key)) {
//        LOGE("RAND_bytes(key) failed");
//    } else {
//        LOGI("RAND_bytes(key) :");
//        for (int i = 0; i < 16; i++) {
//            LOGI("%02X", key[i]);
//        }
//    }
//    if (!RAND_bytes(iv, sizeof iv)) {
//        LOGE("RAND_bytes(iv) failed");
//    } else {
//        LOGI("RAND_bytes(iv) :");
//        for (int i = 0; i < 16; i++) {
//            LOGI("%02X", iv[i]);
//        }
//    }
//
//
//    return result;
//}

