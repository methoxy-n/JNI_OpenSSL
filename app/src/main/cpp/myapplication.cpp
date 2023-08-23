#include "openssl_rsa.h"
#include "openssl_aes.h"
#include "openssl_tdes.h"
/********************************* SHA-256 *********************************/
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
/********************************* END SHA-256 *********************************/

/********************************* AES_256 ENC/DEC *********************************/
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_MainActivity_encryptAes256(JNIEnv *env, jobject thiz, jbyteArray key,
                                                          jbyteArray plain_text) {
    jboolean isCopy;
    jbyte* keyData = env->GetByteArrayElements(key, &isCopy);
    const char* key_data;
    key_data = (const char*) keyData;
    //int key_data_len = strlen(key_data);

    int plainText_len = env->GetArrayLength(plain_text);
    jbyte* temp = env->GetByteArrayElements(plain_text,&isCopy);
    unsigned char* plainText;
    plainText = (unsigned char*) temp;

    //plainText_len = strlen((char*)plainText);

    if( nullptr == plainText )
        return nullptr;

    openssl_aes to_encrypt(plainText, plainText_len, key_data);
    to_encrypt.encryptAES(to_encrypt);

    jbyteArray encryptedByteArray = env->NewByteArray(to_encrypt.encrypted_len);
    env->SetByteArrayRegion(encryptedByteArray, 0, to_encrypt.encrypted_len, (jbyte *) to_encrypt.encrypted_text);

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

    openssl_aes to_decrypt(encText, encText_len, key_data);
    to_decrypt.decryptAES(to_decrypt);

    jbyteArray decryptedByteArray = env->NewByteArray(to_decrypt.decrypted_len);
    env->SetByteArrayRegion(decryptedByteArray, 0, to_decrypt.decrypted_len, (jbyte *) to_decrypt.decrypted_text);

    return decryptedByteArray;
}
/********************************* END AES *********************************/

/********************************* RSA ENC/DEC *********************************/
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_MainActivity_EncryptRSA(JNIEnv *env, jobject thiz, jstring key,
                                                       jbyteArray plain_text, jstring mode) {
      jboolean isCopy;
    unsigned char *key_data = (unsigned char *) (env)->GetStringUTFChars(key, &isCopy);
    std::string sKey((char*) key_data);


    int plainText_len = env->GetArrayLength(plain_text);
    jbyte* temp = env->GetByteArrayElements(plain_text,&isCopy);
    unsigned char* plainText;
    plainText = (unsigned char *) temp;


    unsigned char *enc_mode = (unsigned char *) (env)->GetStringUTFChars(mode, &isCopy);
    std::string s_mode((char*) enc_mode);

    openssl_rsa to_encrypt(plainText, plainText_len, sKey);
    to_encrypt.encryptRSA(to_encrypt, s_mode);
    //openssl_rsa encrypted_mes(to_encrypt);

    jbyteArray EncryptedByteArray = env->NewByteArray(to_encrypt.encrypted_len);
    env->SetByteArrayRegion(EncryptedByteArray, 0, to_encrypt.encrypted_len, (jbyte *) to_encrypt.encrypted_text);

    return EncryptedByteArray;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_MainActivity_DecryptRSA(JNIEnv *env, jobject thiz,
                                                       jstring private_key,
                                                       jbyteArray enc_text, jstring mode) {
    jboolean isCopy;
    unsigned char *key_data = (unsigned char *) (env)->GetStringUTFChars(private_key, &isCopy);
    std::string sKey((char*) key_data);
    int key_data_len = strlen((char*)key_data);

    int encText_len = env->GetArrayLength(enc_text);
    jbyte* a = env->GetByteArrayElements(enc_text,&isCopy);
    unsigned char* encText;
    encText = (unsigned char *) a;

    unsigned char *enc_mode = (unsigned char *) (env)->GetStringUTFChars(mode, &isCopy);
    std::string s_mode((char*) enc_mode);

    openssl_rsa to_decrypt(encText, encText_len, sKey);
    to_decrypt.decryptRSA(to_decrypt, s_mode);

    jbyteArray DecryptedByteArray = env->NewByteArray(to_decrypt.decrypted_len);
    env->SetByteArrayRegion(DecryptedByteArray, 0, to_decrypt.decrypted_len, (jbyte *) to_decrypt.decrypted_text);

    return DecryptedByteArray;
}
/********************************* END RSA *********************************/

/********************************* START 3DES (WORKS) *********************************/
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_MainActivity_new3DesEnc(JNIEnv *env, jobject thiz,
                                                       jbyteArray plain_text) {
    unsigned int salt[] = {12345, 54321};

    jboolean isCopy;
//    jbyte* keyData = env->GetByteArrayElements(key, &isCopy);
//    const char* key_data;
//    key_data = (const char*) keyData;
//    int key_data_len = strlen(key_data);

    int plainText_len = env->GetArrayLength(plain_text);
    jbyte* temp = env->GetByteArrayElements(plain_text,&isCopy);
    unsigned char* plainText;
    plainText = (unsigned char*) temp;
    //plainText_len = strlen((char*)plainText);

    if(nullptr == plainText)
        return nullptr;

//    unsigned char ciphertext[plainText_len];
//    int ciphertext_len = sizeof ciphertext;

//    if (TDES_initialization((char*)key_data, EVP_MAX_KEY_LENGTH, (unsigned char *)salt, enc, dec)) {
//        LOGE("Couldn't initialize AES cipher\n");
//        LOGV("initializing aes failed");
//        return nullptr;
//    }

//    EVP_EncryptUpdate(enc, ciphertext, &ciphertext_len, plainText, plainText_len);
    // EVP_EncryptFinal_ex(en, ciphertext, &ciphertext_len);
//    for(int i = 0; i < ciphertext_len; ++i) {
//        LOGI("EncryptedText[%d]: %c", i, ciphertext[i]);
//    }
    // LOGV("EncryptedData: %s", ciphertext);
    openssl_tdes to_encrypt(plainText, plainText_len);
    to_encrypt.encryptTDES(to_encrypt);

    jbyteArray encryptedByteArray = env->NewByteArray(to_encrypt.encrypted_len);
    env->SetByteArrayRegion(encryptedByteArray, 0, to_encrypt.encrypted_len, (jbyte *) to_encrypt.encrypted_text);

    return encryptedByteArray;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_myapplication_MainActivity_new3DesDec(JNIEnv *env, jobject thiz,
                                                       jbyteArray enc_text) {
    jboolean isCopy;
//    jbyte* keyData = env->GetByteArrayElements(key, &isCopy);
//    const char* key_data;
//    key_data = (const char*) keyData;
//    int key_data_len = strlen(key_data);

    int encText_len = env->GetArrayLength(enc_text);
    jbyte* encryptedText = env->GetByteArrayElements(enc_text, &isCopy);
    unsigned char * encText;
    encText = (unsigned char*) encryptedText;
    //int encText_len = strlen((char*)encText);

//    unsigned char plaintext[encText_len];
//    int plaintext_len = sizeof plaintext;

    //EVP_DecryptInit_ex(de, nullptr, nullptr, nullptr, nullptr);
//    EVP_DecryptUpdate(dec, plaintext, &plaintext_len, encText, encText_len);
    //EVP_DecryptFinal_ex(de, plaintext, &plaintext_len);
//    for(int i = 0; i < plaintext_len; ++i) {
//        LOGV("DecryptedText[%d]: %c", i, plaintext[i]);
//    }
    //LOGV("DecryptedText: %s", plaintext);
    openssl_tdes to_decrypt(encText, encText_len);
    to_decrypt.decryptTDES(to_decrypt);

    jbyteArray decryptedByteArray = env->NewByteArray(to_decrypt.text_len);
    env->SetByteArrayRegion(decryptedByteArray, 0, to_decrypt.text_len, (jbyte *) to_decrypt.decrypted_text);

    return decryptedByteArray;
}
/********************************* END 3DES (WORKS) *********************************/

