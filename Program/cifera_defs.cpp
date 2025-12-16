#include "cifera_head.h"

char* readFromFile(const char* filename, int& len) {
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cout << "Error opening file: " << filename << endl;
        len = 0;
        return nullptr;
    }
    
    file.seekg(0, ios::end);
    len = file.tellg();
    file.seekg(0, ios::beg);
    
    char* message = new char[len + 1];
    file.read(message, len);
    message[len] = '\0';
    
    file.close();
    return message;
}

void writeToFile(const char* filename, const unsigned char* data, int len) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        return;
    }
    file.write((const char*)data, len);
    file.close();
}

void altCC(char msg[], int key, int len) {
    int k = key;
    for (int i = 0; i < len; i++) {
        msg[i] += k;
        k *= -1;
    }
}

void altCC_decrypt(char msg[], int key, int len) {
    int k = key;
    for (int i = 0; i < len; i++) {
        msg[i] -= k;
        k *= -1;
    }
}

char* wood(char msg[], int key, int len) {
    int m = 1;
    while (key*m < len) {
        m++;
    }
    int counter = 0;
    char matrix[key][m];
    for (int i = 0; i < key; i++) {
        for (int j = 0; j < m; j++) {
            if (counter >= len) {
                matrix[i][j] = 'z';
            } else {
                matrix[i][j] = msg[counter];
                counter++;
            }
        }
    }
    counter = 0;
    int wood_vec_size = key*m;
    char* morning_wood = new char[wood_vec_size + 1];
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < key; j++) {
            morning_wood[counter++] = matrix[j][i];
        }
    }
    morning_wood[wood_vec_size] = '\0';
    return morning_wood;
}

char* wood_decrypt(char msg[], int key, int len) {
    int m = len / key;
    char matrix[key][m];
    
    int counter = 0;
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < key; j++) {
            matrix[j][i] = msg[counter++];
        }
    }
    
    char* decrypted = new char[len + 1];
    counter = 0;
    for (int i = 0; i < key; i++) {
        for (int j = 0; j < m; j++) {
            decrypted[counter++] = matrix[i][j];
        }
    }
    
    int real_len = len;
    while (real_len > 0 && decrypted[real_len - 1] == 'z') {
        real_len--;
    }
    decrypted[real_len] = '\0';
    
    return decrypted;
}

int** vTBin(int* ascii, int rows) {
    int** matrix = new int*[rows];
    for (int i = 0; i < rows; i++) {
        matrix[i] = new int[8];
        for (int j = 0; j < 8; j++) {
            int shift = 8 - 1 - j;
            matrix[i][j] = (ascii[i] >> shift) & 1;
        }
    }
    return matrix;
}

void freeBinM(int** matrix, int rows) {
    for (int i = 0; i < rows; i++)
        delete[] matrix[i];
    delete[] matrix;
}

int* BinTv(int** binMatrix, int rows) {
    int* asciiCodes = new int[rows];
    for (int i = 0; i < rows; i++) {
        int val = 0;
        for (int j = 0; j < 8; j++) {
            val <<= 1;
            val |= binMatrix[i][j];
        }
        asciiCodes[i] = val;
    }
    return asciiCodes;
}

void deriveKey(const char* password, unsigned char* salt, unsigned char* key, unsigned char* iv) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 16, 100000, EVP_sha256(), 32, key);
    unsigned char temp[32];
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 16, 50000, EVP_sha256(), 32, temp);
    memcpy(iv, temp, AES_BLOCK_SIZE);
}

EncryptedPayload aes256_encrypt(const unsigned char* plaintext, int plaintext_len,
                                 const unsigned char* key, const unsigned char* iv) {
    EncryptedPayload payload;
    memcpy(payload.iv, iv, AES_BLOCK_SIZE);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    int max_len = plaintext_len + AES_BLOCK_SIZE;
    payload.data = new unsigned char[max_len];
    
    int len;
    EVP_EncryptUpdate(ctx, payload.data, &len, plaintext, plaintext_len);
    payload.length = len;
    
    int final_len;
    EVP_EncryptFinal_ex(ctx, payload.data + len, &final_len);
    payload.length += final_len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    computeHMAC(payload.data, payload.length, key, payload.hmac);
    
    return payload;
}

unsigned char* aes256_decrypt(const EncryptedPayload& payload, const unsigned char* key) {
    if (!verifyHMAC(payload.data, payload.length, key, payload.hmac)) {
        cout << "HMAC verification failed! Message may be tampered." << endl;
        return nullptr;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, payload.iv);
    
    unsigned char* plaintext = new unsigned char[payload.length + AES_BLOCK_SIZE];
    
    int len;
    EVP_DecryptUpdate(ctx, plaintext, &len, payload.data, payload.length);
    int plaintext_len = len;
    
    int final_len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len);
    plaintext_len += final_len;
    
    plaintext[plaintext_len] = '\0';
    
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext;
}

RSA* generateRSAKeyPair(int bits) {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, bits, e, NULL);
    BN_free(e);
    return rsa;
}

unsigned char* rsa_encrypt(RSA* rsa, const unsigned char* data, int data_len, int& encrypted_len) {
    int rsa_size = RSA_size(rsa);
    unsigned char* encrypted = new unsigned char[rsa_size];
    
    encrypted_len = RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    
    if (encrypted_len == -1) {
        cout << "RSA encryption failed!" << endl;
        delete[] encrypted;
        return nullptr;
    }
    
    return encrypted;
}

unsigned char* rsa_decrypt(RSA* rsa, const unsigned char* encrypted, int encrypted_len, int& decrypted_len) {
    int rsa_size = RSA_size(rsa);
    unsigned char* decrypted = new unsigned char[rsa_size];
    
    decrypted_len = RSA_private_decrypt(encrypted_len, encrypted, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    
    if (decrypted_len == -1) {
        cout << "RSA decryption failed!" << endl;
        delete[] decrypted;
        return nullptr;
    }
    
    decrypted[decrypted_len] = '\0';
    return decrypted;
}

void computeHMAC(const unsigned char* data, int data_len, const unsigned char* key, unsigned char* hmac_out) {
    unsigned int hmac_len;
    HMAC(EVP_sha256(), key, 32, data, data_len, hmac_out, &hmac_len);
}

bool verifyHMAC(const unsigned char* data, int data_len, const unsigned char* key, const unsigned char* hmac) {
    unsigned char computed_hmac[SHA256_DIGEST_LENGTH];
    computeHMAC(data, data_len, key, computed_hmac);
    return CRYPTO_memcmp(computed_hmac, hmac, SHA256_DIGEST_LENGTH) == 0;
}

void generateRandomData(unsigned char* buffer, int length) {
    RAND_bytes(buffer, length);
}

char* generateRandomAlphanumeric(int n) {
    char* arr = new char[n + 1];
    unsigned char random_bytes[n];
    RAND_bytes(random_bytes, n);
    
    for (int i = 0; i < n; i++) {
        int r = random_bytes[i] % 62;
        if (r < 10) {
            arr[i] = '0' + r;
        } else if (r < 36) {
            arr[i] = 'A' + (r - 10);
        } else {
            arr[i] = 'a' + (r - 36);
        }
    }
    
    arr[n] = '\0';
    return arr;
}

void saveEncryptedPayload(const char* filename, const vector<EncryptedPayload>& payloads,
                          const unsigned char* rsa_encrypted, int rsa_len) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        cout << "Error creating output file!" << endl;
        return;
    }
    
    int num_payloads = payloads.size();
    file.write((char*)&num_payloads, sizeof(int));
    
    for (const auto& payload : payloads) {
        file.write((char*)&payload.length, sizeof(int));
        file.write((char*)payload.iv, AES_BLOCK_SIZE);
        file.write((char*)payload.hmac, SHA256_DIGEST_LENGTH);
        file.write((char*)payload.data, payload.length);
    }
    
    file.write((char*)&rsa_len, sizeof(int));
    file.write((char*)rsa_encrypted, rsa_len);
    
    file.close();
}

bool loadEncryptedPayload(const char* filename, vector<EncryptedPayload>& payloads,
                         unsigned char** rsa_encrypted, int& rsa_len) {
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cout << "Error opening encrypted file!" << endl;
        return false;
    }
    
    int num_payloads;
    file.read((char*)&num_payloads, sizeof(int));
    
    for (int i = 0; i < num_payloads; i++) {
        EncryptedPayload payload;
        file.read((char*)&payload.length, sizeof(int));
        file.read((char*)payload.iv, AES_BLOCK_SIZE);
        file.read((char*)payload.hmac, SHA256_DIGEST_LENGTH);
        payload.data = new unsigned char[payload.length];
        file.read((char*)payload.data, payload.length);
        payloads.push_back(payload);
    }
    
    file.read((char*)&rsa_len, sizeof(int));
    *rsa_encrypted = new unsigned char[rsa_len];
    file.read((char*)*rsa_encrypted, rsa_len);
    
    file.close();
    return true;
}