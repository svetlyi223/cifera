#ifndef CIFERA_HEAD_H
#define CIFERA_HEAD_H

#include <iostream>
#include <fstream>
#include <cmath>
#include <cstring>
#include <limits.h>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

using namespace std;

struct EncryptedPayload {
    unsigned char* data;
    int length;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char hmac[SHA256_DIGEST_LENGTH];
};


char* readFromFile(const char* filename, int& len);
void writeToFile(const char* filename, const unsigned char* data, int len);


void altCC(char msg[], int key, int len);
void altCC_decrypt(char msg[], int key, int len);
char* wood(char msg[], int key, int len);
char* wood_decrypt(char msg[], int key, int len);

int** vTBin(int* ascii, int rows);
void freeBinM(int** matrix, int rows);
int* BinTv(int** binMatrix, int rows);

template <size_t KEY_ROWS>
int** exohr(int** matrix, int (&key)[KEY_ROWS][8], int rows)
{
    int** result = new int*[rows];
    for (int i = 0; i < rows; i++) {
        result[i] = new int[8];
        int keyRow = i % KEY_ROWS;
        for (int j = 0; j < 8; j++) {
            result[i][j] = matrix[i][j] ^ key[keyRow][j];
        }
    }
    return result;
}

void deriveKey(const char* password, unsigned char* salt, unsigned char* key, unsigned char* iv);
EncryptedPayload aes256_encrypt(const unsigned char* plaintext, int plaintext_len, 
                                 const unsigned char* key, const unsigned char* iv);
unsigned char* aes256_decrypt(const EncryptedPayload& payload, const unsigned char* key);

RSA* generateRSAKeyPair(int bits);
unsigned char* rsa_encrypt(RSA* rsa, const unsigned char* data, int data_len, int& encrypted_len);
unsigned char* rsa_decrypt(RSA* rsa, const unsigned char* encrypted, int encrypted_len, int& decrypted_len);

void computeHMAC(const unsigned char* data, int data_len, const unsigned char* key, unsigned char* hmac_out);
bool verifyHMAC(const unsigned char* data, int data_len, const unsigned char* key, const unsigned char* hmac);

void generateRandomData(unsigned char* buffer, int length);
char* generateRandomAlphanumeric(int n);

void saveEncryptedPayload(const char* filename, const vector<EncryptedPayload>& payloads, 
                            const unsigned char* rsa_encrypted, int rsa_len);
bool loadEncryptedPayload(const char* filename, vector<EncryptedPayload>& payloads,
                            unsigned char** rsa_encrypted, int& rsa_len);

#endif