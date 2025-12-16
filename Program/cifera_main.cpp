#include "cifera_head.h"

// Elon Musks' keys to success = 🔑🔑🔑🔑🔑🔑🔑🔑
int k_wood = 6;  // every morning 🥀
int k_altCC = 7; // The Ides of March 🔪
int k_exohr_1[11][8] = {        // Pandemonium Door 15
    {0, 1, 1, 1, 0, 0, 0, 0},
    {0, 1, 1, 0, 0, 0, 0, 1},
    {0, 1, 1, 0, 1, 1, 1, 0},
    {0, 1, 1, 0, 0, 1, 0, 0},
    {0, 1, 1, 0, 0, 1, 0, 1},
    {0, 1, 1, 0, 1, 1, 0, 1},
    {0, 1, 1, 0, 1, 1, 1, 1},
    {0, 1, 1, 0, 1, 1, 1, 0},
    {0, 1, 1, 0, 1, 0, 0, 1},
    {0, 1, 1, 1, 0, 1, 0, 1},
    {0, 1, 1, 0, 1, 1, 0, 1}
};
int k_exohr_2[12][8] = {         // What kind of Key is this? idfk
    {0, 1, 0, 0, 0, 1, 0, 0},
    {0, 1, 1, 1, 1, 1, 1, 0},
    {0, 1, 1, 0, 1, 1, 1, 1},
    {0, 1, 0, 1, 1, 1, 1, 1},
    {0, 1, 0, 1, 0, 1, 0, 0},
    {0, 1, 1, 1, 0, 0, 1, 0},
    {0, 1, 1, 0, 1, 0, 0, 1},
    {0, 1, 1, 0, 0, 0, 1, 1},
    {0, 1, 1, 0, 1, 0, 1, 1},
    {0, 1, 1, 0, 0, 1, 0, 1},
    {0, 1, 1, 1, 0, 0, 1, 0},
    {0, 1, 1, 1, 1, 0, 0, 1}
};

void encrypt() {
    int plaintext_len;
    char* plaintext = readFromFile("input.txt", plaintext_len);
    
    if (plaintext == nullptr) {
        cout << "Failed to read input file!" << endl;
        return;
    }
    
    cout << "\n╔════════════════════════════════════════════╗\n";
    cout << "║               ENCRYPTION CIFERA            ║\n";
    cout << "╚════════════════════════════════════════════╝\n\n";
    cout << "Original message length: " << plaintext_len << " bytes\n\n";
    
    // Pass me the salt
    unsigned char salt[16];
    generateRandomData(salt, 16);
    
    // Get password
    cout << "Enter encryption password: ";
    char password[256];
    cin.getline(password, 256);
    
    unsigned char aes_key[32];
    unsigned char aes_iv[AES_BLOCK_SIZE];
    deriveKey(password, salt, aes_key, aes_iv);
    
    vector<EncryptedPayload> payloads;
    
    cout << "\n[1/7] Generating 4 decoy payloads...\n";
    
    // RELEASE THE MINIONS
    for (int i = 0; i < 4; i++) {
        char* decoy = generateRandomAlphanumeric(plaintext_len);
        
        // LAYER 1: Alternative Caesar Cipher (YOURS)
        altCC(decoy, k_altCC, plaintext_len);
        
        // LAYER 2: Wood Cipher (YOURS)
        char* wood_encrypted = wood(decoy, k_wood, plaintext_len);
        int wood_len = strlen(wood_encrypted);
        
        // LAYER 3: Convert to ASCII
        int* ascii_codes = new int[wood_len];
        for (int j = 0; j < wood_len; j++) {
            ascii_codes[j] = (int)wood_encrypted[j];
        }
        
        // LAYER 4: XOR #1 (YOURS)
        int** bin = vTBin(ascii_codes, wood_len);
        bin = exohr(bin, k_exohr_1, wood_len);
        
        // LAYER 5: XOR #2 (YOURS)
        bin = exohr(bin, k_exohr_2, wood_len);
        
        // Convert back from binary
        int* xor_result = BinTv(bin, wood_len);
        
        // Convert to char for AES
        unsigned char* pre_aes = new unsigned char[wood_len];
        for (int j = 0; j < wood_len; j++) {
            pre_aes[j] = (unsigned char)xor_result[j];
        }
        
        // LAYER 6: AES-256-CBC (MILITARY-GRADE)
        unsigned char decoy_iv[AES_BLOCK_SIZE];
        generateRandomData(decoy_iv, AES_BLOCK_SIZE);
        EncryptedPayload decoy_payload = aes256_encrypt(pre_aes, wood_len, aes_key, decoy_iv);
        payloads.push_back(decoy_payload);
        
        // Cleanup
        delete[] decoy;
        delete[] wood_encrypted;
        delete[] ascii_codes;
        freeBinM(bin, wood_len);
        delete[] xor_result;
        delete[] pre_aes;
    }
    
    cout << "[2/7] ✓ Alternative Caesar Cipher applied\n";
    cout << "[3/7] ✓ Wood Cipher applied\n";
    cout << "[4/7] ✓ XOR Layer #1 applied\n";
    cout << "[5/7] ✓ XOR Layer #2 applied\n";
    cout << "[6/7] ✓ AES-256-CBC encryption applied\n";
    
    // Process REAL message through Dante's inferno
    char* real_msg = new char[plaintext_len + 1];
    strcpy(real_msg, plaintext);
    
    // Limbo
    altCC(real_msg, k_altCC, plaintext_len);
    
    // Lust
    char* wood_encrypted = wood(real_msg, k_wood, plaintext_len);
    int wood_len = strlen(wood_encrypted);
    
    // Gluttony
    int* ascii_codes = new int[wood_len];
    for (int j = 0; j < wood_len; j++) {
        ascii_codes[j] = (int)wood_encrypted[j];
    }
    
    // Greed
    int** bin = vTBin(ascii_codes, wood_len);
    bin = exohr(bin, k_exohr_1, wood_len);
    
    // Wrath
    bin = exohr(bin, k_exohr_2, wood_len);
    
    // Convert back from binary
    int* xor_result = BinTv(bin, wood_len);
    
    // Convert to char for the special AES-256
    unsigned char* pre_aes = new unsigned char[wood_len];
    for (int j = 0; j < wood_len; j++) {
        pre_aes[j] = (unsigned char)xor_result[j];
    }
    
    // Heresy
    unsigned char real_iv[AES_BLOCK_SIZE];
    generateRandomData(real_iv, AES_BLOCK_SIZE);
    EncryptedPayload real_payload = aes256_encrypt(pre_aes, wood_len, aes_key, real_iv);
    payloads.push_back(real_payload);
    
    // Violence
    cout << "[7/7] ✓ Generating RSA-2048 key pair and encrypting session key...\n\n";
    RSA* rsa = generateRSAKeyPair(2048);
    //! Fraud and Treachery might add later. more custom shit ig
    
    // Save private key
    FILE* priv_file = fopen("private_key.pem", "wb");
    PEM_write_RSAPrivateKey(priv_file, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(priv_file);
    
    // Encrypt AES key with RSA
    int rsa_encrypted_len;
    unsigned char* rsa_encrypted = rsa_encrypt(rsa, aes_key, 32, rsa_encrypted_len);
    
    // Save everything
    saveEncryptedPayload("output.enc", payloads, rsa_encrypted, rsa_encrypted_len);
    writeToFile("salt.bin", salt, 16);
    
    cout << "╔════════════════════════════════════════════╗\n";
    cout << "║           ENCRYPTION COMPLETE!             ║\n";
    cout << "╠════════════════════════════════════════════╣\n";
    cout << "║ Layer 1: Alternative Caesar Cipher    ✓    ║\n";
    cout << "║ Layer 2: Wood Cipher (Transposition)  ✓    ║\n";
    cout << "║ Layer 3: XOR Encryption #1            ✓    ║\n";
    cout << "║ Layer 4: XOR Encryption #2            ✓    ║\n";
    cout << "║ Layer 5: AES-256-CBC                  ✓    ║\n";
    cout << "║ Layer 6: RSA-2048                     ✓    ║\n";
    cout << "║ Layer 7: HMAC-SHA256 Authentication   ✓    ║\n";
    cout << "╠════════════════════════════════════════════╣\n";
    cout << "║ 5 payloads: 4 minions + 1 real        ✓    ║\n";
    cout << "╚════════════════════════════════════════════╝\n\n";
    
    cout << "Files created:\n";
    cout << "  → output.enc (encrypted data)\n";
    cout << "  → private_key.pem (shhhhhh......)\n";
    cout << "  → salt.bin (needed for decryption)\n\n";
    
    // Purge them all
    for (auto& payload : payloads) {
        delete[] payload.data;
    }
    delete[] plaintext;
    delete[] real_msg;
    delete[] wood_encrypted;
    delete[] ascii_codes;
    freeBinM(bin, wood_len);
    delete[] xor_result;
    delete[] pre_aes;
    delete[] rsa_encrypted;
    RSA_free(rsa);
}

void decrypt() {
    cout << "\n╔════════════════════════════════════════════╗\n";
    cout << "║               DECRYPTION CIFERA            ║\n";
    cout << "╚════════════════════════════════════════════╝\n\n";
    
    // Load encrypted payloads
    vector<EncryptedPayload> payloads;
    unsigned char* rsa_encrypted;
    int rsa_encrypted_len;
    
    if (!loadEncryptedPayload("output.enc", payloads, &rsa_encrypted, rsa_encrypted_len)) {
        return;
    }
    
    cout << "[✓] Loaded " << payloads.size() << " encrypted payloads\n";
    
    // Load RSA private key
    FILE* priv_file = fopen("private_key.pem", "rb");
    if (!priv_file) {
        cout << "Error: private_key.pem not found!" << endl;
        return;
    }
    
    RSA* rsa = PEM_read_RSAPrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);
    cout << "[✓] Loaded RSA-2048 private key\n";
    
    int decrypted_key_len;
    unsigned char* decrypted_key = rsa_decrypt(rsa, rsa_encrypted, rsa_encrypted_len, decrypted_key_len);
    
    if (decrypted_key == nullptr) {
        cout << "Failed to decrypt session key!" << endl;
        return;
    }
    cout << "[7/7] ✓ RSA-2048 decryption\n";
    
    // Load salt
    int salt_len;
    unsigned char* salt = (unsigned char*)readFromFile("salt.bin", salt_len);
    
    // Get password
    cout << "\nEnter decryption password: ";
    char password[256];
    cin.getline(password, 256);
    
    // Derive AES key
    unsigned char aes_key[32];
    unsigned char aes_iv[AES_BLOCK_SIZE];
    deriveKey(password, salt, aes_key, aes_iv);
    
    // Verify password
    if (memcmp(aes_key, decrypted_key, 32) != 0) {
        cout << "\n[✗] ERROR: Incorrect password!\n";
        return;
    }
    
    cout << "[✓] Password verified\n\n";
    
    EncryptedPayload& real_payload = payloads[4];
    
    unsigned char* aes_decrypted = aes256_decrypt(real_payload, aes_key);
    if (aes_decrypted == nullptr) {
        cout << "[✗] Decryption failed!" << endl;
        return;
    }
    cout << "[6/7] ✓ AES-256-CBC decryption + HMAC verification\n";
    
    int aes_len = strlen((char*)aes_decrypted);
    
    // Convert to int array for XOR
    int* xor_input = new int[aes_len];
    for (int i = 0; i < aes_len; i++) {
        xor_input[i] = (int)aes_decrypted[i];
    }
    
    int** bin = vTBin(xor_input, aes_len);
    bin = exohr(bin, k_exohr_2, aes_len);
    cout << "[5/7] ✓ XOR Layer #2 reversed\n";
    
    bin = exohr(bin, k_exohr_1, aes_len);
    cout << "[4/7] ✓ XOR Layer #1 reversed\n";
    
    // Convert back to ASCII
    int* ascii_result = BinTv(bin, aes_len);
    
    // Convert to char
    char* wood_decrypted = new char[aes_len + 1];
    for (int i = 0; i < aes_len; i++) {
        wood_decrypted[i] = (char)ascii_result[i];
    }
    wood_decrypted[aes_len] = '\0';
    
    char* caesar_encrypted = wood_decrypt(wood_decrypted, k_wood, aes_len);
    cout << "[3/7] ✓ Wood Cipher reversed\n";
    
    int caesar_len = strlen(caesar_encrypted);
    altCC_decrypt(caesar_encrypted, k_altCC, caesar_len);
    cout << "[2/7] ✓ Alternative Caesar Cipher reversed\n";
    
    // Save result
    ofstream outFile("d_output.txt");
    outFile << caesar_encrypted;
    outFile.close();

    // Welcome back from Hell
    
    cout << "[1/7] ✓ Original message recovered!\n\n";
    
    cout << "╔════════════════════════════════════════════╗\n";
    cout << "║          DECRYPTION COMPLETE!              ║\n";
    cout << "╠════════════════════════════════════════════╣\n";
    cout << "║ All 7 layers successfully reversed!   ✓    ║\n";
    cout << "║ Message authenticated and verified!   ✓    ║\n";
    cout << "╚════════════════════════════════════════════╝\n\n";
    
    cout << "Decrypted message saved to: decrypted_output.txt\n\n";
    
    // Purge them all
    for (auto& payload : payloads) {
        delete[] payload.data;
    }
    delete[] rsa_encrypted;
    delete[] decrypted_key;
    delete[] aes_decrypted;
    delete[] xor_input;
    freeBinM(bin, aes_len);
    delete[] ascii_result;
    delete[] wood_decrypted;
    delete[] caesar_encrypted;
    delete[] salt;
    RSA_free(rsa);
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    int choice;
    cout << "\n╔═══════════════════════════════════════════════╗\n";
    cout << "║           7-LAYER ENCRYPTION CIFERA           ║\n";
    cout << "╠═══════════════════════════════════════════════╣\n";
    cout << "║                                               ║\n";
    cout << "║  CUSTOM LAYERS:                               ║\n";
    cout << "║    1. Alternative Caesar Cipher           ✓   ║\n";
    cout << "║    2. Wood Cipher (Transposition)         ✓   ║\n";
    cout << "║    3. XOR Encryption #1                   ✓   ║\n";
    cout << "║    4. XOR Encryption #2                   ✓   ║\n";
    cout << "║                                               ║\n";
    cout << "║  THE SPECIAL LAYERS:                          ║\n";
    cout << "║    5. AES-256-CBC Encryption              ✓   ║\n";
    cout << "║    6. RSA-2048 Key Exchange               ✓   ║\n";
    cout << "║    7. HMAC-SHA256 Authentication          ✓   ║\n";
    cout << "║                                               ║\n";
    cout << "║  BONUS DUMBASS SHIT:                          ║\n";
    cout << "║    • PBKDF2 Key Derivation (100k iter)    ✓   ║\n";
    cout << "║    • 4 MINIONS                            ✓   ║\n";
    cout << "║                                               ║\n";
    cout << "╚═══════════════════════════════════════════════╝\n\n";
    
    cout << "1. Encrypt Message\n";
    cout << "2. Decrypt Message\n";
    cout << "\nEnter your choice (1 or 2): ";
    cin >> choice;
    cin.ignore();
    
    if (choice == 1) {
        encrypt();
    } else if (choice == 2) {
        decrypt();
    } else {
        cout << "Invalid choice!\n";
    }
    
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}