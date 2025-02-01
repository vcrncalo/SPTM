#ifndef TORENCRYPTION_H
#define TORENCRYPTION_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <memory>
#include <mutex>
#include <iostream>

class TOREncryption {
public:
    static std::vector<std::string> keys;
    static std::mutex keyMutex;

    static std::string GenerateKey(int length = 32) {
        std::vector<unsigned char> key(length);
        if (1 != RAND_bytes(key.data(), length)) {
            throw std::runtime_error("TOREncryption::GenerateKey: RAND_bytes failed");
        }
        return std::string(reinterpret_cast<char*>(key.data()), length);
    }

    static void InitializeKeys(int numLayers) {
        std::lock_guard<std::mutex> lock(keyMutex);
        keys.clear();
        for (int i = 0; i < numLayers; ++i) {
            keys.push_back(GenerateKey());
        }
    }

    static std::string EncryptLayer(const std::string &data, uint32_t layer) {
        std::lock_guard<std::mutex> lock(keyMutex);
        if (layer >= keys.size()) {
            throw std::runtime_error("TOREncryption::EncryptLayer: Invalid layer");
        }
        std::string key = keys[layer];

        // Generate a random IV
        unsigned char iv[EVP_MAX_IV_LENGTH];
        if (1 != RAND_bytes(iv, EVP_MAX_IV_LENGTH)) {
            throw std::runtime_error("TOREncryption::EncryptLayer: RAND_bytes failed for IV");
        }

        std::string encrypted;

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            throw std::runtime_error("TOREncryption::EncryptLayer: EVP_CIPHER_CTX_new failed");
        }

        if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), iv)) {
            throw std::runtime_error("TOREncryption::EncryptLayer: EVP_EncryptInit_ex failed");
        }

        std::unique_ptr<unsigned char[]> ciphertext(new unsigned char[data.length() + EVP_MAX_BLOCK_LENGTH]);
        int ciphertext_len;
        int len;

        if (1 != EVP_EncryptUpdate(ctx.get(), ciphertext.get(), &len, reinterpret_cast<const unsigned char*>(data.c_str()), data.length())) {
            throw std::runtime_error("TOREncryption::EncryptLayer: EVP_EncryptUpdate failed");
        }
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext.get() + len, &len)) {
            throw std::runtime_error("TOREncryption::EncryptFinal_ex failed");
        }
        ciphertext_len += len;

        // Prepend the IV to the ciphertext
        encrypted = std::string(reinterpret_cast<char*>(iv), EVP_MAX_IV_LENGTH) + std::string(reinterpret_cast<char*>(ciphertext.get()), ciphertext_len);

        return encrypted;
    }

    static std::string DecryptLayer(const std::string &data, uint32_t layer) {
        std::lock_guard<std::mutex> lock(keyMutex);
        if (layer >= keys.size()) {
            throw std::runtime_error("TOREncryption::DecryptLayer: Invalid layer");
        }
        std::string key = keys[layer];

        // Extract the IV from the beginning of the ciphertext
        std::string iv_str = data.substr(0, EVP_MAX_IV_LENGTH);
        unsigned char iv[EVP_MAX_IV_LENGTH];
        std::copy(iv_str.begin(), iv_str.end(), iv);

        // Get the actual ciphertext
        std::string ciphertext = data.substr(EVP_MAX_IV_LENGTH);

        std::string decrypted;

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            throw std::runtime_error("TOREncryption::DecryptLayer: EVP_CIPHER_CTX_new failed");
        }

        if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), iv)) {
            throw std::runtime_error("TOREncryption::DecryptLayer: EVP_DecryptInit_ex failed");
        }

        std::unique_ptr<unsigned char[]> plaintext(new unsigned char[ciphertext.length()]);
        int plaintext_len;
        int len;

        if (1 != EVP_DecryptUpdate(ctx.get(), plaintext.get(), &len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length())) {
            throw std::runtime_error("TOREncryption::DecryptUpdate failed");
        }
        plaintext_len = len;

        if (1 != EVP_DecryptFinal_ex(ctx.get(), plaintext.get() + len, &len)) {
            throw std::runtime_error("TOREncryption::DecryptFinal_ex failed");
        }
        plaintext_len += len;

        decrypted = std::string(reinterpret_cast<char*>(plaintext.get()), plaintext_len);

        return decrypted;
    }
};

// Define the static members
std::vector<std::string> TOREncryption::keys;
std::mutex TOREncryption::keyMutex;

#endif // TORENCRYPTION_H
