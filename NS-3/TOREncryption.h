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
    static std::mutex keysMutex;

    static std::string GenerateKey(int length = 32) {
        std::vector<unsigned char> key(length);
        if (1 != RAND_bytes(key.data(), length)) {
            throw std::runtime_error("TOREncryption::GenerateKey: RAND_bytes failed");
        }
        return std::string(reinterpret_cast<char*>(key.data()), length);
    }

    static void InitializeKeys(int numLayers) {
        std::lock_guard<std::mutex> lock(keysMutex);
        keys.clear();
        for (int i = 0; i < numLayers; ++i) {
            keys.push_back(GenerateKey());
        }
    }

    static std::string EncryptLayer(const std::string &data, int layer) {
        std::lock_guard<std::mutex> lock(keysMutex);
        if (layer < 0 || layer >= static_cast<int>(keys.size())) {
            throw std::runtime_error("Invalid layer");
        }

        std::string encrypted;

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            throw std::runtime_error("TOREncryption::EncryptLayer: EVP_CIPHER_CTX_new failed");
        }

        if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(keys[layer].c_str()), reinterpret_cast<const unsigned char*>(keys[layer].c_str()))) {
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

        encrypted = std::string(reinterpret_cast<char*>(ciphertext.get()), ciphertext_len);

        return encrypted;
    }

    static std::string DecryptLayer(const std::string &data, int layer) {
        std::lock_guard<std::mutex> lock(keysMutex);
        if (layer < 0 || layer >= static_cast<int>(keys.size())) {
            throw std::runtime_error("Invalid layer");
        }

        std::string decrypted;

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx) {
            throw std::runtime_error("TOREncryption::DecryptLayer: EVP_CIPHER_CTX_new failed");
        }

        if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(keys[layer].c_str()), reinterpret_cast<const unsigned char*>(keys[layer].c_str()))) {
            throw std::runtime_error("TOREncryption::DecryptLayer: EVP_DecryptInit_ex failed");
        }

        std::unique_ptr<unsigned char[]> plaintext(new unsigned char[data.length()]);
        int plaintext_len;
        int len;

        if (1 != EVP_DecryptUpdate(ctx.get(), plaintext.get(), &len, reinterpret_cast<const unsigned char*>(data.c_str()), data.length())) {
            throw std::runtime_error("TOREncryption::DecryptLayer: EVP_DecryptUpdate failed");
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
std::mutex TOREncryption::keysMutex;

#endif // TORENCRYPTION_H
