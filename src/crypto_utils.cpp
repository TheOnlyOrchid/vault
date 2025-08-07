#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <sstream>
#include <iomanip>

// Generate random bytes for salt or IV
std::vector<unsigned char> CryptoUtils::generateRandom(int length) {
    std::vector<unsigned char> buffer(length);
    if (RAND_bytes(buffer.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return buffer;
}

std::vector<unsigned char> CryptoUtils::deriveKey(const std::string& password,
    const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(32); // 256 bits

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
        salt.data(), salt.size(),
        100000, // iterations
        EVP_sha256(),
        32, key.data()) != 1) {
        throw std::runtime_error("Key derivation failed");
    }
    return key;
}

std::string CryptoUtils::bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<unsigned char> CryptoUtils::hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string CryptoUtils::encrypt(const std::string& plaintext,
    const std::vector<unsigned char>& key) {
    std::vector<unsigned char> iv = generateRandom(12); // 96-bit IV for GCM
    std::vector<unsigned char> tag(16); // 128-bit tag
    std::vector<unsigned char> ciphertext(plaintext.length());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
        reinterpret_cast<const unsigned char*>(plaintext.c_str()),
        plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get authentication tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    return bytesToHex(iv) + bytesToHex(tag) + bytesToHex(ciphertext);
}

std::string CryptoUtils::decrypt(const std::string& encryptedHex,
    const std::vector<unsigned char>& key) {
    if (encryptedHex.length() < 56) {
        throw std::runtime_error("Invalid encrypted data format");
    }

    std::vector<unsigned char> iv = hexToBytes(encryptedHex.substr(0, 24));
    std::vector<unsigned char> tag = hexToBytes(encryptedHex.substr(24, 32));
    std::vector<unsigned char> ciphertext = hexToBytes(encryptedHex.substr(56));
    std::vector<unsigned char> plaintext(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed - invalid tag or corrupted data");
    }

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}