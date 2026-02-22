#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cctype>
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

secure::SecureBytes CryptoUtils::deriveKey(std::span<const unsigned char> password,
    const std::vector<unsigned char>& salt,
    int iterations) {
    secure::SecureBytes key(32); // 256 bits

    if (iterations <= 0) {
        throw std::runtime_error("Invalid PBKDF2 iteration count");
    }

    if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(password.data()),
        static_cast<int>(password.size()),
        salt.data(), salt.size(),
        iterations,
        EVP_sha256(),
        32, key.data()) != 1) {
        throw std::runtime_error("Key derivation failed");
    }
    return key;
}

std::string CryptoUtils::bytesToHex(const std::vector<unsigned char>& bytes) {
    return bytesToHex(std::span<const unsigned char>(bytes.data(), bytes.size()));
}

std::string CryptoUtils::bytesToHex(std::span<const unsigned char> bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const unsigned char byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<unsigned char> CryptoUtils::hexToBytes(const std::string& hex) {
    if ((hex.size() % 2) != 0) {
        throw std::runtime_error("Invalid hex length");
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        const char c1 = hex[i];
        const char c2 = hex[i + 1];
        if (!std::isxdigit(static_cast<unsigned char>(c1)) ||
            !std::isxdigit(static_cast<unsigned char>(c2))) {
            throw std::runtime_error("Invalid hex character");
        }

        const unsigned char high = static_cast<unsigned char>(std::isdigit(static_cast<unsigned char>(c1))
            ? (c1 - '0')
            : (std::tolower(static_cast<unsigned char>(c1)) - 'a' + 10));
        const unsigned char low = static_cast<unsigned char>(std::isdigit(static_cast<unsigned char>(c2))
            ? (c2 - '0')
            : (std::tolower(static_cast<unsigned char>(c2)) - 'a' + 10));
        bytes.push_back(static_cast<unsigned char>((high << 4U) | low));
    }
    return bytes;
}

secure::SecureBytes CryptoUtils::hexToSecureBytes(const std::string& hex) {
    if ((hex.size() % 2) != 0) {
        throw std::runtime_error("Invalid hex length");
    }

    secure::SecureBytes bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        const char c1 = hex[i];
        const char c2 = hex[i + 1];
        if (!std::isxdigit(static_cast<unsigned char>(c1)) ||
            !std::isxdigit(static_cast<unsigned char>(c2))) {
            throw std::runtime_error("Invalid hex character");
        }

        const unsigned char high = static_cast<unsigned char>(std::isdigit(static_cast<unsigned char>(c1))
            ? (c1 - '0')
            : (std::tolower(static_cast<unsigned char>(c1)) - 'a' + 10));
        const unsigned char low = static_cast<unsigned char>(std::isdigit(static_cast<unsigned char>(c2))
            ? (c2 - '0')
            : (std::tolower(static_cast<unsigned char>(c2)) - 'a' + 10));
        bytes.push_back(static_cast<unsigned char>((high << 4U) | low));
    }
    return bytes;
}

secure::SecureBytes CryptoUtils::encryptRaw(std::span<const unsigned char> plaintext,
    std::span<const unsigned char> key,
    const std::vector<unsigned char>& iv,
    std::vector<unsigned char>& outTag) {
    if (iv.empty()) {
        throw std::runtime_error("IV must not be empty");
    }
    outTag.assign(16, 0U); // 128-bit GCM tag
    secure::SecureBytes ciphertext(plaintext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    int len = 0;
    int totalLen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
        plaintext.data(),
        static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }
    totalLen += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + totalLen, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    totalLen += len;
    ciphertext.resize(static_cast<std::size_t>(totalLen));

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, outTag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get authentication tag");
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

secure::SecureBytes CryptoUtils::decryptRaw(std::span<const unsigned char> ciphertext,
    std::span<const unsigned char> key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& tag) {
    if (iv.empty()) {
        throw std::runtime_error("IV must not be empty");
    }
    if (tag.size() != 16) {
        throw std::runtime_error("Invalid tag length");
    }

    secure::SecureBytes plaintext(ciphertext.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    int len = 0;
    int totalLen = 0;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }
    totalLen += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<unsigned char*>(tag.data())) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext.data() + totalLen, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed - invalid tag or corrupted data");
    }
    totalLen += len;
    plaintext.resize(static_cast<std::size_t>(totalLen));

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

std::string CryptoUtils::encrypt(std::span<const unsigned char> plaintext,
    std::span<const unsigned char> key) {
    std::vector<unsigned char> iv = generateRandom(12); // 96-bit IV for GCM
    std::vector<unsigned char> tag;
    secure::SecureBytes ciphertext = encryptRaw(plaintext, key, iv, tag);

    return bytesToHex(iv) +
        bytesToHex(tag) +
        bytesToHex(std::span<const unsigned char>(ciphertext.data(), ciphertext.size()));
}

secure::SecureBytes CryptoUtils::decryptToBytes(const std::string& encryptedHex,
    std::span<const unsigned char> key) {
    if (encryptedHex.length() < 56) {
        throw std::runtime_error("Invalid encrypted data format");
    }

    std::vector<unsigned char> iv = hexToBytes(encryptedHex.substr(0, 24));
    std::vector<unsigned char> tag = hexToBytes(encryptedHex.substr(24, 32));
    std::vector<unsigned char> ciphertext = hexToBytes(encryptedHex.substr(56));
    return decryptRaw(ciphertext, key, iv, tag);
}
