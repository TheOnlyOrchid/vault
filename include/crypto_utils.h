#pragma once

#include <vector>
#include <string>
#include <stdexcept>
#include <span>

#include "secure_memory.h"

class CryptoUtils {
public:
    static std::vector<unsigned char> generateRandom(int length);

    static secure::SecureBytes deriveKey(std::span<const unsigned char> password,
        const std::vector<unsigned char>& salt,
        int iterations = 100000);

    static std::string bytesToHex(const std::vector<unsigned char>& bytes);

    static std::string bytesToHex(std::span<const unsigned char> bytes);

    static std::vector<unsigned char> hexToBytes(const std::string& hex);

    static secure::SecureBytes hexToSecureBytes(const std::string& hex);

    static secure::SecureBytes encryptRaw(std::span<const unsigned char> plaintext,
        std::span<const unsigned char> key,
        const std::vector<unsigned char>& iv,
        std::vector<unsigned char>& outTag);

    static secure::SecureBytes decryptRaw(std::span<const unsigned char> ciphertext,
        std::span<const unsigned char> key,
        const std::vector<unsigned char>& iv,
        const std::vector<unsigned char>& tag);

    static std::string encrypt(std::span<const unsigned char> plaintext,
        std::span<const unsigned char> key);

    static secure::SecureBytes decryptToBytes(const std::string& encryptedHex,
        std::span<const unsigned char> key);
};
