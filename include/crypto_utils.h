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
        const std::vector<unsigned char>& salt);
    static std::string bytesToHex(const std::vector<unsigned char>& bytes);
    static std::vector<unsigned char> hexToBytes(const std::string& hex);
    static std::string encrypt(std::span<const unsigned char> plaintext,
        std::span<const unsigned char> key);
    static secure::SecureBytes decryptToBytes(const std::string& encryptedHex,
        std::span<const unsigned char> key);
};
