#pragma once

#include <vector>
#include <string>
#include <stdexcept>

class CryptoUtils {
public:
    static std::vector<unsigned char> generateRandom(int length);
    static std::vector<unsigned char> deriveKey(const std::string& password,
        const std::vector<unsigned char>& salt);
    static std::string bytesToHex(const std::vector<unsigned char>& bytes);
    static std::vector<unsigned char> hexToBytes(const std::string& hex);
    static std::string encrypt(const std::string& plaintext,
        const std::vector<unsigned char>& key);
    static std::string decrypt(const std::string& encryptedHex,
        const std::vector<unsigned char>& key);
};