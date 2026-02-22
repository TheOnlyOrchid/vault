#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <span>

#include "secure_memory.h"
#include "secret_string.h"

class PasswordManager {
private:
    enum class FieldValueType {
        text,
        password,
        url,
        username
    };

    struct KdfParams {
        std::string algorithm;
        std::string digest;
        int iterations = 0;
        int key_length = 0;
    };

    struct Field {
        std::string key;
        secure::SecureBytes value;
        bool is_secret = false;
        FieldValueType value_type = FieldValueType::text;
    };

    struct Entry {
        std::string uuid;
        std::string type;
        std::string title;
        std::vector<Field> fields;
        std::vector<std::string> tags;
        std::uint64_t creation_time = 0;
        std::uint64_t last_update_time = 0;
    };

    static const std::string dataFile;
    static constexpr int saltLength = 32;
    static constexpr int ivLength = 12;
    static constexpr int tagLength = 16;
    static constexpr int kdfIterations = 600000;

    KdfParams kdfParams_;
    std::vector<unsigned char> salt_;
    std::vector<Entry> entries_;
    secure::SecureBytes key;

    static std::uint64_t nowEpochSeconds();
    static std::string generateUuidHex();
    static std::string toFieldValueTypeString(FieldValueType type);
    static FieldValueType parseFieldValueType(const std::string& value);
    static std::vector<unsigned char> buildBlob(std::uint32_t iterations,
        const std::vector<unsigned char>& salt,
        const std::vector<unsigned char>& iv,
        const std::vector<unsigned char>& tag,
        const secure::SecureBytes& ciphertext);
    static void parseBlob(const std::vector<unsigned char>& blob,
        std::uint32_t& outIterations,
        std::vector<unsigned char>& outSalt,
        std::vector<unsigned char>& outIv,
        std::vector<unsigned char>& outTag,
        std::vector<unsigned char>& outCiphertext);

    Entry* findPasswordEntry(const std::string& service);
    const Entry* findPasswordEntry(const std::string& service) const;
    void saveToFile();
    void loadFromFile();

public:
    bool initialize(const SecretString& masterPassword);
    void addPassword(const std::string& service, const SecretString& password);
    SecretString getPassword(const std::string& service) const;
    std::vector<std::string> listServices() const;
    bool deletePassword(const std::string& service);
    bool isInitialized() const { return !key.empty(); }
};
