#include "password_manager.h"

#include "crypto_utils.h"
#include "file_utils.h"
#include "external/json/json.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>

namespace {
using json = nlohmann::json;

constexpr std::array<unsigned char, 4> kVaultMagic = {
    static_cast<unsigned char>('V'),
    static_cast<unsigned char>('L'),
    static_cast<unsigned char>('T'),
    static_cast<unsigned char>('1')
};
constexpr std::uint8_t kKdfIdPbkdf2Sha256 = 1;

std::uint32_t readU32BE(const std::vector<unsigned char>& bytes, std::size_t offset) {
    if (offset + 4 > bytes.size()) {
        throw std::runtime_error("Invalid vault header size");
    }
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
}

void appendU32BE(std::vector<unsigned char>& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>((value >> 24U) & 0xFFU));
    out.push_back(static_cast<unsigned char>((value >> 16U) & 0xFFU));
    out.push_back(static_cast<unsigned char>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<unsigned char>(value & 0xFFU));
}

bool isAscii(const std::string& value) {
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch <= 0x7FU;
    });
}
}

const std::string PasswordManager::dataFile = "vault.dat";

std::uint64_t PasswordManager::nowEpochSeconds() {
    const auto now = std::chrono::system_clock::now();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
    return static_cast<std::uint64_t>(secs.count());
}

std::string PasswordManager::generateUuidHex() {
    return CryptoUtils::bytesToHex(CryptoUtils::generateRandom(16));
}

std::string PasswordManager::toFieldValueTypeString(FieldValueType type) {
    switch (type) {
        case FieldValueType::text:
            return "text";
        case FieldValueType::password:
            return "password";
        case FieldValueType::url:
            return "url";
        case FieldValueType::username:
            return "username";
    }
    throw std::runtime_error("Unknown field value type");
}

PasswordManager::FieldValueType PasswordManager::parseFieldValueType(const std::string& value) {
    if (value == "text") return FieldValueType::text;
    if (value == "password") return FieldValueType::password;
    if (value == "url") return FieldValueType::url;
    if (value == "username") return FieldValueType::username;
    throw std::runtime_error("Invalid field value type");
}

std::vector<unsigned char> PasswordManager::buildBlob(std::uint32_t iterations,
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& tag,
    const secure::SecureBytes& ciphertext) {
    if (salt.size() > 255 || iv.size() > 255 || tag.size() > 255) {
        throw std::runtime_error("Vault component too large");
    }

    std::vector<unsigned char> blob;
    blob.reserve(12 + salt.size() + iv.size() + tag.size() + ciphertext.size());
    blob.insert(blob.end(), kVaultMagic.begin(), kVaultMagic.end());
    blob.push_back(kKdfIdPbkdf2Sha256);
    appendU32BE(blob, iterations);
    blob.push_back(static_cast<unsigned char>(salt.size()));
    blob.push_back(static_cast<unsigned char>(iv.size()));
    blob.push_back(static_cast<unsigned char>(tag.size()));
    blob.insert(blob.end(), salt.begin(), salt.end());
    blob.insert(blob.end(), iv.begin(), iv.end());
    blob.insert(blob.end(), tag.begin(), tag.end());
    blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());
    return blob;
}

void PasswordManager::parseBlob(const std::vector<unsigned char>& blob,
    std::uint32_t& outIterations,
    std::vector<unsigned char>& outSalt,
    std::vector<unsigned char>& outIv,
    std::vector<unsigned char>& outTag,
    std::vector<unsigned char>& outCiphertext) {
    if (blob.size() < 12) {
        throw std::runtime_error("Vault blob too small");
    }
    if (!std::equal(kVaultMagic.begin(), kVaultMagic.end(), blob.begin())) {
        throw std::runtime_error("Invalid vault header");
    }
    if (blob[4] != kKdfIdPbkdf2Sha256) {
        throw std::runtime_error("Unsupported KDF");
    }

    outIterations = readU32BE(blob, 5);
    if (outIterations == 0) {
        throw std::runtime_error("Invalid KDF iteration count");
    }
    const std::size_t saltLen = blob[9];
    const std::size_t ivLen = blob[10];
    const std::size_t tagLen = blob[11];

    const std::size_t headerDataSize = 12 + saltLen + ivLen + tagLen;
    if (blob.size() < headerDataSize) {
        throw std::runtime_error("Corrupt vault blob");
    }

    if (saltLen != saltLength || ivLen != ivLength || tagLen != tagLength) {
        throw std::runtime_error("Unexpected vault parameter sizes");
    }

    std::size_t offset = 12;
    outSalt.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                   blob.begin() + static_cast<std::ptrdiff_t>(offset + saltLen));
    offset += saltLen;

    outIv.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                 blob.begin() + static_cast<std::ptrdiff_t>(offset + ivLen));
    offset += ivLen;

    outTag.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                  blob.begin() + static_cast<std::ptrdiff_t>(offset + tagLen));
    offset += tagLen;

    outCiphertext.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset), blob.end());
}

PasswordManager::Entry* PasswordManager::findPasswordEntry(const std::string& service) {
    return const_cast<Entry*>(static_cast<const PasswordManager*>(this)->findPasswordEntry(service));
}

const PasswordManager::Entry* PasswordManager::findPasswordEntry(const std::string& service) const {
    const auto it = std::find_if(entries_.begin(), entries_.end(), [&](const Entry& entry) {
        return entry.type == "password" && entry.title == service;
    });
    return (it == entries_.end()) ? nullptr : &(*it);
}

bool PasswordManager::initialize(const SecretString& masterPassword) {
    try {
        const auto pwView = masterPassword.view();
        if (pwView.empty()) {
            throw std::runtime_error("Master password cannot be empty");
        }

        kdfParams_.algorithm = "PBKDF2";
        kdfParams_.digest = "SHA256";
        kdfParams_.iterations = kdfIterations;
        kdfParams_.key_length = 32;

        if (FileUtils::fileExists(dataFile)) {
            const std::vector<unsigned char> blob = FileUtils::readFileBytes(dataFile);
            std::uint32_t fileIterations = 0;
            std::vector<unsigned char> iv;
            std::vector<unsigned char> tag;
            std::vector<unsigned char> ciphertext;
            parseBlob(blob, fileIterations, salt_, iv, tag, ciphertext);

            kdfParams_.iterations = static_cast<int>(fileIterations);
            key = CryptoUtils::deriveKey(
                std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(pwView.data()), pwView.size()),
                salt_,
                kdfParams_.iterations);

            const secure::SecureBytes plaintext = CryptoUtils::decryptRaw(ciphertext,
                std::span<const unsigned char>(key.data(), key.size()),
                iv,
                tag);
            if (plaintext.empty()) {
                throw std::runtime_error("Vault payload is empty");
            }

            const char* plaintextBegin = reinterpret_cast<const char*>(plaintext.data());
            const char* plaintextEnd = plaintextBegin + plaintext.size();
            const json root = json::parse(plaintextBegin, plaintextEnd);

            if (!root.is_object() || !root.contains("global") || !root.contains("entries")) {
                throw std::runtime_error("Invalid vault payload structure");
            }

            const json global = root.at("global");
            if (!global.is_object() || !global.contains("kdfParams") || !global.contains("salt")) {
                throw std::runtime_error("Invalid global payload");
            }

            const json kdf = global.at("kdfParams");
            if (!kdf.is_object()) {
                throw std::runtime_error("Invalid kdfParams payload");
            }

            kdfParams_.algorithm = kdf.at("algorithm").get<std::string>();
            kdfParams_.digest = kdf.at("digest").get<std::string>();
            kdfParams_.iterations = kdf.at("iterations").get<int>();
            kdfParams_.key_length = kdf.at("key_length").get<int>();

            if (kdfParams_.algorithm != "PBKDF2" || kdfParams_.digest != "SHA256" ||
                kdfParams_.iterations <= 0 || kdfParams_.key_length != 32) {
                throw std::runtime_error("Unsupported KDF parameters");
            }
            if (kdfParams_.iterations != static_cast<int>(fileIterations)) {
                throw std::runtime_error("KDF iteration mismatch");
            }

            const std::vector<unsigned char> saltInPayload = CryptoUtils::hexToBytes(global.at("salt").get<std::string>());
            if (saltInPayload != salt_) {
                throw std::runtime_error("Vault salt mismatch");
            }

            const json entries = root.at("entries");
            if (!entries.is_array()) {
                throw std::runtime_error("Invalid entries payload");
            }

            entries_.clear();
            entries_.reserve(entries.size());

            for (const auto& entryJson : entries) {
                if (!entryJson.is_object()) {
                    throw std::runtime_error("Invalid entry payload");
                }

                Entry entry;
                entry.uuid = entryJson.at("uuid").get<std::string>();
                entry.type = entryJson.at("type").get<std::string>();
                entry.title = entryJson.at("title").get<std::string>();
                entry.creation_time = entryJson.at("creation_time").get<std::uint64_t>();
                entry.last_update_time = entryJson.at("last_update_time").get<std::uint64_t>();

                const json tags = entryJson.at("tags");
                if (!tags.is_array()) {
                    throw std::runtime_error("Invalid entry tags");
                }
                for (const auto& tagValue : tags) {
                    const std::string tag = tagValue.get<std::string>();
                    if (!isAscii(tag)) {
                        throw std::runtime_error("Tags must be ASCII");
                    }
                    entry.tags.push_back(tag);
                }

                const json fields = entryJson.at("fields");
                if (!fields.is_array()) {
                    throw std::runtime_error("Invalid entry fields");
                }
                for (const auto& fieldJson : fields) {
                    if (!fieldJson.is_object()) {
                        throw std::runtime_error("Invalid field payload");
                    }

                    Field field;
                    field.key = fieldJson.at("key").get<std::string>();
                    std::string valueHex = fieldJson.at("value").get<std::string>();
                    field.value = CryptoUtils::hexToSecureBytes(valueHex);
                    secure::zeroize(valueHex.data(), valueHex.size());
                    valueHex.clear();
                    valueHex.shrink_to_fit();
                    field.is_secret = fieldJson.at("is_secret").get<bool>();
                    field.value_type = parseFieldValueType(fieldJson.at("value_type").get<std::string>());
                    entry.fields.push_back(std::move(field));
                }

                entries_.push_back(std::move(entry));
            }

            return true;
        }

        salt_ = CryptoUtils::generateRandom(saltLength);
        key = CryptoUtils::deriveKey(
            std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(pwView.data()), pwView.size()),
            salt_,
            kdfParams_.iterations);

        entries_.clear();
        saveToFile();
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Initialization failed: " << e.what() << std::endl;
        return false;
    }
}

void PasswordManager::addPassword(const std::string& service, const SecretString& password) {
    if (service.empty()) {
        throw std::runtime_error("Service must not be empty");
    }

    Entry* entry = findPasswordEntry(service);
    const std::uint64_t now = nowEpochSeconds();

    if (!entry) {
        Entry newEntry;
        newEntry.uuid = generateUuidHex();
        newEntry.type = "password";
        newEntry.title = service;
        newEntry.creation_time = now;
        newEntry.last_update_time = now;

        Field passwordField;
        passwordField.key = "password";
        const auto pwView = password.view();
        passwordField.value.assign(
            reinterpret_cast<const unsigned char*>(pwView.data()),
            reinterpret_cast<const unsigned char*>(pwView.data()) + pwView.size());
        passwordField.is_secret = true;
        passwordField.value_type = FieldValueType::password;
        newEntry.fields.push_back(std::move(passwordField));

        entries_.push_back(std::move(newEntry));
    }
    else {
        entry->last_update_time = now;

        auto fieldIt = std::find_if(entry->fields.begin(), entry->fields.end(), [](const Field& field) {
            return field.key == "password";
        });

        const auto pwView = password.view();

        if (fieldIt == entry->fields.end()) {
            Field passwordField;
            passwordField.key = "password";
            passwordField.value.assign(
                reinterpret_cast<const unsigned char*>(pwView.data()),
                reinterpret_cast<const unsigned char*>(pwView.data()) + pwView.size());
            passwordField.is_secret = true;
            passwordField.value_type = FieldValueType::password;
            entry->fields.push_back(std::move(passwordField));
        }
        else {
            fieldIt->value.assign(
                reinterpret_cast<const unsigned char*>(pwView.data()),
                reinterpret_cast<const unsigned char*>(pwView.data()) + pwView.size());
            fieldIt->is_secret = true;
            fieldIt->value_type = FieldValueType::password;
        }
    }

    saveToFile();
}

SecretString PasswordManager::getPassword(const std::string& service) const {
    const Entry* entry = findPasswordEntry(service);
    if (!entry) {
        return SecretString();
    }

    const auto fieldIt = std::find_if(entry->fields.begin(), entry->fields.end(), [](const Field& field) {
        return field.key == "password";
    });
    if (fieldIt == entry->fields.end()) {
        return SecretString();
    }

    SecretString out;
    out.assign(std::string_view(reinterpret_cast<const char*>(fieldIt->value.data()), fieldIt->value.size()));
    return out;
}

std::vector<std::string> PasswordManager::listServices() const {
    std::vector<std::string> services;
    services.reserve(entries_.size());

    for (const Entry& entry : entries_) {
        if (entry.type == "password") {
            services.push_back(entry.title);
        }
    }

    std::sort(services.begin(), services.end());
    return services;
}

bool PasswordManager::deletePassword(const std::string& service) {
    const auto it = std::find_if(entries_.begin(), entries_.end(), [&](const Entry& entry) {
        return entry.type == "password" && entry.title == service;
    });

    if (it == entries_.end()) {
        return false;
    }

    entries_.erase(it);
    saveToFile();
    return true;
}

void PasswordManager::saveToFile() {
    if (key.empty() || salt_.size() != saltLength) {
        throw std::runtime_error("Password manager is not initialized");
    }

    json root;
    root["global"] = {
        {"kdfParams", {
            {"algorithm", kdfParams_.algorithm},
            {"digest", kdfParams_.digest},
            {"iterations", kdfParams_.iterations},
            {"key_length", kdfParams_.key_length}
        }},
        {"salt", CryptoUtils::bytesToHex(salt_)}
    };

    root["entries"] = json::array();
    for (const Entry& entry : entries_) {
        json entryJson;
        entryJson["uuid"] = entry.uuid;
        entryJson["type"] = entry.type;
        entryJson["title"] = entry.title;
        entryJson["creation_time"] = entry.creation_time;
        entryJson["last_update_time"] = entry.last_update_time;
        entryJson["tags"] = entry.tags;

        entryJson["fields"] = json::array();
        for (const Field& field : entry.fields) {
            entryJson["fields"].push_back({
                {"key", field.key},
                {"value", CryptoUtils::bytesToHex(std::span<const unsigned char>(field.value.data(), field.value.size()))},
                {"is_secret", field.is_secret},
                {"value_type", toFieldValueTypeString(field.value_type)}
            });
        }

        root["entries"].push_back(std::move(entryJson));
    }

    std::string plaintextJson = root.dump();
    secure::SecureBytes plaintextBytes;
    plaintextBytes.assign(
        reinterpret_cast<const unsigned char*>(plaintextJson.data()),
        reinterpret_cast<const unsigned char*>(plaintextJson.data()) + plaintextJson.size());
    secure::zeroize(plaintextJson.data(), plaintextJson.size());
    plaintextJson.clear();
    plaintextJson.shrink_to_fit();

    const std::vector<unsigned char> iv = CryptoUtils::generateRandom(ivLength);
    std::vector<unsigned char> tag;
    const secure::SecureBytes ciphertext = CryptoUtils::encryptRaw(
        std::span<const unsigned char>(plaintextBytes.data(), plaintextBytes.size()),
        std::span<const unsigned char>(key.data(), key.size()),
        iv,
        tag);
    secure::zeroize(plaintextBytes.data(), plaintextBytes.size());
    plaintextBytes.clear();

    const std::vector<unsigned char> blob = buildBlob(
        static_cast<std::uint32_t>(kdfParams_.iterations),
        salt_,
        iv,
        tag,
        ciphertext);
    FileUtils::writeFileAtomic(dataFile, blob);
}

void PasswordManager::loadFromFile() {
    // Loading is now handled during initialize() to ensure the key/salt/KDF metadata are validated together.
}
