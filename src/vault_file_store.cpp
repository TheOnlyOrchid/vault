#include "vault_file_store.h"

#include "crypto_utils.h"
#include "file_utils.h"
#include "external/json/json.hpp"

#include <algorithm>
#include <array>
#include <openssl/sha.h>
#include <span>
#include <stdexcept>

namespace {
using json = nlohmann::json;

constexpr int kSaltLength = 16;
constexpr int kIvLength = 12;
constexpr int kTagLength = 16;
constexpr int kKdfIterations = 600000;
constexpr std::uint32_t kFormatVersion = 1;

constexpr std::array<unsigned char, 8> kVaultMagic = {
    static_cast<unsigned char>('O'),
    static_cast<unsigned char>('R'),
    static_cast<unsigned char>('C'),
    static_cast<unsigned char>('H'),
    static_cast<unsigned char>('V'),
    static_cast<unsigned char>('A'),
    static_cast<unsigned char>('1'),
    static_cast<unsigned char>('\0')
};
constexpr std::uint32_t kKdfIdPbkdf2Sha256 = 1;
constexpr std::uint32_t kCipherIdAes256Gcm = 1;
constexpr std::size_t kPasswordCheckLength = 32;
constexpr std::size_t kReservedLength = 64;
constexpr std::size_t kVaultHeaderSize = 156;

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

std::array<unsigned char, kPasswordCheckLength> buildPasswordCheck(std::span<const unsigned char> key) {
    std::array<unsigned char, kPasswordCheckLength> out{};
    SHA256(key.data(), key.size(), out.data());
    return out;
}

bool isAscii(const std::string& value) {
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch <= 0x7FU;
    });
}

std::string toEntryTypeString(vault::EntryType type) {
    switch (type) {
        case vault::EntryType::password:
            return "password";
        case vault::EntryType::note:
            return "note";
        case vault::EntryType::api_key:
            return "api_key";
        case vault::EntryType::card:
            return "card";
        case vault::EntryType::identity:
            return "identity";
        case vault::EntryType::random_secret:
            return "random_secret";
    }
    throw std::runtime_error("Unknown entry type");
}

vault::EntryType parseEntryType(const std::string& value) {
    if (value == "password") return vault::EntryType::password;
    if (value == "note") return vault::EntryType::note;
    if (value == "api_key") return vault::EntryType::api_key;
    if (value == "card") return vault::EntryType::card;
    if (value == "identity") return vault::EntryType::identity;
    if (value == "random_secret") return vault::EntryType::random_secret;
    throw std::runtime_error("Invalid entry type");
}

std::string toFieldValueTypeString(vault::FieldValueType type) {
    switch (type) {
        case vault::FieldValueType::text:
            return "text";
        case vault::FieldValueType::secret:
            return "secret";
        case vault::FieldValueType::url:
            return "url";
        case vault::FieldValueType::email:
            return "email";
        case vault::FieldValueType::username:
            return "username";
        case vault::FieldValueType::password:
            return "password";
        case vault::FieldValueType::note:
            return "note";
        case vault::FieldValueType::totp_seed:
            return "totp_seed";
        case vault::FieldValueType::number:
            return "number";
        case vault::FieldValueType::date:
            return "date";
    }
    throw std::runtime_error("Unknown field value type");
}

vault::FieldValueType parseFieldValueType(const std::string& value) {
    if (value == "text") return vault::FieldValueType::text;
    if (value == "secret") return vault::FieldValueType::secret;
    if (value == "url") return vault::FieldValueType::url;
    if (value == "email") return vault::FieldValueType::email;
    if (value == "username") return vault::FieldValueType::username;
    if (value == "password") return vault::FieldValueType::password;
    if (value == "note") return vault::FieldValueType::note;
    if (value == "totp_seed") return vault::FieldValueType::totp_seed;
    if (value == "number") return vault::FieldValueType::number;
    if (value == "date") return vault::FieldValueType::date;
    throw std::runtime_error("Invalid field value type");
}

std::string secureBytesToString(std::span<const unsigned char> bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

secure::SecureBytes secureBytesFromString(const std::string& value) {
    secure::SecureBytes bytes;
    bytes.assign(
        reinterpret_cast<const unsigned char*>(value.data()),
        reinterpret_cast<const unsigned char*>(value.data()) + value.size());
    return bytes;
}

void zeroizeString(std::string& value) noexcept {
    if (!value.empty()) {
        secure::zeroize(value.data(), value.size());
        value.clear();
    }
}

std::vector<unsigned char> buildBlob(std::uint32_t iterations,
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& tag,
    std::span<const unsigned char> key,
    const secure::SecureBytes& ciphertext) {
    if (salt.size() != kSaltLength || iv.size() != kIvLength || tag.size() != kTagLength) {
        throw std::runtime_error("Unexpected vault component sizes");
    }

    std::vector<unsigned char> blob;
    blob.reserve(kVaultHeaderSize + iv.size() + tag.size() + ciphertext.size());
    blob.insert(blob.end(), kVaultMagic.begin(), kVaultMagic.end());
    appendU32BE(blob, kFormatVersion);
    appendU32BE(blob, static_cast<std::uint32_t>(kVaultHeaderSize));
    appendU32BE(blob, kKdfIdPbkdf2Sha256);
    appendU32BE(blob, iterations);
    appendU32BE(blob, 0);
    appendU32BE(blob, 0);
    blob.insert(blob.end(), salt.begin(), salt.end());
    appendU32BE(blob, kCipherIdAes256Gcm);
    appendU32BE(blob, static_cast<std::uint32_t>(iv.size()));
    appendU32BE(blob, static_cast<std::uint32_t>(tag.size()));

    const auto passwordCheck = buildPasswordCheck(key);
    blob.insert(blob.end(), passwordCheck.begin(), passwordCheck.end());
    blob.resize(blob.size() + kReservedLength, 0U);

    blob.insert(blob.end(), iv.begin(), iv.end());
    blob.insert(blob.end(), tag.begin(), tag.end());
    blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());
    return blob;
}

void parseBlob(const std::vector<unsigned char>& blob,
    std::uint32_t& outIterations,
    std::vector<unsigned char>& outSalt,
    std::vector<unsigned char>& outIv,
    std::vector<unsigned char>& outTag,
    std::span<const unsigned char> key,
    std::vector<unsigned char>& outCiphertext) {
    if (blob.size() < kVaultHeaderSize + kIvLength + kTagLength) {
        throw std::runtime_error("Vault blob too small");
    }
    if (!std::equal(kVaultMagic.begin(), kVaultMagic.end(), blob.begin())) {
        throw std::runtime_error("Invalid vault header");
    }

    const std::uint32_t version = readU32BE(blob, 8);
    if (version != kFormatVersion) {
        throw std::runtime_error("Unsupported vault format version");
    }

    const std::uint32_t headerSize = readU32BE(blob, 12);
    if (headerSize < kVaultHeaderSize || headerSize > blob.size()) {
        throw std::runtime_error("Invalid vault header size");
    }

    const std::uint32_t kdfAlgorithm = readU32BE(blob, 16);
    if (kdfAlgorithm != kKdfIdPbkdf2Sha256) {
        throw std::runtime_error("Unsupported KDF");
    }

    outIterations = readU32BE(blob, 20);
    if (outIterations == 0) {
        throw std::runtime_error("Invalid KDF iteration count");
    }

    if (readU32BE(blob, 24) != 0 || readU32BE(blob, 28) != 0) {
        throw std::runtime_error("Unsupported KDF tuning parameters");
    }

    outSalt.assign(blob.begin() + 32, blob.begin() + 32 + kSaltLength);

    const std::uint32_t cipherAlgorithm = readU32BE(blob, 48);
    if (cipherAlgorithm != kCipherIdAes256Gcm) {
        throw std::runtime_error("Unsupported cipher");
    }

    const std::uint32_t nonceSize = readU32BE(blob, 52);
    const std::uint32_t authTagSize = readU32BE(blob, 56);
    if (nonceSize != kIvLength || authTagSize != kTagLength) {
        throw std::runtime_error("Unexpected vault parameter sizes");
    }

    const auto expectedPasswordCheck = buildPasswordCheck(key);
    if (!std::equal(expectedPasswordCheck.begin(), expectedPasswordCheck.end(), blob.begin() + 60)) {
        throw std::runtime_error("Invalid master password");
    }

    std::size_t offset = headerSize;
    if (blob.size() < offset + nonceSize + authTagSize) {
        throw std::runtime_error("Corrupt vault blob");
    }

    outIv.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                 blob.begin() + static_cast<std::ptrdiff_t>(offset + nonceSize));
    offset += nonceSize;

    outTag.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                  blob.begin() + static_cast<std::ptrdiff_t>(offset + authTagSize));
    offset += authTagSize;

    outCiphertext.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset), blob.end());
}

json serializeVault(const vault::VaultData& vault) {
    json root;
    root["metadata"] = {
        {"vault_name", vault.metadata.vault_name},
        {"created_at", vault.metadata.created_at},
        {"updated_at", vault.metadata.updated_at},
        {"last_opened_at", vault.metadata.last_opened_at}
    };

    root["entries"] = json::array();
    for (const vault::Entry& entry : vault.entries) {
        json entryJson;
        entryJson["id"] = entry.id;
        entryJson["type"] = toEntryTypeString(entry.type);
        entryJson["title"] = entry.title;
        entryJson["created_at"] = entry.created_at;
        entryJson["updated_at"] = entry.updated_at;
        entryJson["last_used_at"] = entry.last_used_at;
        entryJson["favorite"] = entry.favorite;
        entryJson["archived"] = entry.archived;
        entryJson["tags"] = entry.tags;

        entryJson["fields"] = json::array();
        for (const vault::Field& field : entry.fields) {
            std::string value = secureBytesToString(std::span<const unsigned char>(field.value.data(), field.value.size()));
            entryJson["fields"].push_back({
                {"id", field.id},
                {"key", field.key},
                {"value", value},
                {"value_type", toFieldValueTypeString(field.value_type)},
                {"concealed", field.concealed},
                {"copyable", field.copyable},
                {"multiline", field.multiline},
                {"required", field.required}
            });
            zeroizeString(value);
        }

        root["entries"].push_back(std::move(entryJson));
    }

    return root;
}

void deserializeVault(const json& root, vault::VaultData& vault) {
    if (!root.is_object() || !root.contains("metadata") || !root.contains("entries")) {
        throw std::runtime_error("Invalid vault payload structure");
    }

    const json metadataJson = root.at("metadata");
    if (!metadataJson.is_object()) {
        throw std::runtime_error("Invalid vault metadata");
    }

    vault.metadata.vault_name = metadataJson.at("vault_name").get<std::string>();
    vault.metadata.created_at = metadataJson.at("created_at").get<std::uint64_t>();
    vault.metadata.updated_at = metadataJson.at("updated_at").get<std::uint64_t>();
    vault.metadata.last_opened_at = metadataJson.at("last_opened_at").get<std::uint64_t>();

    const json entries = root.at("entries");
    if (!entries.is_array()) {
        throw std::runtime_error("Invalid entries payload");
    }

    vault.entries.clear();
    vault.entries.reserve(entries.size());

    for (const auto& entryJson : entries) {
        if (!entryJson.is_object()) {
            throw std::runtime_error("Invalid entry payload");
        }

        vault::Entry entry;
        entry.id = entryJson.at("id").get<std::string>();
        entry.type = parseEntryType(entryJson.at("type").get<std::string>());
        entry.title = entryJson.at("title").get<std::string>();
        entry.created_at = entryJson.at("created_at").get<std::uint64_t>();
        entry.updated_at = entryJson.at("updated_at").get<std::uint64_t>();
        entry.last_used_at = entryJson.at("last_used_at").get<std::uint64_t>();
        entry.favorite = entryJson.at("favorite").get<bool>();
        entry.archived = entryJson.at("archived").get<bool>();

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

            vault::Field field;
            field.id = fieldJson.at("id").get<std::string>();
            field.key = fieldJson.at("key").get<std::string>();
            std::string value = fieldJson.at("value").get<std::string>();
            field.value = secureBytesFromString(value);
            zeroizeString(value);
            field.value_type = parseFieldValueType(fieldJson.at("value_type").get<std::string>());
            field.concealed = fieldJson.at("concealed").get<bool>();
            field.copyable = fieldJson.at("copyable").get<bool>();
            field.multiline = fieldJson.at("multiline").get<bool>();
            field.required = fieldJson.at("required").get<bool>();
            entry.fields.push_back(std::move(field));
        }

        vault.entries.push_back(std::move(entry));
    }
}
}

VaultFileStore::VaultFileStore(std::string dataFile)
    : data_file_(std::move(dataFile)) {}

void VaultFileStore::openOrCreate(const SecretString& masterPassword, vault::VaultData& vault) const {
    const auto pwView = masterPassword.view();
    if (pwView.empty()) {
        throw std::runtime_error("Master password cannot be empty");
    }

    if (FileUtils::fileExists(data_file_)) {
        const std::vector<unsigned char> blob = FileUtils::readFileBytes(data_file_);
        if (blob.size() < 48) {
            throw std::runtime_error("Vault blob too small");
        }

        std::vector<unsigned char> iv;
        std::vector<unsigned char> tag;
        std::vector<unsigned char> ciphertext;
        std::uint32_t fileIterations = 0;
        std::vector<unsigned char> fileSalt(blob.begin() + 32, blob.begin() + 32 + kSaltLength);

        vault.key = CryptoUtils::deriveKey(
            std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(pwView.data()), pwView.size()),
            fileSalt,
            static_cast<int>(readU32BE(blob, 20)));

        parseBlob(blob, fileIterations, vault.salt, iv, tag,
            std::span<const unsigned char>(vault.key.data(), vault.key.size()), ciphertext);

        const secure::SecureBytes plaintext = CryptoUtils::decryptRaw(ciphertext,
            std::span<const unsigned char>(vault.key.data(), vault.key.size()),
            iv,
            tag);
        if (plaintext.empty()) {
            throw std::runtime_error("Vault payload is empty");
        }

        const char* plaintextBegin = reinterpret_cast<const char*>(plaintext.data());
        const char* plaintextEnd = plaintextBegin + plaintext.size();
        deserializeVault(json::parse(plaintextBegin, plaintextEnd), vault);

        vault.metadata.last_opened_at = vault::nowEpochSeconds();
        save(vault);
        return;
    }

    vault.salt = CryptoUtils::generateRandom(kSaltLength);
    vault.key = CryptoUtils::deriveKey(
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(pwView.data()), pwView.size()),
        vault.salt,
        kKdfIterations);
    vault.entries.clear();

    const std::uint64_t now = vault::nowEpochSeconds();
    vault.metadata.vault_name = "Vault";
    vault.metadata.created_at = now;
    vault.metadata.updated_at = now;
    vault.metadata.last_opened_at = now;
    save(vault);
}

void VaultFileStore::save(const vault::VaultData& vault) const {
    if (vault.key.empty() || vault.salt.size() != kSaltLength) {
        throw std::runtime_error("Password manager is not initialized");
    }

    std::string plaintextJson = serializeVault(vault).dump();
    secure::SecureBytes plaintextBytes;
    plaintextBytes.assign(
        reinterpret_cast<const unsigned char*>(plaintextJson.data()),
        reinterpret_cast<const unsigned char*>(plaintextJson.data()) + plaintextJson.size());
    secure::zeroize(plaintextJson.data(), plaintextJson.size());
    plaintextJson.clear();
    plaintextJson.shrink_to_fit();

    const std::vector<unsigned char> iv = CryptoUtils::generateRandom(kIvLength);
    std::vector<unsigned char> tag;
    const secure::SecureBytes ciphertext = CryptoUtils::encryptRaw(
        std::span<const unsigned char>(plaintextBytes.data(), plaintextBytes.size()),
        std::span<const unsigned char>(vault.key.data(), vault.key.size()),
        iv,
        tag);
    secure::zeroize(plaintextBytes.data(), plaintextBytes.size());
    plaintextBytes.clear();

    const std::vector<unsigned char> blob = buildBlob(
        kKdfIterations,
        vault.salt,
        iv,
        tag,
        std::span<const unsigned char>(vault.key.data(), vault.key.size()),
        ciphertext);
    FileUtils::writeFileAtomic(data_file_, blob);
}
