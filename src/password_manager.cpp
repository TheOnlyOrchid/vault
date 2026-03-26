#include "password_manager.h"

#include "crypto_utils.h"
#include "file_utils.h"
#include "external/json/json.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <openssl/sha.h>
#include <span>
#include <stdexcept>

namespace {
using json = nlohmann::json;

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

std::string PasswordManager::toEntryTypeString(EntryType type) {
    switch (type) {
        case EntryType::password:
            return "password";
        case EntryType::note:
            return "note";
        case EntryType::api_key:
            return "api_key";
        case EntryType::card:
            return "card";
        case EntryType::identity:
            return "identity";
        case EntryType::random_secret:
            return "random_secret";
    }
    throw std::runtime_error("Unknown entry type");
}

PasswordManager::EntryType PasswordManager::parseEntryType(const std::string& value) {
    if (value == "password") return EntryType::password;
    if (value == "note") return EntryType::note;
    if (value == "api_key") return EntryType::api_key;
    if (value == "card") return EntryType::card;
    if (value == "identity") return EntryType::identity;
    if (value == "random_secret") return EntryType::random_secret;
    throw std::runtime_error("Invalid entry type");
}

std::string PasswordManager::toFieldValueTypeString(FieldValueType type) {
    switch (type) {
        case FieldValueType::text:
            return "text";
        case FieldValueType::secret:
            return "secret";
        case FieldValueType::url:
            return "url";
        case FieldValueType::email:
            return "email";
        case FieldValueType::username:
            return "username";
        case FieldValueType::password:
            return "password";
        case FieldValueType::note:
            return "note";
        case FieldValueType::totp_seed:
            return "totp_seed";
        case FieldValueType::number:
            return "number";
        case FieldValueType::date:
            return "date";
    }
    throw std::runtime_error("Unknown field value type");
}

PasswordManager::FieldValueType PasswordManager::parseFieldValueType(const std::string& value) {
    if (value == "text") return FieldValueType::text;
    if (value == "secret") return FieldValueType::secret;
    if (value == "url") return FieldValueType::url;
    if (value == "email") return FieldValueType::email;
    if (value == "username") return FieldValueType::username;
    if (value == "password") return FieldValueType::password;
    if (value == "note") return FieldValueType::note;
    if (value == "totp_seed") return FieldValueType::totp_seed;
    if (value == "number") return FieldValueType::number;
    if (value == "date") return FieldValueType::date;
    throw std::runtime_error("Invalid field value type");
}

std::vector<unsigned char> PasswordManager::buildBlob(std::uint32_t iterations,
    const std::vector<unsigned char>& salt,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& tag,
    std::span<const unsigned char> key,
    const secure::SecureBytes& ciphertext) {
    if (salt.size() > 255 || iv.size() > 255 || tag.size() > 255) {
        throw std::runtime_error("Vault component too large");
    }
    if (salt.size() != saltLength || iv.size() != ivLength || tag.size() != tagLength) {
        throw std::runtime_error("Unexpected vault component sizes");
    }

    std::vector<unsigned char> blob;
    blob.reserve(kVaultHeaderSize + iv.size() + tag.size() + ciphertext.size());
    blob.insert(blob.end(), kVaultMagic.begin(), kVaultMagic.end());
    appendU32BE(blob, formatVersion);
    appendU32BE(blob, static_cast<std::uint32_t>(kVaultHeaderSize));
    appendU32BE(blob, kKdfIdPbkdf2Sha256);
    appendU32BE(blob, iterations);
    appendU32BE(blob, 0);
    appendU32BE(blob, 0);
    blob.insert(blob.end(), salt.begin(), salt.end());
    appendU32BE(blob, kCipherIdAes256Gcm);
    appendU32BE(blob, static_cast<std::uint32_t>(iv.size()));
    appendU32BE(blob, static_cast<std::uint32_t>(tag.size()));

    const auto passwordCheck = buildPasswordCheck(std::span<const unsigned char>(key.data(), key.size()));
    blob.insert(blob.end(), passwordCheck.begin(), passwordCheck.end());
    blob.resize(blob.size() + kReservedLength, 0U);

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
    std::span<const unsigned char> key,
    std::vector<unsigned char>& outCiphertext) {
    if (blob.size() < kVaultHeaderSize + ivLength + tagLength) {
        throw std::runtime_error("Vault blob too small");
    }
    if (!std::equal(kVaultMagic.begin(), kVaultMagic.end(), blob.begin())) {
        throw std::runtime_error("Invalid vault header");
    }

    const std::uint32_t version = readU32BE(blob, 8);
    if (version != formatVersion) {
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

    const std::uint32_t kdfMemoryKiB = readU32BE(blob, 24);
    const std::uint32_t kdfParallelism = readU32BE(blob, 28);
    if (kdfMemoryKiB != 0 || kdfParallelism != 0) {
        throw std::runtime_error("Unsupported KDF tuning parameters");
    }

    outSalt.assign(blob.begin() + 32, blob.begin() + 32 + saltLength);

    const std::uint32_t cipherAlgorithm = readU32BE(blob, 48);
    if (cipherAlgorithm != kCipherIdAes256Gcm) {
        throw std::runtime_error("Unsupported cipher");
    }

    const std::uint32_t nonceSize = readU32BE(blob, 52);
    const std::uint32_t authTagSize = readU32BE(blob, 56);
    if (nonceSize != ivLength || authTagSize != tagLength) {
        throw std::runtime_error("Unexpected vault parameter sizes");
    }

    const auto expectedPasswordCheck = buildPasswordCheck(std::span<const unsigned char>(key.data(), key.size()));
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

std::string PasswordManager::secureBytesToString(std::span<const unsigned char> bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

secure::SecureBytes PasswordManager::secureBytesFromString(const std::string& value) {
    secure::SecureBytes bytes;
    bytes.assign(
        reinterpret_cast<const unsigned char*>(value.data()),
        reinterpret_cast<const unsigned char*>(value.data()) + value.size());
    return bytes;
}

void PasswordManager::zeroizeString(std::string& value) noexcept {
    if (!value.empty()) {
        secure::zeroize(value.data(), value.size());
        value.clear();
    }
}

PasswordManager::~PasswordManager() {
    std::future<void> worker;
    {
        std::lock_guard<std::mutex> lock(async_mutex_);
        if (async_state_.worker.valid()) {
            worker = std::move(async_state_.worker);
        }
    }

    if (worker.valid()) {
        worker.wait();
    }
}

PasswordManager::Entry* PasswordManager::findPasswordEntry(const std::string& service) {
    return const_cast<Entry*>(static_cast<const PasswordManager*>(this)->findPasswordEntry(service));
}

const PasswordManager::Entry* PasswordManager::findPasswordEntry(const std::string& service) const {
    const auto it = std::find_if(entries_.begin(), entries_.end(), [&](const Entry& entry) {
        return entry.type == EntryType::password && entry.title == service;
    });
    return (it == entries_.end()) ? nullptr : &(*it);
}

bool PasswordManager::initialize(const SecretString& masterPassword) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    try {
        const auto pwView = masterPassword.view();
        if (pwView.empty()) {
            throw std::runtime_error("Master password cannot be empty");
        }

        if (FileUtils::fileExists(dataFile)) {
            const std::vector<unsigned char> blob = FileUtils::readFileBytes(dataFile);
            std::uint32_t fileIterations = 0;
            std::vector<unsigned char> fileSalt;
            std::vector<unsigned char> iv;
            std::vector<unsigned char> tag;
            std::vector<unsigned char> ciphertext;
            if (blob.size() < 48) {
                throw std::runtime_error("Vault blob too small");
            }
            fileSalt.assign(blob.begin() + 32, blob.begin() + 32 + saltLength);
            key = CryptoUtils::deriveKey(
                std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(pwView.data()), pwView.size()),
                fileSalt,
                static_cast<int>(readU32BE(blob, 20)));

            parseBlob(blob, fileIterations, salt_, iv, tag,
                std::span<const unsigned char>(key.data(), key.size()), ciphertext);

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

            if (!root.is_object() || !root.contains("metadata") || !root.contains("entries")) {
                throw std::runtime_error("Invalid vault payload structure");
            }

            const json metadataJson = root.at("metadata");
            if (!metadataJson.is_object()) {
                throw std::runtime_error("Invalid vault metadata");
            }

            metadata_.vault_name = metadataJson.at("vault_name").get<std::string>();
            metadata_.created_at = metadataJson.at("created_at").get<std::uint64_t>();
            metadata_.updated_at = metadataJson.at("updated_at").get<std::uint64_t>();
            metadata_.last_opened_at = metadataJson.at("last_opened_at").get<std::uint64_t>();

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

                    Field field;
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

                entries_.push_back(std::move(entry));
            }

            metadata_.last_opened_at = nowEpochSeconds();
            saveToFile();
            return true;
        }

        salt_ = CryptoUtils::generateRandom(saltLength);
        key = CryptoUtils::deriveKey(
            std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(pwView.data()), pwView.size()),
            salt_,
            kdfIterations);

        entries_.clear();
        const std::uint64_t now = nowEpochSeconds();
        metadata_.vault_name = "Vault";
        metadata_.created_at = now;
        metadata_.updated_at = now;
        metadata_.last_opened_at = now;
        saveToFile();
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Initialization failed: " << e.what() << std::endl;
        return false;
    }
}

void PasswordManager::addPassword(const std::string& service, const SecretString& password) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    if (service.empty()) {
        throw std::runtime_error("Service must not be empty");
    }

    Entry* entry = findPasswordEntry(service);
    const std::uint64_t now = nowEpochSeconds();

    if (!entry) {
        Entry newEntry;
        newEntry.id = generateUuidHex();
        newEntry.type = EntryType::password;
        newEntry.title = service;
        newEntry.created_at = now;
        newEntry.updated_at = now;
        newEntry.last_used_at = now;

        Field passwordField;
        passwordField.id = generateUuidHex();
        passwordField.key = "password";
        const auto pwView = password.view();
        passwordField.value.assign(
            reinterpret_cast<const unsigned char*>(pwView.data()),
            reinterpret_cast<const unsigned char*>(pwView.data()) + pwView.size());
        passwordField.value_type = FieldValueType::password;
        passwordField.concealed = true;
        passwordField.copyable = true;
        passwordField.required = true;
        newEntry.fields.push_back(std::move(passwordField));

        entries_.push_back(std::move(newEntry));
    }
    else {
        entry->updated_at = now;
        entry->last_used_at = now;

        auto fieldIt = std::find_if(entry->fields.begin(), entry->fields.end(), [](const Field& field) {
            return field.key == "password";
        });

        const auto pwView = password.view();

        if (fieldIt == entry->fields.end()) {
            Field passwordField;
            passwordField.id = generateUuidHex();
            passwordField.key = "password";
            passwordField.value.assign(
                reinterpret_cast<const unsigned char*>(pwView.data()),
                reinterpret_cast<const unsigned char*>(pwView.data()) + pwView.size());
            passwordField.value_type = FieldValueType::password;
            passwordField.concealed = true;
            passwordField.copyable = true;
            passwordField.required = true;
            entry->fields.push_back(std::move(passwordField));
        }
        else {
            fieldIt->value.assign(
                reinterpret_cast<const unsigned char*>(pwView.data()),
                reinterpret_cast<const unsigned char*>(pwView.data()) + pwView.size());
            fieldIt->value_type = FieldValueType::password;
            fieldIt->concealed = true;
            fieldIt->copyable = true;
            fieldIt->required = true;
        }
    }

    metadata_.updated_at = now;
    saveToFile();
}

SecretString PasswordManager::getPassword(const std::string& service) const {
    std::lock_guard<std::mutex> lock(data_mutex_);
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
    std::lock_guard<std::mutex> lock(data_mutex_);
    std::vector<std::string> services;
    services.reserve(entries_.size());

    for (const Entry& entry : entries_) {
        if (entry.type == EntryType::password && !entry.archived) {
            services.push_back(entry.title);
        }
    }

    std::sort(services.begin(), services.end());
    return services;
}

bool PasswordManager::deletePassword(const std::string& service) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    const auto it = std::find_if(entries_.begin(), entries_.end(), [&](const Entry& entry) {
        return entry.type == EntryType::password && entry.title == service;
    });

    if (it == entries_.end()) {
        return false;
    }

    entries_.erase(it);
    metadata_.updated_at = nowEpochSeconds();
    saveToFile();
    return true;
}

void PasswordManager::saveToFile() {
    if (key.empty() || salt_.size() != saltLength) {
        throw std::runtime_error("Password manager is not initialized");
    }

    json root;
    root["metadata"] = {
        {"vault_name", metadata_.vault_name},
        {"created_at", metadata_.created_at},
        {"updated_at", metadata_.updated_at},
        {"last_opened_at", metadata_.last_opened_at}
    };

    root["entries"] = json::array();
    for (const Entry& entry : entries_) {
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
        for (const Field& field : entry.fields) {
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
        kdfIterations,
        salt_,
        iv,
        tag,
        std::span<const unsigned char>(key.data(), key.size()),
        ciphertext);
    FileUtils::writeFileAtomic(dataFile, blob);
}

bool PasswordManager::beginInitialize(SecretString masterPassword) {
    startAsync(AsyncOperation::initialize,
        "Unlocking vault. Deriving key and loading encrypted data...",
        [this, masterPassword = std::move(masterPassword)]() mutable {
            if (!initialize(masterPassword)) {
                throw std::runtime_error("Initialization failed");
            }
            masterPassword.wipe();
            return "Password manager initialized successfully";
        });
    return true;
}

bool PasswordManager::beginAddPassword(std::string service, SecretString password) {
    startAsync(AsyncOperation::save_password,
        "Encrypting and saving password entry...",
        [this, service = std::move(service), password = std::move(password)]() mutable {
            addPassword(service, password);
            password.wipe();
            return "Password saved for: " + service;
        });
    return true;
}

bool PasswordManager::beginDeletePassword(std::string service) {
    startAsync(AsyncOperation::delete_password,
        "Re-encrypting vault after deleting entry...",
        [this, service = std::move(service)]() mutable {
            if (!deletePassword(service)) {
                throw std::runtime_error("Password entry not found");
            }
            return "Deleted password for: " + service;
        });
    return true;
}

bool PasswordManager::pollAsync() {
    std::future<void> worker;
    {
        std::lock_guard<std::mutex> lock(async_mutex_);
        if (!async_state_.worker.valid()) {
            return false;
        }
        if (async_state_.worker.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
            return false;
        }
        worker = std::move(async_state_.worker);
    }

    worker.get();
    return true;
}

bool PasswordManager::consumeAsyncResult(bool& outSuccess, std::string& outMessage) {
    std::lock_guard<std::mutex> lock(async_mutex_);
    if (!async_state_.completed) {
        return false;
    }

    outSuccess = async_state_.last_success;
    outMessage = async_state_.completion_message;
    async_state_.completed = false;
    async_state_.last_operation = AsyncOperation::none;
    async_state_.completion_message.clear();
    return true;
}

bool PasswordManager::isBusy() const {
    std::lock_guard<std::mutex> lock(async_mutex_);
    return async_state_.busy;
}

std::string PasswordManager::currentStatusMessage() const {
    std::lock_guard<std::mutex> lock(async_mutex_);
    return async_state_.working_message;
}

bool PasswordManager::isInitialized() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return !key.empty();
}
