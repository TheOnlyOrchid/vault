#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <future>
#include <mutex>
#include <span>
#include <utility>

#include "secure_memory.h"
#include "secret_string.h"

class PasswordManager {
private:
    enum class EntryType {
        password,
        note,
        api_key,
        card,
        identity,
        random_secret
    };

    enum class FieldValueType {
        text,
        secret,
        url,
        email,
        username,
        password,
        note,
        totp_seed,
        number,
        date
    };

    struct Field {
        std::string id;
        std::string key;
        secure::SecureBytes value;
        FieldValueType value_type = FieldValueType::text;
        bool concealed = false;
        bool copyable = true;
        bool multiline = false;
        bool required = false;
    };

    struct Entry {
        std::string id;
        EntryType type = EntryType::password;
        std::string title;
        std::vector<Field> fields;
        std::vector<std::string> tags;
        std::uint64_t created_at = 0;
        std::uint64_t updated_at = 0;
        std::uint64_t last_used_at = 0;
        bool favorite = false;
        bool archived = false;
    };

    struct VaultMetadata {
        std::string vault_name;
        std::uint64_t created_at = 0;
        std::uint64_t updated_at = 0;
        std::uint64_t last_opened_at = 0;
    };

    enum class AsyncOperation {
        none,
        initialize,
        save_password,
        delete_password
    };

    struct AsyncState {
        std::future<void> worker;
        bool busy = false;
        bool completed = false;
        bool last_success = false;
        AsyncOperation last_operation = AsyncOperation::none;
        std::string working_message;
        std::string completion_message;
    };

    static const std::string dataFile;
    static constexpr int saltLength = 16;
    static constexpr int ivLength = 12;
    static constexpr int tagLength = 16;
    static constexpr int kdfIterations = 600000;
    static constexpr std::uint32_t formatVersion = 1;

    std::vector<unsigned char> salt_;
    VaultMetadata metadata_;
    std::vector<Entry> entries_;
    secure::SecureBytes key;
    mutable std::mutex data_mutex_;
    mutable std::mutex async_mutex_;
    AsyncState async_state_;

    static std::uint64_t nowEpochSeconds();
    static std::string generateUuidHex();
    static std::string toEntryTypeString(EntryType type);
    static EntryType parseEntryType(const std::string& value);
    static std::string toFieldValueTypeString(FieldValueType type);
    static FieldValueType parseFieldValueType(const std::string& value);
    static std::vector<unsigned char> buildBlob(std::uint32_t iterations,
        const std::vector<unsigned char>& salt,
        const std::vector<unsigned char>& iv,
        const std::vector<unsigned char>& tag,
        std::span<const unsigned char> key,
        const secure::SecureBytes& ciphertext);
    static void parseBlob(const std::vector<unsigned char>& blob,
        std::uint32_t& outIterations,
        std::vector<unsigned char>& outSalt,
        std::vector<unsigned char>& outIv,
        std::vector<unsigned char>& outTag,
        std::span<const unsigned char> key,
        std::vector<unsigned char>& outCiphertext);
    static std::string secureBytesToString(std::span<const unsigned char> bytes);
    static secure::SecureBytes secureBytesFromString(const std::string& value);
    static void zeroizeString(std::string& value) noexcept;
    template <typename Task>
    void startAsync(AsyncOperation operation, std::string workingMessage, Task&& task);

    Entry* findPasswordEntry(const std::string& service);
    const Entry* findPasswordEntry(const std::string& service) const;
    void saveToFile();

public:
    ~PasswordManager();

    bool initialize(const SecretString& masterPassword);
    void addPassword(const std::string& service, const SecretString& password);
    SecretString getPassword(const std::string& service) const;
    std::vector<std::string> listServices() const;
    bool deletePassword(const std::string& service);
    bool beginInitialize(SecretString masterPassword);
    bool beginAddPassword(std::string service, SecretString password);
    bool beginDeletePassword(std::string service);
    bool pollAsync();
    bool consumeAsyncResult(bool& outSuccess, std::string& outMessage);
    bool isBusy() const;
    std::string currentStatusMessage() const;
    bool isInitialized() const;
};

template <typename Task>
void PasswordManager::startAsync(AsyncOperation operation, std::string workingMessage, Task&& task) {
    std::lock_guard<std::mutex> lock(async_mutex_);
    if (async_state_.busy) {
        throw std::runtime_error("Password manager is busy");
    }

    if (async_state_.worker.valid()) {
        async_state_.worker.get();
    }

    async_state_.busy = true;
    async_state_.completed = false;
    async_state_.last_success = false;
    async_state_.last_operation = operation;
    async_state_.working_message = std::move(workingMessage);
    async_state_.completion_message.clear();

    async_state_.worker = std::async(std::launch::async, [this, task = std::forward<Task>(task)]() mutable {
        bool success = false;
        std::string message;

        try {
            message = task();
            success = true;
        }
        catch (const std::exception& e) {
            message = e.what();
        }
        catch (...) {
            message = "Unknown background task failure";
        }

        std::lock_guard<std::mutex> taskLock(async_mutex_);
        async_state_.busy = false;
        async_state_.completed = true;
        async_state_.last_success = success;
        async_state_.completion_message = std::move(message);
        async_state_.working_message.clear();
    });
}
