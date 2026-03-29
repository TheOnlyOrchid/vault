#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "async_worker.h"
#include "secret_string.h"
#include "vault_file_store.h"
#include "vault_types.h"

class PasswordManager {
public:
    PasswordManager();

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
    bool isInitialized() const;

private:
    vault::Entry* findPasswordEntry(const std::string& service);
    const vault::Entry* findPasswordEntry(const std::string& service) const;
    vault::Field* findPasswordField(vault::Entry& entry);
    const vault::Field* findPasswordField(const vault::Entry& entry) const;

    mutable std::mutex data_mutex_;
    vault::VaultData vault_;
    VaultFileStore file_store_;
    AsyncWorker async_worker_;
};
