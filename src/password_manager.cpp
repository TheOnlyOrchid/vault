#include "password_manager.h"

#include <algorithm>
#include <iostream>
#include <string_view>
#include <utility>

PasswordManager::PasswordManager()
    : file_store_("vault.dat") {}

bool PasswordManager::initialize(const SecretString& masterPassword) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    try {
        file_store_.openOrCreate(masterPassword, vault_);
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

    vault::Entry* entry = findPasswordEntry(service);
    const std::uint64_t now = vault::nowEpochSeconds();
    const auto pwView = password.view();

    if (!entry) {
        vault::Entry newEntry;
        newEntry.id = vault::generateIdHex();
        newEntry.type = vault::EntryType::password;
        newEntry.title = service;
        newEntry.created_at = now;
        newEntry.updated_at = now;
        newEntry.last_used_at = now;

        vault::Field passwordField;
        passwordField.id = vault::generateIdHex();
        passwordField.key = "password";
        passwordField.value.assign(
            reinterpret_cast<const unsigned char*>(pwView.data()),
            reinterpret_cast<const unsigned char*>(pwView.data()) + pwView.size());
        passwordField.value_type = vault::FieldValueType::password;
        passwordField.concealed = true;
        passwordField.copyable = true;
        passwordField.required = true;
        newEntry.fields.push_back(std::move(passwordField));

        vault_.entries.push_back(std::move(newEntry));
    }
    else {
        entry->updated_at = now;
        entry->last_used_at = now;

        vault::Field* field = findPasswordField(*entry);
        if (!field) {
            vault::Field passwordField;
            passwordField.id = vault::generateIdHex();
            passwordField.key = "password";
            passwordField.value.assign(
                reinterpret_cast<const unsigned char*>(pwView.data()),
                reinterpret_cast<const unsigned char*>(pwView.data()) + pwView.size());
            passwordField.value_type = vault::FieldValueType::password;
            passwordField.concealed = true;
            passwordField.copyable = true;
            passwordField.required = true;
            entry->fields.push_back(std::move(passwordField));
        }
        else {
            field->value.assign(
                reinterpret_cast<const unsigned char*>(pwView.data()),
                reinterpret_cast<const unsigned char*>(pwView.data()) + pwView.size());
            field->value_type = vault::FieldValueType::password;
            field->concealed = true;
            field->copyable = true;
            field->required = true;
        }
    }

    vault_.metadata.updated_at = now;
    file_store_.save(vault_);
}

SecretString PasswordManager::getPassword(const std::string& service) const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    const vault::Entry* entry = findPasswordEntry(service);
    if (!entry) {
        return SecretString();
    }

    const vault::Field* field = findPasswordField(*entry);
    if (!field) {
        return SecretString();
    }

    SecretString out;
    out.assign(std::string_view(reinterpret_cast<const char*>(field->value.data()), field->value.size()));
    return out;
}

std::vector<std::string> PasswordManager::listServices() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    std::vector<std::string> services;
    services.reserve(vault_.entries.size());

    for (const vault::Entry& entry : vault_.entries) {
        if (entry.type == vault::EntryType::password && !entry.archived) {
            services.push_back(entry.title);
        }
    }

    std::sort(services.begin(), services.end());
    return services;
}

bool PasswordManager::deletePassword(const std::string& service) {
    std::lock_guard<std::mutex> lock(data_mutex_);
    const auto it = std::find_if(vault_.entries.begin(), vault_.entries.end(), [&](const vault::Entry& entry) {
        return entry.type == vault::EntryType::password && entry.title == service;
    });

    if (it == vault_.entries.end()) {
        return false;
    }

    vault_.entries.erase(it);
    vault_.metadata.updated_at = vault::nowEpochSeconds();
    file_store_.save(vault_);
    return true;
}

bool PasswordManager::beginInitialize(SecretString masterPassword) {
    async_worker_.start(
        "Unlocking vault. Deriving key and loading encrypted data...",
        [this, masterPassword = std::move(masterPassword)]() mutable {
            if (!initialize(masterPassword)) {
                throw std::runtime_error("Initialization failed");
            }
            masterPassword.wipe();
            return std::string("Password manager initialized successfully");
        });
    return true;
}

bool PasswordManager::beginAddPassword(std::string service, SecretString password) {
    async_worker_.start(
        "Encrypting and saving password entry...",
        [this, service = std::move(service), password = std::move(password)]() mutable {
            addPassword(service, password);
            password.wipe();
            return std::string("Password saved for: ") + service;
        });
    return true;
}

bool PasswordManager::beginDeletePassword(std::string service) {
    async_worker_.start(
        "Re-encrypting vault after deleting entry...",
        [this, service = std::move(service)]() mutable {
            if (!deletePassword(service)) {
                throw std::runtime_error("Password entry not found");
            }
            return std::string("Deleted password for: ") + service;
        });
    return true;
}

bool PasswordManager::pollAsync() {
    return async_worker_.poll();
}

bool PasswordManager::consumeAsyncResult(bool& outSuccess, std::string& outMessage) {
    return async_worker_.consumeResult(outSuccess, outMessage);
}

bool PasswordManager::isBusy() const {
    return async_worker_.isBusy();
}

bool PasswordManager::isInitialized() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return !vault_.key.empty();
}

vault::Entry* PasswordManager::findPasswordEntry(const std::string& service) {
    const auto it = std::find_if(vault_.entries.begin(), vault_.entries.end(), [&](const vault::Entry& entry) {
        return entry.type == vault::EntryType::password && entry.title == service;
    });
    return (it == vault_.entries.end()) ? nullptr : &(*it);
}

const vault::Entry* PasswordManager::findPasswordEntry(const std::string& service) const {
    const auto it = std::find_if(vault_.entries.begin(), vault_.entries.end(), [&](const vault::Entry& entry) {
        return entry.type == vault::EntryType::password && entry.title == service;
    });
    return (it == vault_.entries.end()) ? nullptr : &(*it);
}

vault::Field* PasswordManager::findPasswordField(vault::Entry& entry) {
    const auto it = std::find_if(entry.fields.begin(), entry.fields.end(), [](const vault::Field& field) {
        return field.key == "password";
    });
    return (it == entry.fields.end()) ? nullptr : &(*it);
}

const vault::Field* PasswordManager::findPasswordField(const vault::Entry& entry) const {
    const auto it = std::find_if(entry.fields.begin(), entry.fields.end(), [](const vault::Field& field) {
        return field.key == "password";
    });
    return (it == entry.fields.end()) ? nullptr : &(*it);
}
