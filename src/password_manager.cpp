#include "password_manager.h"
#include "crypto_utils.h"
#include "file_utils.h"
#include <iostream>
#include <sstream>

const std::string PasswordManager::dataFile = "passwords.dat";

bool PasswordManager::initialize(const SecretString& masterPassword) {
    try {
        const std::string saltFile = "salt.dat";
        std::vector<unsigned char> salt;

        if (FileUtils::fileExists(saltFile)) {
            std::string saltHex = FileUtils::readFile(saltFile);
            salt = CryptoUtils::hexToBytes(saltHex);
        }
        else {
            salt = CryptoUtils::generateRandom(32);
            FileUtils::writeFile(saltFile, CryptoUtils::bytesToHex(salt));
        }

        auto pw_view = masterPassword.view();
        key = CryptoUtils::deriveKey(
            std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(pw_view.data()), pw_view.size()),
            salt);
        loadFromFile();
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Initialization failed: " << e.what() << std::endl;
        return false;
    }
}

void PasswordManager::addPassword(const std::string& service, const SecretString& password) {
    SecretString copy;
    copy.assign(password.view());
    passwords[service] = std::move(copy);
    saveToFile();
}

SecretString PasswordManager::getPassword(const std::string& service) const {
    auto it = passwords.find(service);
    if (it != passwords.end()) {
        SecretString out;
        out.assign(it->second.view());
        return out;
    }
    return SecretString();
}

std::vector<std::string> PasswordManager::listServices() const {
    std::vector<std::string> services;
    services.reserve(passwords.size());
    for (const auto& pair : passwords) {
        services.push_back(pair.first);
    }
    return services;
}

bool PasswordManager::deletePassword(const std::string& service) {
    auto it = passwords.find(service);
    if (it != passwords.end()) {
        passwords.erase(it);
        saveToFile();
        return true;
    }
    return false;
}

void PasswordManager::saveToFile() {
    std::string content;
    for (const auto& pair : passwords) {
        SecretString line;
        line.assign(pair.first);

        {
            auto service = pair.first;
            auto pw = pair.second.view();
            std::vector<char, secure::allocator<char>> tmp;
            tmp.reserve(service.size() + 1 + pw.size() + 1 + 1);
            tmp.insert(tmp.end(), service.begin(), service.end());
            tmp.push_back(':');
            tmp.insert(tmp.end(), pw.begin(), pw.end());
            tmp.push_back('\n');
            tmp.push_back('\0');

            line.assign(std::string_view(tmp.data(), tmp.size() - 1));
        }

        auto line_view = line.view();
        content += CryptoUtils::encrypt(
            std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(line_view.data()), line_view.size()),
            std::span<const unsigned char>(key.data(), key.size())) + "\n";
    }
    FileUtils::writeFile(dataFile, content);
}

void PasswordManager::loadFromFile() {
    if (!FileUtils::fileExists(dataFile)) return;

    passwords.clear();
    std::string content = FileUtils::readFile(dataFile);
    std::istringstream iss(content);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.empty()) continue;

        try {
            secure::SecureBytes decrypted = CryptoUtils::decryptToBytes(
                line, std::span<const unsigned char>(key.data(), key.size()));
            auto it = std::find(decrypted.begin(), decrypted.end(), static_cast<unsigned char>(':'));
            if (it != decrypted.end()) {
                std::string service(reinterpret_cast<const char*>(decrypted.data()),
                    static_cast<std::size_t>(std::distance(decrypted.begin(), it)));

                const unsigned char* pw_start = &*(it + 1);
                std::size_t pw_len = static_cast<std::size_t>(decrypted.end() - (it + 1));
                if (pw_len > 0 && pw_start[pw_len - 1] == static_cast<unsigned char>('\n')) {
                    pw_len -= 1;
                }

                SecretString password;
                password.assign(std::string_view(reinterpret_cast<const char*>(pw_start), pw_len));
                passwords[service] = std::move(password);
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Warning: Failed to decrypt, likely wrong password. - " << e.what() << std::endl;
        }
    }
}
