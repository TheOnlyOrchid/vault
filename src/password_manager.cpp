#include "password_manager.h"
#include "crypto_utils.h"
#include "file_utils.h"
#include <iostream>
#include <sstream>

const std::string PasswordManager::dataFile = "passwords.dat";

bool PasswordManager::initialize(const std::string& masterPassword) {
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

        key = CryptoUtils::deriveKey(masterPassword, salt);
        loadFromFile();
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Initialization failed: " << e.what() << std::endl;
        return false;
    }
}

void PasswordManager::addPassword(const std::string& service, const std::string& password) {
    passwords[service] = password;
    try {
        saveToFile();
        std::cout << "Password saved for: " << service << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to save: " << e.what() << std::endl;
    }
}

bool PasswordManager::getPassword(const std::string& service) const {
    auto it = passwords.find(service);
    if (it != passwords.end()) {
        std::cout << "Password for " << service << ": " << it->second << std::endl;
        return true;
    }
    std::cout << "No password found for: " << service << std::endl;
    return false;
}

void PasswordManager::listServices() const {
    if (passwords.empty()) {
        std::cout << "No passwords stored." << std::endl;
        return;
    }

    std::cout << "Stored services:" << std::endl;
    for (const auto& pair : passwords) {
        std::cout << "  - " << pair.first << std::endl;
    }
}

bool PasswordManager::deletePassword(const std::string& service) {
    auto it = passwords.find(service);
    if (it != passwords.end()) {
        passwords.erase(it);
        try {
            saveToFile();
            std::cout << "Password deleted for: " << service << std::endl;
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "Failed to save after deletion: " << e.what() << std::endl;
        }
    }
    else {
        std::cout << "No password found for: " << service << std::endl;
    }
    return false;
}

void PasswordManager::saveToFile() {
    std::string content;
    for (const auto& pair : passwords) {
        std::string line = pair.first + ":" + pair.second + "\n";
        content += CryptoUtils::encrypt(line, key) + "\n";
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
            std::string decrypted = CryptoUtils::decrypt(line, key);
            size_t colonPos = decrypted.find(':');
            if (colonPos != std::string::npos) {
                std::string service = decrypted.substr(0, colonPos);
                std::string password = decrypted.substr(colonPos + 1);
                if (!password.empty() && password.back() == '\n') {
                    password.pop_back();
                }
                passwords[service] = password;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Warning: Failed to decrypt, likely wrong password. - " << e.what() << std::endl;
        }
    }
}