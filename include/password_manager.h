#pragma once

#include <string>
#include <map>
#include <vector>

#include "secure_memory.h"
#include "secret_string.h"

class PasswordManager {
private:
    static const std::string dataFile;
    std::map<std::string, SecretString> passwords;
    secure::SecureBytes key;

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
