#pragma once

#include <string>
#include <map>
#include <vector>

class PasswordManager {
private:
    static const std::string dataFile;
    std::map<std::string, std::string> passwords;
    std::vector<unsigned char> key;

    void saveToFile();
    void loadFromFile();

public:
    bool initialize(const std::string& masterPassword);
    void addPassword(const std::string& service, const std::string& password);
    std::string getPassword(const std::string& service) const;
    std::vector<std::string> listServices() const;
    bool deletePassword(const std::string& service);
    bool isInitialized() const { return !key.empty(); }
};