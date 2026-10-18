#pragma once

#include <string>

#include "secret_string.hpp"
#include "vault_types.hpp"

class VaultFileStore {
public:
    explicit VaultFileStore(std::string dataFile = "vault.dat");

    void openOrCreate(const SecretString& masterPassword, vault::VaultData& vault) const;
    void save(const vault::VaultData& vault) const;

private:
    std::string data_file_;
};
