#pragma once

#include <string>

#include "secret_string.h"
#include "vault_types.h"

class VaultFileStore {
public:
    explicit VaultFileStore(std::string dataFile = "vault.dat");

    void openOrCreate(const SecretString& masterPassword, vault::VaultData& vault) const;
    void save(const vault::VaultData& vault) const;

private:
    std::string data_file_;
};
