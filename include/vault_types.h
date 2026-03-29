#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "secure_memory.h"

namespace vault {

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

struct VaultData {
    std::vector<unsigned char> salt;
    VaultMetadata metadata;
    std::vector<Entry> entries;
    secure::SecureBytes key;
};

std::uint64_t nowEpochSeconds();
std::string generateIdHex();

}
