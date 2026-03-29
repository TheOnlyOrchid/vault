#include "vault_types.h"

#include "crypto_utils.h"

#include <chrono>

namespace vault {

std::uint64_t nowEpochSeconds() {
    const auto now = std::chrono::system_clock::now();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
    return static_cast<std::uint64_t>(secs.count());
}

std::string generateIdHex() {
    return CryptoUtils::bytesToHex(CryptoUtils::generateRandom(16));
}

}
