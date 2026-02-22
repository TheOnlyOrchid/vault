#include "file_utils.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {
void restrictToOwnerReadWrite(const std::string& filename) {
    std::error_code ec;
    std::filesystem::permissions(
        filename,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        ec);
}

void writeBytes(const std::string& filename, const unsigned char* data, const std::size_t size) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open : " + filename);
    }

    const auto* p = reinterpret_cast<const char*>(data);
    std::size_t remainingLen = size;

    std::streamsize streamSizeLimit = std::numeric_limits<std::streamsize>::max();
    const auto chunk = static_cast<std::size_t>(streamSizeLimit);

    while (remainingLen > 0) {
        const std::size_t chunkSize = std::min(remainingLen, chunk);
        file.write(p, static_cast<std::streamsize>(chunkSize));
        if (!file) {
            throw std::runtime_error("Failed to write to : " + filename);
        }

        p += chunkSize;
        remainingLen -= chunkSize;
    }

    file.flush();
    if (!file) {
        throw std::runtime_error("Failed to flush into : " + filename);
    }

    file.close();
    restrictToOwnerReadWrite(filename);
}
}

void FileUtils::writeFile(const std::string& filename, const std::string& content) {
    writeBytes(
        filename,
        reinterpret_cast<const unsigned char*>(content.data()),
        content.size());
}

void FileUtils::writeFile(const std::string& filename, const std::vector<unsigned char>& content) {
    const unsigned char* data = content.empty() ? nullptr : content.data();
    writeBytes(filename, data, content.size());
}

void FileUtils::writeFileAtomic(const std::string& filename, const std::vector<unsigned char>& content) {
    const std::filesystem::path targetPath(filename);
    const std::filesystem::path parent = targetPath.parent_path();
    const std::string tempName = targetPath.filename().string() + ".tmp";
    const std::filesystem::path tempPath = parent.empty() ? std::filesystem::path(tempName) : parent / tempName;

    // Remove stale temp files from interrupted previous writes.
    std::error_code ec;
    std::filesystem::remove(tempPath, ec);

    writeFile(tempPath.string(), content);

    ec.clear();
    std::filesystem::rename(tempPath, targetPath, ec);
    if (ec) {
        std::filesystem::remove(tempPath, ec);
        throw std::runtime_error("Atomic rename failed for: " + filename);
    }
}

/**
 * there is no sanitisation of the file. Since this is a local password manager this is okay, however if I were to
 * include web support, or anything that contained untrusted inputs, sanitisation would be *needed*.
 */
std::string FileUtils::readFile(const std::string& filename) {
    if (!fileExists(filename)) {
        throw std::runtime_error("File does not exist: " + filename);
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to read from: " + filename);
    }
    return std::string((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
}

// this exists as a wrapper to port old code, used to use custom logic.
bool FileUtils::fileExists(const std::string& filename) {
    return std::filesystem::exists(filename);
}

std::vector<unsigned char> FileUtils::readFileBytes(const std::string& filename) {
    std::string content = readFile(filename);
    return std::vector<unsigned char>(content.begin(), content.end());
}
