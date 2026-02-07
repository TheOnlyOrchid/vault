#include "file_utils.h"

#include <filesystem>
#include <fstream>
#include <stdexcept>

void FileUtils::writeFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename, std::ios::binary);

    // failed to open
    if (!file) {
        throw std::runtime_error("Failed to open : " + filename);
    }

    const char *p = content.data();
    std::size_t remainingLen = content.size();

    // stack overflow says this has to be const, not constexpr to ensure compatibility with all C++ versions.
    const std::streamsize streamSizeLimit = std::numeric_limits<std::streamsize>::max();
    const auto chunk = static_cast<std::size_t>(streamSizeLimit);

    /**
     * writes in chunks, this prevents a rare crash condition before, where if the size of the data was larger
     * than the size of the streamsize, it would crash.
    */
    while (remainingLen > 0 ) {
        const std::size_t chunkSize = std::min(remainingLen, chunk);
        // writes from P chunkSize chars
        file.write(p, static_cast<std::streamsize>(chunkSize));

        if (!file) {
            throw std::runtime_error("Failed to write to : " + filename);
        }

        p += chunkSize;
        remainingLen -= chunkSize;
    }

    // this is here so we can have our own error, instead of a standard runtime error.
    file.flush();
    if (!file) {
        throw std::runtime_error("Failed to flush into : " + filename);
    }
}

std::string FileUtils::readFile(const std::string& filename) {
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