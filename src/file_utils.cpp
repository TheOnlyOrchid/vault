#include "file_utils.h"
#include <fstream>
#include <stdexcept>

void FileUtils::writeFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to write to: " + filename);
    }
    file << content;
}

std::string FileUtils::readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to read from: " + filename);
    }
    return std::string((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
}

bool FileUtils::fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}