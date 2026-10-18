#pragma once

#include <string>
#include <vector>

class FileUtils {
public:
    static void writeFile(const std::string& filename, const std::string& content);
    static void writeFile(const std::string& filename, const std::vector<unsigned char>& content);
    static void writeFileAtomic(const std::string& filename, const std::vector<unsigned char>& content);
    static std::string readFile(const std::string& filename);
    static std::vector<unsigned char> readFileBytes(const std::string& filename);
    static bool fileExists(const std::string& filename);
};
