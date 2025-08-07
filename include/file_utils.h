#pragma once

#include <string>
#include <vector>

class FileUtils {
public:
    static void writeFile(const std::string& filename, const std::string& content);
    static std::string readFile(const std::string& filename);
    static bool fileExists(const std::string& filename);
};