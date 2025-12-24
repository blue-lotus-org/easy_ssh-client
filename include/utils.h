#ifndef UTILS_H
#define UTILS_H

#include "types.h"
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <chrono>
#include <memory>
#include <functional>
#include <random>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <fstream>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

namespace SSHVPN {

class ProcessUtils {
public:
    // Process management
    static pid_t startProcess(const std::vector<std::string>& args, 
                             std::optional<std::string> working_dir = std::nullopt,
                             bool redirect_output = true);
    static bool stopProcess(pid_t pid, int timeout_seconds = 10);
    static bool isProcessRunning(pid_t pid);
    static int getProcessExitCode(pid_t pid);
    static std::string getProcessCommand(pid_t pid);
    static std::chrono::steady_clock::time_point getProcessStartTime(pid_t pid);
    
    // Process information
    static bool getProcessInfo(pid_t pid, ProcessInfo& info);
    static std::vector<pid_t> findProcessesByName(const std::string& process_name);
    static bool killProcessTree(pid_t root_pid, int signal = SIGTERM);
    
    // System information
    static std::string getHostname();
    static std::string getUsername();
    static std::string getHomeDirectory();
    static std::string getTemporaryDirectory();
    static std::string getSystemTemporaryDirectory();
    
    // File system utilities
    static bool fileExists(const std::string& path);
    static bool directoryExists(const std::string& path);
    static bool createDirectory(const std::string& path, bool recursive = true);
    static bool removeFile(const std::string& path);
    static bool removeDirectory(const std::string& path, bool recursive = false);
    static std::string getAbsolutePath(const std::string& path);
    static std::string getRelativePath(const std::string& path, const std::string& base = ".");
    static std::vector<std::string> listDirectory(const std::string& path);
    static bool copyFile(const std::string& source, const std::string& destination);
    static bool moveFile(const std::string& source, const std::string& destination);
    
    // File permissions
    static bool setFilePermissions(const std::string& path, int permissions);
    static int getFilePermissions(const std::string& path);
    static bool isFileReadable(const std::string& path);
    static bool isFileWritable(const std::string& path);
    static bool isFileExecutable(const std::string& path);
    
    // Network utilities
    static bool isPortInUse(int port);
    static std::vector<int> getUsedPorts();
    static int findAvailablePort(int start_port = 1080, int max_attempts = 100);
    static bool isValidIPAddress(const std::string& ip);
    static bool isValidHostname(const std::string& hostname);
    static std::string getLocalIPAddress();
    static std::vector<std::string> getNetworkInterfaces();
    
    // Time utilities
    static std::chrono::steady_clock::time_point getCurrentTime();
    static std::chrono::system_clock::time_point getSystemCurrentTime();
    static std::string formatDuration(std::chrono::milliseconds duration);
    static std::string formatTimestamp(const std::chrono::system_clock::time_point& time_point);
    static std::chrono::milliseconds parseDuration(const std::string& duration_string);
    
    // String utilities
    static std::vector<std::string> splitString(const std::string& str, char delimiter);
    static std::string joinStrings(const std::vector<std::string>& strings, const std::string& separator);
    static std::string trimString(const std::string& str);
    static std::string toLowerCase(const std::string& str);
    static std::string toUpperCase(const std::string& str);
    static bool startsWith(const std::string& str, const std::string& prefix);
    static bool endsWith(const std::string& str, const std::string& suffix);
    static std::string replaceAll(const std::string& str, const std::string& from, const std::string& to);
    
    // Encoding and hashing
    static std::string base64Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64Decode(const std::string& encoded);
    static std::string urlEncode(const std::string& input);
    static std::string urlDecode(const std::string& input);
    static std::string sha256Hash(const std::string& input);
    static std::string md5Hash(const std::string& input);
    
    // Random utilities
    static int generateRandomInt(int min, int max);
    static std::vector<uint8_t> generateRandomBytes(size_t length);
    static std::string generateRandomString(size_t length, const std::string& charset = "");
    static std::string generateUUID();
    
    // Validation utilities
    static bool isValidEmail(const std::string& email);
    static bool isValidURL(const std::string& url);
    static bool isValidPort(int port);
    static bool isValidPort(const std::string& port);
    static bool isValidUsername(const std::string& username);
    static bool isValidPath(const std::string& path);
    static bool isValidHexColor(const std::string& color);
    
    // JSON utilities
    static std::string formatJSON(const std::string& json_string, int indent = 2);
    static std::string minifyJSON(const std::string& json_string);
    static bool isValidJSON(const std::string& json_string);
    
    // Configuration utilities
    static std::map<std::string, std::string> parseConfigFile(const std::string& filepath);
    static bool writeConfigFile(const std::string& filepath, const std::map<std::string, std::string>& config);
    static std::string getEnvironmentVariable(const std::string& name, const std::string& default_value = "");
    static bool setEnvironmentVariable(const std::string& name, const std::string& value);
    static std::vector<std::string> getEnvironmentVariables(const std::string& prefix = "");
    
    // Security utilities
    static bool verifyFileIntegrity(const std::string& filepath, const std::string& expected_hash);
    static std::string calculateFileHash(const std::string& filepath);
    static bool secureDeleteFile(const std::string& filepath);
    static std::string sanitizeFilename(const std::string& filename);
    static bool isSafePath(const std::string& path);
    
    // Cryptographic utilities
    static std::vector<uint8_t> generateSecureRandomBytes(size_t length);
    static std::string xorEncrypt(const std::vector<uint8_t>& data, const std::string& key);
    static std::vector<uint8_t> xorDecrypt(const std::vector<uint8_t>& encrypted_data, const std::string& key);
    
    // System command execution
    static std::pair<int, std::string> executeCommand(const std::vector<std::string>& command, 
                                                     int timeout_seconds = 30);
    static std::pair<int, std::string> executeShellCommand(const std::string& command,
                                                          int timeout_seconds = 30);
    static bool commandExists(const std::string& command);
    static std::string getCommandPath(const std::string& command);
    
    // System monitoring
    static double getCPUUsage();
    static size_t getMemoryUsage();
    static size_t getAvailableMemory();
    static double getSystemLoad();
    static std::vector<std::string> getRunningProcesses();
    
    // Error handling utilities
    static std::string getLastSystemError();
    static int getLastErrorCode();
    static void setErrorCode(int error_code);
    
private:
    ProcessUtils() = default; // Static class
};

// Thread-safe singleton for global utilities
class GlobalUtils {
public:
    static GlobalUtils& getInstance();
    
    // Global configuration
    void setGlobalConfigDirectory(const std::string& path);
    std::string getGlobalConfigDirectory() const;
    void setGlobalLogDirectory(const std::string& path);
    std::string getGlobalLogDirectory() const;
    
    // Global settings
    void setDefaultTimeout(int seconds);
    int getDefaultTimeout() const;
    void setMaxConnections(int max);
    int getMaxConnections() const;
    void setVerbose(bool verbose);
    bool isVerbose() const;
    
    // Thread safety
    void lock() const { mutex_.lock(); }
    void unlock() const { mutex_.unlock(); }
    bool tryLock() const { return mutex_.try_lock(); }
    
private:
    GlobalUtils() = default;
    
    std::string config_dir_;
    std::string log_dir_;
    int default_timeout_ = 30;
    int max_connections_ = 10;
    bool verbose_ = false;
    mutable std::mutex mutex_;
};

// Exception classes for utilities
class UtilsException : public std::runtime_error {
public:
    explicit UtilsException(const std::string& message) 
        : std::runtime_error("Utils error: " + message) {}
};

class ProcessException : public UtilsException {
public:
    explicit ProcessException(const std::string& process_name, const std::string& reason)
        : UtilsException("Process operation failed for '" + process_name + "': " + reason) {}
};

class FileException : public UtilsException {
public:
    explicit FileException(const std::string& filepath, const std::string& operation, const std::string& reason)
        : UtilsException("File operation '" + operation + "' failed for '" + filepath + "': " + reason) {}
};

class NetworkException : public UtilsException {
public:
    explicit NetworkException(const std::string& operation, const std::string& details)
        : UtilsException("Network operation '" + operation + "' failed: " + details) {}
};

class ValidationException : public UtilsException {
public:
    explicit ValidationException(const std::string& value, const std::string& type, const std::string& reason)
        : UtilsException("Validation failed for '" + value + "' as " + type + ": " + reason) {}
};

// Utility functions for common operations
namespace StringUtils {
    // Case conversion
    std::string toTitleCase(const std::string& str);
    std::string toCamelCase(const std::string& str);
    std::string toSnakeCase(const std::string& str);
    std::string toKebabCase(const std::string& str);
    
    // Pattern matching
    bool matchesPattern(const std::string& str, const std::string& pattern);
    std::vector<std::string> extractMatches(const std::string& str, const std::string& pattern);
    
    // Text processing
    std::string removeWhitespace(const std::string& str);
    std::string collapseWhitespace(const std::string& str);
    std::string escapeHtml(const std::string& str);
    std::string unescapeHtml(const std::string& str);
    std::string wrapText(const std::string& text, size_t width, const std::string& indent = "");
    
    // Validation
    bool isAlphanumeric(const std::string& str);
    bool isNumeric(const std::string& str);
    bool isAlpha(const std::string& str);
    bool containsOnly(const std::string& str, const std::string& allowed_chars);
}

namespace CryptoUtils {
    // Key derivation
    std::vector<uint8_t> deriveKey(const std::string& password, const std::string& salt, 
                                  size_t key_length = 32, int iterations = 100000);
    
    // Encryption helpers
    std::string encryptString(const std::string& plain_text, const std::string& key);
    std::string decryptString(const std::string& cipher_text, const std::string& key);
    
    // Secure comparison
    bool secureEqual(const std::string& a, const std::string& b);
    
    // Time-based tokens
    std::string generateTimeBasedToken(const std::string& secret, 
                                      const std::chrono::system_clock::time_point& time_point);
    bool verifyTimeBasedToken(const std::string& token, const std::string& secret,
                             std::chrono::seconds tolerance = std::chrono::seconds{30});
}

} // namespace SSHVPN

#endif // UTILS_H