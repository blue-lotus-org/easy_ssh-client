#ifndef SECURITY_H
#define SECURITY_H

#include "types.h"
#include <string>
#include <vector>
#include <regex>
#include <atomic>

namespace SSHVPN {

class SecurityManager {
public:
    explicit SecurityManager(const SecurityConfig& config = SecurityConfig{});
    ~SecurityManager() = default;
    
    // Delete copy constructor and assignment operator
    SecurityManager(const SecurityManager&) = delete;
    SecurityManager& operator=(const SecurityManager&) = delete;
    
    // Input validation and sanitization
    bool validateHost(const std::string& host) const;
    bool validatePort(const std::string& port) const;
    bool validatePort(int port) const;
    bool validateUser(const std::string& user) const;
    bool validateSSHCommand(const std::string& command) const;
    bool validateProfileName(const std::string& name) const;
    
    // String sanitization
    std::string sanitizeShellArgument(const std::string& input) const;
    std::string sanitizeSSHCommand(const std::string& command) const;
    std::string escapeForShell(const std::string& input) const;
    
    // Command construction safety
    std::vector<std::string> buildSecureSSHCommand(const SSHProfile& profile) const;
    bool isCommandSafe(const std::vector<std::string>& command_parts) const;
    
    // File security
    bool validateFilePath(const std::string& path) const;
    bool checkFilePermissions(const std::string& path, int required_permissions) const;
    bool secureFilePermissions(const std::string& path, int permissions = 0600) const;
    bool isPathTraversalAttempt(const std::string& path) const;
    
    // Memory security
    void secureClear(void* ptr, size_t size) const;
    void secureClearString(std::string& str) const;
    std::string secureReadPassword(const std::string& prompt = "Enter password: ") const;
    
    // Process security
    bool validateProcessArguments(const std::vector<std::string>& args) const;
    void setupProcessSecurity() const;
    
    // Configuration security
    SecurityConfig getSecurityConfig() const { return config_; }
    void setSecurityConfig(const SecurityConfig& config);
    
    // Threat detection
    bool detectInjectionAttempt(const std::string& input) const;
    bool detectSuspiciousActivity(const std::string& activity) const;
    
    // Security logging
    void logSecurityEvent(const std::string& event, const std::string& details = "") const;
    
private:
    SecurityConfig config_;
    mutable std::atomic<bool> security_enabled_{true};
    
    // Internal validation helpers
    bool isValidHostname(const std::string& hostname) const;
    bool isValidIPv4(const std::string& ip) const;
    bool isValidIPv6(const std::string& ip) const;
    bool isValidDomainName(const std::string& domain) const;
    bool containsShellMetacharacters(const std::string& input) const;
    bool isAllowedCommand(const std::string& command) const;
    
    // Pattern matching for security threats
    static const std::vector<std::regex> injection_patterns_;
    static const std::vector<std::regex> path_traversal_patterns_;
    static const std::vector<std::regex> command_injection_patterns_;
    
    // Whitelist validation
    static bool isPortInRange(int port);
    static bool isUsernameValid(const std::string& username);
    
    // Command construction helpers
    std::vector<std::string> sanitizeSSHArgs(const std::vector<std::string>& args) const;
    std::string quoteForShell(const std::string& input) const;
    
    // Disable core dumps for sensitive operations
    void disableCoreDumps() const;
    
    // Security initialization
    void initializeSecurity() const;
};

// Security utilities
namespace SecurityUtils {
    // Input validation
    bool isValidEmail(const std::string& email);
    bool isValidURL(const std::string& url);
    bool isValidPath(const std::string& path);
    bool isValidHexColor(const std::string& color);
    
    // String sanitization
    std::string removeDangerousCharacters(const std::string& input);
    std::string normalizeWhitespace(const std::string& input);
    std::string stripControlCharacters(const std::string& input);
    
    // Encoding/decoding
    std::string base64Encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> base64Decode(const std::string& encoded);
    std::string urlEncode(const std::string& input);
    std::string urlDecode(const std::string& input);
    
    // Cryptographic helpers
    std::string generateSecureToken(size_t length = 32);
    bool verifyFileIntegrity(const std::string& filepath, const std::string& expected_hash);
    std::string calculateFileHash(const std::string& filepath);
    
    // Random number generation
    int generateSecureRandomInt(int min, int max);
    std::vector<uint8_t> generateSecureRandomBytes(size_t length);
    
    // Time-based security
    bool isWithinTimeWindow(const std::chrono::steady_clock::time_point& start, 
                           std::chrono::seconds max_duration);
    std::chrono::steady_clock::time_point getCurrentTime();
}

// Security exception classes
class SecurityException : public std::runtime_error {
public:
    explicit SecurityException(const std::string& message) 
        : std::runtime_error("Security violation: " + message) {}
};

class InputValidationException : public SecurityException {
public:
    explicit InputValidationException(const std::string& field, const std::string& value)
        : SecurityException("Invalid input in field '" + field + "': " + value) {}
};

class CommandInjectionException : public SecurityException {
public:
    explicit CommandInjectionException(const std::string& command)
        : SecurityException("Potential command injection detected: " + command) {}
};

class PathTraversalException : public SecurityException {
public:
    explicit PathTraversalException(const std::string& path)
        : SecurityException("Path traversal attempt detected: " + path) {}
};

class PermissionException : public SecurityException {
public:
    explicit PermissionException(const std::string& resource, const std::string& reason)
        : SecurityException("Permission denied for '" + resource + "': " + reason) {}
};

} // namespace SSHVPN

#endif // SECURITY_H