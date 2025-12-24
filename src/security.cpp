#include "security.h"
#include "utils.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <unistd.h>
#include <sys/resource.h>

namespace SSHVPN {

// Static pattern definitions for security threat detection
const std::vector<std::regex> SecurityManager::injection_patterns_ = {
    std::regex(R"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)", std::regex::icase),
    std::regex(R"(<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>)", std::regex::icase),
    std::regex(R"(&lt;script\b[^&]*(?:(?!&lt;/script&gt;)&[^&]*)*&lt;/script&gt;)", std::regex::icase),
    std::regex(R"(\bon\w+\s*=\s*['\"][^'\"]*['\"])", std::regex::icase),
    std::regex(R"(<iframe\b[^<]*(?:(?!</iframe>)<[^<]*)*</iframe>)", std::regex::icase)
};

const std::vector<std::regex> SecurityManager::path_traversal_patterns_ = {
    std::regex(R"(\.\./)"),
    std::regex(R"(\.\.\\)"),
    std::regex(R"(/%2e%2e%2f)", std::regex::icase),
    std::regex(R"(/%2e%2e%5c)", std::regex::icase),
    std::regex(R"(%c0%af)", std::regex::icase)
};

const std::vector<std::regex> SecurityManager::command_injection_patterns_ = {
    std::regex(R"(;|&&|\|\||\|)"),
    std::regex(R"(`[^`]*`)"),
    std::regex(R"(\$\([^)]*\))"),
    std::regex(R"(\$\{[^}]*\})"),
    std::regex(R"(<|>)"),
    std::regex(R"(!)"),
    std::regex(R"(\*)"),
    std::regex(R"(\?)"),
    std::regex(R"(\[|\])"),
    std::regex(R"(\{)"),
    std::regex(R"(\})")
};

SecurityManager::SecurityManager(const SecurityConfig& config) : config_(config) {
    initializeSecurity();
}

void SecurityManager::initializeSecurity() const {
    if (config_.disable_core_dumps) {
        disableCoreDumps();
    }
    
    // Initialize security patterns if needed
    // Additional security initialization can be added here
}

bool SecurityManager::validateHost(const std::string& host) const {
    if (!config_.validate_inputs) {
        return true;
    }
    
    // Check for suspicious patterns
    if (detectInjectionAttempt(host)) {
        logSecurityEvent("Invalid host detected", "Potential injection in host: " + host);
        return false;
    }
    
    // Validate hostname/IP format
    if (isValidHostname(host) || isValidIPv4(host) || isValidIPv6(host)) {
        return true;
    }
    
    logSecurityEvent("Invalid host format", "Host: " + host);
    return false;
}

bool SecurityManager::validatePort(const std::string& port) const {
    if (!config_.validate_inputs) {
        return true;
    }
    
    try {
        int port_num = std::stoi(port);
        return validatePort(port_num);
    } catch (const std::exception&) {
        logSecurityEvent("Invalid port format", "Port: " + port);
        return false;
    }
}

bool SecurityManager::validatePort(int port) const {
    if (!config_.validate_inputs) {
        return true;
    }
    
    if (!isPortInRange(port)) {
        logSecurityEvent("Invalid port range", "Port: " + std::to_string(port));
        return false;
    }
    
    return true;
}

bool SecurityManager::validateUser(const std::string& user) const {
    if (!config_.validate_inputs) {
        return true;
    }
    
    // Check for suspicious patterns
    if (detectInjectionAttempt(user)) {
        logSecurityEvent("Invalid user detected", "Potential injection in user: " + user);
        return false;
    }
    
    if (isUsernameValid(user)) {
        return true;
    }
    
    logSecurityEvent("Invalid user format", "User: " + user);
    return false;
}

bool SecurityManager::validateSSHCommand(const std::string& command) const {
    if (!config_.validate_inputs) {
        return true;
    }
    
    // Check for command injection patterns
    for (const auto& pattern : command_injection_patterns_) {
        if (std::regex_search(command, pattern)) {
            logSecurityEvent("Command injection detected", "Command: " + command);
            return false;
        }
    }
    
    return true;
}

bool SecurityManager::validateProfileName(const std::string& name) const {
    if (!config_.validate_inputs) {
        return true;
    }
    
    // Check for suspicious characters
    if (containsShellMetacharacters(name)) {
        logSecurityEvent("Invalid profile name", "Contains shell metacharacters: " + name);
        return false;
    }
    
    // Check length
    if (name.length() > config_.max_command_length) {
        logSecurityEvent("Invalid profile name", "Too long: " + name);
        return false;
    }
    
    return true;
}

std::string SecurityManager::sanitizeShellArgument(const std::string& input) const {
    if (!config_.sanitize_commands) {
        return input;
    }
    
    std::string sanitized = input;
    
    // Escape shell metacharacters
    static const char* metacharacters = " \t\n\"'`\\$(){}[]|;&<>?!*~";
    for (size_t i = 0; i < sanitized.length(); ++i) {
        if (std::strchr(metacharacters, sanitized[i])) {
            sanitized.insert(i, "\\");
            ++i; // Skip the backslash we just added
        }
    }
    
    // Remove control characters
    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(), 
        [](unsigned char c) { return std::iscntrl(c); }), sanitized.end());
    
    return sanitized;
}

std::string SecurityManager::sanitizeSSHCommand(const std::string& command) const {
    if (!config_.sanitize_commands) {
        return command;
    }
    
    std::string sanitized = command;
    
    // Remove dangerous patterns
    sanitized = std::regex_replace(sanitized, std::regex(R"(\bor\b)", std::regex::icase), "");
    sanitized = std::regex_replace(sanitized, std::regex(R"(\band\b)", std::regex::icase), "");
    sanitized = std::regex_replace(sanitized, std::regex(R"(\bdrop\b)", std::regex::icase), "");
    sanitized = std::regex_replace(sanitized, std::regex(R"(\bdelete\b)", std::regex::icase), "");
    
    // Escape quotes and backslashes
    sanitized = std::regex_replace(sanitized, std::regex(R"(\\")", std::regex::icase), "\\\\");
    sanitized = std::regex_replace(sanitized, std::regex(R"(")", std::regex::icase), "\\\"");
    sanitized = std::regex_replace(sanitized, std::regex(R"(')", std::regex::icase), "\\'");
    
    return sanitized;
}

std::string SecurityManager::escapeForShell(const std::string& input) const {
    return quoteForShell(input);
}

std::vector<std::string> SecurityManager::buildSecureSSHCommand(const SSHProfile& profile) const {
    std::vector<std::string> command_parts;
    
    // Build base SSH command
    command_parts.push_back("ssh");
    
    // Add port if not default
    if (profile.port != "22") {
        command_parts.push_back("-p");
        command_parts.push_back(sanitizeShellArgument(profile.port));
    }
    
    // Add identity file if specified
    if (profile.identity_file.has_value()) {
        command_parts.push_back("-i");
        command_parts.push_back(sanitizeShellArgument(profile.identity_file.value()));
    }
    
    // Add custom prefix if specified
    if (profile.prefix.has_value()) {
        // Parse and validate prefix
        std::vector<std::string> prefix_parts = ProcessUtils::splitString(profile.prefix.value(), ' ');
        for (const auto& part : prefix_parts) {
            if (!part.empty() && validateSSHCommand(part)) {
                command_parts.push_back(sanitizeShellArgument(part));
            }
        }
    } else {
        // Default SOCKS5 proxy
        command_parts.push_back("-D");
        command_parts.push_back(sanitizeShellArgument(profile.local_port));
    }
    
    // Add connection options
    command_parts.push_back("-N"); // No remote command
    command_parts.push_back("-T"); // Disable pseudo-terminal allocation
    command_parts.push_back("-o");
    command_parts.push_back("ServerAliveInterval=60");
    command_parts.push_back("-o");
    command_parts.push_back("ServerAliveCountMax=3");
    
    // Add connection timeout
    if (profile.timeout.has_value()) {
        command_parts.push_back("-o");
        command_parts.push_back("ConnectTimeout=" + std::to_string(profile.timeout.value()));
    }
    
    // Add target
    std::string target = sanitizeShellArgument(profile.user) + "@" + sanitizeShellArgument(profile.host);
    command_parts.push_back(target);
    
    return command_parts;
}

bool SecurityManager::isCommandSafe(const std::vector<std::string>& command_parts) const {
    for (const auto& part : command_parts) {
        if (!validateSSHCommand(part)) {
            return false;
        }
    }
    return true;
}

bool SecurityManager::validateFilePath(const std::string& path) const {
    if (!config_.validate_inputs) {
        return true;
    }
    
    // Check for path traversal attempts
    if (isPathTraversalAttempt(path)) {
        logSecurityEvent("Path traversal attempt", "Path: " + path);
        return false;
    }
    
    // Check for absolute paths that might be dangerous
    if (path.find("/etc/") == 0 || path.find("/bin/") == 0 || path.find("/usr/bin/") == 0) {
        logSecurityEvent("Dangerous path access", "Path: " + path);
        return false;
    }
    
    return true;
}

bool SecurityManager::checkFilePermissions(const std::string& path, int required_permissions) const {
    if (!config_.check_file_permissions) {
        return true;
    }
    
    try {
        int actual_permissions = ProcessUtils::getFilePermissions(path);
        return (actual_permissions & required_permissions) == required_permissions;
    } catch (const std::exception&) {
        return false;
    }
}

bool SecurityManager::secureFilePermissions(const std::string& path, int permissions) const {
    if (!config_.restrict_file_access) {
        return true;
    }
    
    try {
        return ProcessUtils::setFilePermissions(path, permissions);
    } catch (const std::exception&) {
        return false;
    }
}

bool SecurityManager::isPathTraversalAttempt(const std::string& path) const {
    for (const auto& pattern : path_traversal_patterns_) {
        if (std::regex_search(path, pattern)) {
            return true;
        }
    }
    return false;
}

void SecurityManager::secureClear(void* ptr, size_t size) const {
    if (!config_.secure_memory_clear || !ptr || size == 0) {
        return;
    }
    
    // Use volatile pointer to prevent compiler optimization
    volatile unsigned char* volatile_ptr = static_cast<volatile unsigned char*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        volatile_ptr[i] = 0;
    }
}

void SecurityManager::secureClearString(std::string& str) const {
    if (!config_.secure_memory_clear) {
        return;
    }
    
    // Clear the string data
    if (!str.empty()) {
        secureClear(&str[0], str.size());
        str.clear();
        str.shrink_to_fit();
    }
}

std::string SecurityManager::secureReadPassword(const std::string& prompt) const {
    std::string password;
    
    // Disable echo
    std::cout << prompt;
    std::cout.flush();
    
    // Read password character by character
    char ch;
    while (std::cin.get(ch)) {
        if (ch == '\n' || ch == '\r') {
            break;
        }
        if (ch == '\b' || ch == 127) { // Backspace or DEL
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b"; // Erase character
                std::cout.flush();
            }
        } else {
            password += ch;
            std::cout << "*";
            std::cout.flush();
        }
    }
    
    std::cout << std::endl;
    return password;
}

bool SecurityManager::validateProcessArguments(const std::vector<std::string>& args) const {
    for (const auto& arg : args) {
        if (detectInjectionAttempt(arg)) {
            return false;
        }
    }
    return true;
}

void SecurityManager::setupProcessSecurity() const {
    // Set up process security measures
    if (config_.disable_core_dumps) {
        disableCoreDumps();
    }
    
    // Additional process security setup can be added here
}

void SecurityManager::setSecurityConfig(const SecurityConfig& config) {
    config_ = config;
    initializeSecurity();
}

bool SecurityManager::detectInjectionAttempt(const std::string& input) const {
    for (const auto& pattern : injection_patterns_) {
        if (std::regex_search(input, pattern)) {
            return true;
        }
    }
    return false;
}

bool SecurityManager::detectSuspiciousActivity(const std::string& activity) const {
    // Check for suspicious patterns in activity descriptions
    std::vector<std::string> suspicious_keywords = {
        "exploit", "hack", "bypass", "overflow", "injection", "malicious",
        "unauthorized", "escalation", "privilege"
    };
    
    std::string lower_activity = ProcessUtils::toLowerCase(activity);
    for (const auto& keyword : suspicious_keywords) {
        if (lower_activity.find(keyword) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

void SecurityManager::logSecurityEvent(const std::string& event, const std::string& details) const {
    // This would typically write to a security log
    // For now, we'll use stderr to ensure it's visible
    std::cerr << "[SECURITY] " << event;
    if (!details.empty()) {
        std::cerr << ": " << details;
    }
    std::cerr << std::endl;
}

bool SecurityManager::isValidHostname(const std::string& hostname) const {
    if (hostname.empty() || hostname.length() > 253) {
        return false;
    }
    
    // Check for valid hostname characters
    for (char c : hostname) {
        if (!std::isalnum(c) && c != '-' && c != '.') {
            return false;
        }
    }
    
    // Check for valid domain name format
    std::vector<std::string> parts = ProcessUtils::splitString(hostname, '.');
    for (const auto& part : parts) {
        if (part.empty() || part.length() > 63) {
            return false;
        }
        if (part[0] == '-' || part.back() == '-') {
            return false;
        }
    }
    
    return true;
}

bool SecurityManager::isValidIPv4(const std::string& ip) const {
    std::vector<std::string> parts = ProcessUtils::splitString(ip, '.');
    if (parts.size() != 4) {
        return false;
    }
    
    for (const auto& part : parts) {
        try {
            int num = std::stoi(part);
            if (num < 0 || num > 255) {
                return false;
            }
        } catch (const std::exception&) {
            return false;
        }
    }
    
    return true;
}

bool SecurityManager::isValidIPv6(const std::string& ip) const {
    // Simplified IPv6 validation - a full implementation would be more complex
    if (ip.empty() || ip.length() > 39) {
        return false;
    }
    
    // Check for valid characters
    for (char c : ip) {
        if (!std::isxdigit(c) && c != ':' && c != '.') {
            return false;
        }
    }
    
    return true;
}

bool SecurityManager::isValidDomainName(const std::string& domain) const {
    return isValidHostname(domain);
}

bool SecurityManager::containsShellMetacharacters(const std::string& input) const {
    static const char* metacharacters = " \t\n\"'`\\$(){}[]|;&<>?!*~";
    for (char c : input) {
        if (std::strchr(metacharacters, c)) {
            return true;
        }
    }
    return false;
}

bool SecurityManager::isAllowedCommand(const std::string& command) const {
    // Check against whitelist if configured
    if (!config_.allowed_shell_commands.empty()) {
        for (const auto& allowed : config_.allowed_shell_commands) {
            if (command.find(allowed) == 0) {
                return true;
            }
        }
        return false;
    }
    
    // Default: allow only ssh-related commands
    return command.find("ssh") == 0 || command.find("scp") == 0;
}

std::vector<std::string> SecurityManager::sanitizeSSHArgs(const std::vector<std::string>& args) const {
    std::vector<std::string> sanitized;
    for (const auto& arg : args) {
        sanitized.push_back(sanitizeShellArgument(arg));
    }
    return sanitized;
}

std::string SecurityManager::quoteForShell(const std::string& input) const {
    if (input.empty()) {
        return "''";
    }
    
    // If input contains single quotes, we need to handle them specially
    if (input.find('\'') != std::string::npos) {
        std::string result;
        for (size_t i = 0; i < input.length(); ++i) {
            if (input[i] == '\'') {
                result += "'\"'\"'"; // Close quote, add escaped quote, open quote
            } else {
                result += input[i];
            }
        }
        return "'" + result + "'";
    } else {
        return "'" + input + "'";
    }
}

void SecurityManager::disableCoreDumps() const {
    struct rlimit limit;
    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &limit);
}

bool SecurityManager::isPortInRange(int port) {
    return port >= 1 && port <= 65535;
}

bool SecurityManager::isUsernameValid(const std::string& username) {
    if (username.empty() || username.length() > 32) {
        return false;
    }
    
    // Check for valid username characters
    for (char c : username) {
        if (!std::isalnum(c) && c != '_' && c != '-' && c != '.') {
            return false;
        }
    }
    
    // Check for reserved usernames
    std::vector<std::string> reserved = {"root", "admin", "administrator", "system", "daemon"};
    for (const auto& reserved_name : reserved) {
        if (ProcessUtils::toLowerCase(username) == reserved_name) {
            return false;
        }
    }
    
    return true;
}

SSHError SecurityManager::createSSHError(SSHError::Type type, const std::string& message, const std::string& details) {
    SSHError error;
    error.type = type;
    error.message = message;
    error.details = details;
    return error;
}

// SecurityUtils implementations
namespace SecurityUtils {
    bool isValidEmail(const std::string& email) {
        static const std::regex email_regex(
            R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
        );
        return std::regex_match(email, email_regex);
    }
    
    bool isValidURL(const std::string& url) {
        static const std::regex url_regex(
            R"(https?://[^\s/$.?#].[^\s]*)"
        );
        return std::regex_match(url, url_regex);
    }
    
    bool isValidPath(const std::string& path) {
        if (path.empty() || path.length() > 4096) {
            return false;
        }
        
        // Check for path traversal
        if (path.find("..") != std::string::npos) {
            return false;
        }
        
        return true;
    }
    
    bool isValidHexColor(const std::string& color) {
        static const std::regex hex_color_regex(R"(^#[0-9A-Fa-f]{6}$|^#[0-9A-Fa-f]{3}$)");
        return std::regex_match(color, hex_color_regex);
    }
    
    std::string removeDangerousCharacters(const std::string& input) {
        std::string result;
        for (char c : input) {
            if (!std::iscntrl(c) && c != '\x7f') { // Remove control characters and DEL
                result += c;
            }
        }
        return result;
    }
    
    std::string normalizeWhitespace(const std::string& input) {
        std::string result = input;
        
        // Replace multiple spaces/tabs with single space
        static const std::regex whitespace_regex(R"(\s+)");
        result = std::regex_replace(result, whitespace_regex, " ");
        
        // Trim leading and trailing whitespace
        result.erase(result.begin(), std::find_if(result.begin(), result.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
        result.erase(std::find_if(result.rbegin(), result.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), result.end());
        
        return result;
    }
    
    std::string stripControlCharacters(const std::string& input) {
        std::string result;
        for (unsigned char c : input) {
            if (!std::iscntrl(c)) {
                result += c;
            }
        }
        return result;
    }
    
    std::string base64Encode(const std::vector<uint8_t>& data) {
        static const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::string result;
        int val = 0, valb = -8;
        
        for (unsigned char c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        
        if (valb > -8) {
            result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        
        while (result.size() % 4) {
            result.push_back('=');
        }
        
        return result;
    }
    
    std::vector<uint8_t> base64Decode(const std::string& encoded) {
        static const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;
        
        std::vector<uint8_t> result;
        int val = 0, valb = -8;
        
        for (unsigned char c : encoded) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                result.push_back((val >> valb) & 0xFF);
                valb -= 8;
            }
        }
        
        return result;
    }
    
    std::string urlEncode(const std::string& input) {
        std::ostringstream oss;
        for (unsigned char c : input) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                oss << c;
            } else {
                oss << '%' << std::hex << std::uppercase << (int)c;
            }
        }
        return oss.str();
    }
    
    std::string urlDecode(const std::string& input) {
        std::string result;
        for (size_t i = 0; i < input.length(); ++i) {
            if (input[i] == '%' && i + 2 < input.length()) {
                std::string hex = input.substr(i + 1, 2);
                try {
                    int value = std::stoi(hex, nullptr, 16);
                    result += static_cast<char>(value);
                    i += 2;
                } catch (const std::exception&) {
                    result += input[i];
                }
            } else {
                result += input[i];
            }
        }
        return result;
    }
    
    std::string generateSecureToken(size_t length) {
        static const std::string charset = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, charset.size() - 1);
        
        std::string result;
        for (size_t i = 0; i < length; ++i) {
            result += charset[dis(gen)];
        }
        return result;
    }
    
    bool verifyFileIntegrity(const std::string& filepath, const std::string& expected_hash) {
        std::string actual_hash = ProcessUtils::calculateFileHash(filepath);
        return actual_hash == expected_hash;
    }
    
    std::string calculateFileHash(const std::string& filepath) {
        return ProcessUtils::sha256Hash(filepath);
    }
    
    int generateSecureRandomInt(int min, int max) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min, max);
        return dis(gen);
    }
    
    std::vector<uint8_t> generateSecureRandomBytes(size_t length) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        std::vector<uint8_t> result(length);
        for (size_t i = 0; i < length; ++i) {
            result[i] = static_cast<uint8_t>(dis(gen));
        }
        return result;
    }
    
    bool isWithinTimeWindow(const std::chrono::steady_clock::time_point& start, 
                           std::chrono::seconds max_duration) {
        auto now = std::chrono::steady_clock::now();
        return (now - start) <= max_duration;
    }
    
    std::chrono::steady_clock::time_point getCurrentTime() {
        return std::chrono::steady_clock::now();
    }
}

} // namespace SSHVPN