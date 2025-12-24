#ifndef TYPES_H
#define TYPES_H

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>
#include <memory>

namespace SSHVPN {

// Configuration structures
struct SSHProfile {
    std::string name;
    std::string host;
    std::string user;
    std::string port;
    std::string local_port;
    std::optional<std::string> identity_file;
    std::optional<std::string> prefix;
    std::optional<std::string> password;
    std::optional<int> timeout;
    std::optional<bool> auto_reconnect;
    std::optional<int> reconnect_attempts;
    std::optional<int> reconnect_delay;
    
    // Validation
    bool isValid() const;
    std::vector<std::string> validate() const;
};

struct ConnectionConfig {
    int max_retry_attempts = 3;
    int retry_delay_seconds = 5;
    int connection_timeout_seconds = 30;
    int command_timeout_seconds = 60;
    bool keep_alive = true;
    int keep_alive_interval = 60;
    bool verify_host_key = true;
    bool compress_data = false;
};

// Authentication types
enum class AuthType {
    PASSWORD,
    PUBLIC_KEY,
    KEYBOARD_INTERACTIVE,
    NONE
};

// Connection status
enum class ConnectionStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    RECONNECTING,
    ERROR,
    TIMEOUT
};

// Log levels
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
};

// Security configuration
struct SecurityConfig {
    bool validate_inputs = true;
    bool sanitize_commands = true;
    bool check_file_permissions = true;
    bool restrict_file_access = true;
    bool disable_core_dumps = true;
    bool secure_memory_clear = true;
    int max_command_length = 4096;
    std::vector<std::string> allowed_shell_commands;
};

// Error types
struct SSHError {
    enum class Type {
        CONNECTION_FAILED,
        AUTHENTICATION_FAILED,
        TIMEOUT,
        COMMAND_FAILED,
        FILE_ERROR,
        SECURITY_VIOLATION,
        CONFIGURATION_ERROR,
        NETWORK_ERROR,
        UNKNOWN
    };
    
    Type type;
    std::string message;
    std::string details;
    int error_code = 0;
    
    static SSHError create(Type type, const std::string& message, const std::string& details = "");
};

// Statistics
struct ConnectionStats {
    std::chrono::steady_clock::time_point connection_start;
    std::chrono::steady_clock::time_point last_activity;
    size_t bytes_sent = 0;
    size_t bytes_received = 0;
    int reconnect_count = 0;
    bool is_active = false;
};

// Process information
struct ProcessInfo {
    pid_t pid = 0;
    int exit_code = 0;
    bool is_running = false;
    std::string command_line;
    std::chrono::steady_clock::time_point start_time;
};

// CLI options
struct CLIOptions {
    bool verbose = false;
    bool quiet = false;
    bool daemon = false;
    std::string config_file;
    std::string log_file;
    LogLevel log_level = LogLevel::INFO;
    int max_connections = 10;
    bool version = false;
    bool help = false;
};

// Configuration manager options
struct ConfigManagerOptions {
    std::string config_dir = "~/.config/sshvpn";
    std::string log_dir = "~/.cache/sshvpn";
    std::string pid_dir = "/tmp/sshvpn";
    bool create_directories = true;
    bool backup_on_save = true;
    int max_backup_files = 5;
};

// Utility types
using ProfileMap = std::map<std::string, SSHProfile>;
using ConnectionMap = std::map<std::string, std::unique_ptr<class Connection>>;

} // namespace SSHVPN

#endif // TYPES_H