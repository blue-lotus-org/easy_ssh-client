#ifndef SSH_CLIENT_H
#define SSH_CLIENT_H

#include "types.h"
#include "security.h"
#include "logger.h"
#include "config_manager.h"
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <future>

#ifdef USE_LIBSSH
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#endif

namespace SSHVPN {

class SSHClient {
public:
    explicit SSHClient(const std::shared_ptr<Logger>& logger = nullptr);
    ~SSHClient();
    
    // Delete copy constructor and assignment operator
    SSHClient(const SSHClient&) = delete;
    SSHClient& operator=(const SSHClient&) = delete;
    
    // Connection management
    bool connect(const SSHProfile& profile, const ConnectionConfig& config = ConnectionConfig{});
    bool disconnect();
    bool isConnected() const;
    ConnectionStatus getStatus() const { return status_; }
    
    // Command execution
    std::pair<int, std::string> executeCommand(const std::string& command, int timeout_seconds = 30);
    std::pair<int, std::string> executeCommandSecure(const std::string& command, int timeout_seconds = 30);
    
    // Tunnel management
    bool startSOCKS5Proxy(int local_port, int remote_port = 1080);
    bool startPortForward(const std::string& local_host, int local_port, 
                         const std::string& remote_host, int remote_port);
    bool startReversePortForward(int local_port, const std::string& remote_host, int remote_port);
    bool stopTunnel();
    
    // Process management
    pid_t startTunnelProcess(const std::vector<std::string>& command_args);
    bool stopTunnelProcess();
    bool isProcessRunning() const;
    ProcessInfo getProcessInfo() const;
    
    // Authentication
    bool authenticateWithPassword(const std::string& password);
    bool authenticateWithKey(const std::string& key_path, const std::string& passphrase = "");
    bool authenticateWithAgent();
    
    // Connection configuration
    void setConnectionConfig(const ConnectionConfig& config);
    ConnectionConfig getConnectionConfig() const { return config_; }
    
    // Security settings
    void setSecurityManager(std::shared_ptr<SecurityManager> security);
    std::shared_ptr<SecurityManager> getSecurityManager() const { return security_; }
    
    // Event handling
    using ConnectionEventHandler = std::function<void(ConnectionStatus, const std::string&)>;
    using DataEventHandler = std::function<void(const std::string& data, bool is_error)>;
    
    void setConnectionEventHandler(ConnectionEventHandler handler);
    void setDataEventHandler(DataEventHandler handler);
    
    // Statistics and monitoring
    ConnectionStats getStatistics() const;
    void resetStatistics();
    
    // Error handling
    std::string getLastError() const { return last_error_; }
    int getErrorCode() const { return error_code_; }
    void clearError();
    
    // Configuration validation
    bool validateProfile(const SSHProfile& profile) const;
    bool testConnection(const SSHProfile& profile, int timeout_seconds = 10);
    
    // Utility methods
    std::string getServerVersion() const;
    std::string getClientVersion() const;
    bool isHostKeyVerified() const;
    bool verifyHostKey(const std::string& expected_key);
    
    // Thread safety
    void lock() const { connection_mutex_.lock(); }
    void unlock() const { connection_mutex_.unlock(); }
    bool tryLock() const { return connection_mutex_.try_lock(); }
    
private:
    // Connection state
    ConnectionStatus status_ = ConnectionStatus::DISCONNECTED;
    ConnectionConfig config_;
    ConnectionStats stats_;
    ProcessInfo process_info_;
    
    // SSH connection details
    SSHProfile current_profile_;
    std::string host_key_;
    std::string server_version_;
    std::string client_version_;
    
    // Error handling
    std::string last_error_;
    int error_code_ = 0;
    
    // Threading
    mutable std::mutex connection_mutex_;
    std::atomic<bool> should_stop_{false};
    std::thread connection_monitor_;
    std::thread data_monitor_;
    
    // Dependencies
    std::shared_ptr<Logger> logger_;
    std::shared_ptr<SecurityManager> security_;
    
    // Event handlers
    ConnectionEventHandler connection_handler_;
    DataEventHandler data_handler_;
    
#ifdef USE_LIBSSH
    // libssh specific
    ssh_session session_ = nullptr;
    ssh_channel channel_ = nullptr;
    
    // libssh callbacks
    static int authCallback(const char* prompt, char* buf, size_t len, int echo, int verify, void* userdata);
    static void logCallback(int priority, const char* message, void* userdata);
#endif
    
    // Internal methods
    bool initializeConnection();
    bool establishConnection();
    bool performAuthentication();
    bool setupConnection();
    void monitorConnection();
    void monitorData();
    
    // Process management
    bool forkAndExecute(const std::vector<std::string>& command);
    bool setupChildProcess();
    void cleanupProcess();
    
    // Command execution
    std::pair<int, std::string> executeCommandInternal(const std::string& command, int timeout);
    bool prepareCommand(const std::string& command, std::vector<std::string>& safe_args) const;
    
    // Tunnel management
    bool createSOCKS5Proxy(int local_port);
    bool createPortForward(const std::string& local_host, int local_port,
                          const std::string& remote_host, int remote_port);
    bool createReversePortForward(int local_port, const std::string& remote_host, int remote_port);
    
    // Authentication helpers
    bool authenticateKeyboardInteractive();
    bool authenticatePublicKeyFile(const std::string& key_path);
    bool authenticateWithAgentImpl();
    
    // Error handling helpers
    void setError(const std::string& error, int code = 0);
    bool handleSSHError(const std::string& context);
    
    // Security helpers
    bool validateAndSanitizeCommand(const std::string& command, std::string& sanitized) const;
    bool validateHostKey(const std::string& host_key);
    
    // Statistics helpers
    void updateStatistics(const std::string& operation, size_t bytes = 0);
    void resetStatsInternal();
    
    // Connection monitoring
    void startMonitoring();
    void stopMonitoring();
    bool checkConnectionHealth() const;
    
    // Configuration helpers
    bool validateSSHConfig(const SSHProfile& profile) const;
    bool validateConnectionConfig(const ConnectionConfig& config) const;
    
    // Cleanup
    void cleanup();
    void cleanupSession();
    void cleanupChannels();
};

// SSH Connection exception classes
class SSHConnectionException : public std::runtime_error {
public:
    explicit SSHConnectionException(const std::string& message, int error_code = 0)
        : std::runtime_error("SSH connection error: " + message), error_code_(error_code) {}
    
    int getErrorCode() const { return error_code_; }
    
private:
    int error_code_;
};

class SSHAuthenticationException : public SSHConnectionException {
public:
    explicit SSHAuthenticationException(const std::string& message, int error_code = 0)
        : SSHConnectionException("Authentication failed: " + message, error_code) {}
};

class SSHTimeoutException : public SSHConnectionException {
public:
    explicit SSHTimeoutException(const std::string& message)
        : SSHConnectionException("Connection timeout: " + message) {}
};

class SSHCommandException : public SSHConnectionException {
public:
    explicit SSHCommandException(const std::string& command, int exit_code, const std::string& output)
        : SSHConnectionException("Command failed: " + command + " (exit code: " + std::to_string(exit_code) + ")", exit_code),
          command_(command), exit_code_(exit_code), output_(output) {}
    
    const std::string& getCommand() const { return command_; }
    int getExitCode() const { return exit_code_; }
    const std::string& getOutput() const { return output_; }
    
private:
    std::string command_;
    int exit_code_;
    std::string output_;
};

// SSH Client factory and utilities
namespace SSHUtils {
    // Connection testing
    bool testSSHConnection(const SSHProfile& profile, int timeout_seconds = 10);
    bool testPortConnectivity(const std::string& host, int port, int timeout_seconds = 5);
    
    // Key management
    bool generateSSHKeyPair(const std::string& public_key_path, const std::string& private_key_path,
                           const std::string& passphrase = "", int key_type = SSH_KEYTYPE_RSA);
    bool validateSSHKey(const std::string& key_path);
    std::string getSSHKeyFingerprint(const std::string& key_path);
    
    // Host key verification
    bool verifyKnownHost(const std::string& host, int port, const std::string& expected_key);
    std::string getHostKey(const std::string& host, int port);
    
    // SSH agent management
    bool isSSHAgentRunning();
    std::vector<std::string> listSSHAgentKeys();
    bool addKeyToSSHAgent(const std::string& key_path, const std::string& passphrase = "");
    
    // Configuration helpers
    bool isValidSSHConfig(const SSHProfile& profile);
    std::vector<std::string> getSSHConfigSuggestions(const SSHProfile& profile);
    
    // Network utilities
    bool isPortAvailable(int port);
    bool findAvailablePort(int start_port = 1080, int max_attempts = 100);
    std::string getLocalIPAddress();
}

} // namespace SSHVPN

#endif // SSH_CLIENT_H