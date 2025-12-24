#ifndef CONNECTION_MANAGER_H
#define CONNECTION_MANAGER_H

#include "types.h"
#include "ssh_client.h"
#include "config_manager.h"
#include "logger.h"
#include <map>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <chrono>

namespace SSHVPN {

class Connection {
public:
    explicit Connection(const std::string& profile_name, 
                       std::shared_ptr<SSHClient> client,
                       std::shared_ptr<Logger> logger);
    ~Connection();
    
    // Connection lifecycle
    bool start();
    bool stop();
    bool restart();
    bool isActive() const;
    ConnectionStatus getStatus() const;
    
    // Profile management
    void setProfile(const SSHProfile& profile);
    SSHProfile getProfile() const { return profile_; }
    std::string getProfileName() const { return profile_name_; }
    
    // Statistics and monitoring
    ConnectionStats getStatistics() const;
    void resetStatistics();
    std::string getConnectionSummary() const;
    
    // Error handling
    std::string getLastError() const;
    void clearError();
    
    // Event handling
    using ConnectionEventHandler = std::function<void(const std::string& profile_name, ConnectionStatus status)>;
    using ErrorEventHandler = std::function<void(const std::string& profile_name, const std::string& error)>;
    using StatisticsEventHandler = std::function<void(const std::string& profile_name, const ConnectionStats& stats)>;
    
    void setConnectionEventHandler(ConnectionEventHandler handler);
    void setErrorEventHandler(ErrorEventHandler handler);
    void setStatisticsEventHandler(StatisticsEventHandler handler);
    
    // Configuration
    void setConnectionConfig(const ConnectionConfig& config);
    ConnectionConfig getConnectionConfig() const;
    
    // Health monitoring
    bool isHealthy() const;
    void performHealthCheck();
    std::chrono::steady_clock::time_point getLastHealthCheck() const;
    
    // Thread safety
    void lock() const { connection_mutex_.lock(); }
    void unlock() const { connection_mutex_.unlock(); }
    bool tryLock() const { return connection_mutex_.try_lock(); }
    
private:
    std::string profile_name_;
    SSHProfile profile_;
    ConnectionConfig config_;
    
    std::shared_ptr<SSHClient> client_;
    std::shared_ptr<Logger> logger_;
    
    ConnectionStatus status_ = ConnectionStatus::DISCONNECTED;
    ConnectionStats stats_;
    std::string last_error_;
    
    // Health monitoring
    std::chrono::steady_clock::time_point last_health_check_;
    std::atomic<bool> health_check_running_{false};
    
    // Event handlers
    ConnectionEventHandler connection_handler_;
    ErrorEventHandler error_handler_;
    StatisticsEventHandler statistics_handler_;
    
    // Threading
    mutable std::mutex connection_mutex_;
    std::thread health_monitor_;
    std::atomic<bool> should_stop_{false};
    
    // Internal methods
    void monitorConnection();
    void performHealthCheckInternal();
    void handleConnectionEvent(ConnectionStatus new_status);
    void handleError(const std::string& error);
    void updateStatistics();
    void startHealthMonitoring();
    void stopHealthMonitoring();
    
    // Auto-reconnection
    bool attemptReconnection(int attempt_number);
    bool shouldAttemptReconnection() const;
    std::chrono::seconds getReconnectionDelay(int attempt_number) const;
};

class ConnectionManager {
public:
    explicit ConnectionManager(std::shared_ptr<ConfigManager> config_manager,
                              std::shared_ptr<Logger> logger = nullptr);
    ~ConnectionManager();
    
    // Connection management
    bool startConnection(const std::string& profile_name);
    bool stopConnection(const std::string& profile_name);
    bool restartConnection(const std::string& profile_name);
    bool stopAllConnections();
    
    // Connection status
    ConnectionStatus getConnectionStatus(const std::string& profile_name) const;
    std::map<std::string, ConnectionStatus> getAllConnectionStatuses() const;
    std::vector<std::string> getActiveConnections() const;
    bool isConnectionActive(const std::string& profile_name) const;
    
    // Profile management
    bool addConnection(const SSHProfile& profile);
    bool removeConnection(const std::string& profile_name);
    bool updateConnection(const std::string& profile_name, const SSHProfile& updated_profile);
    std::optional<SSHProfile> getConnectionProfile(const std::string& profile_name) const;
    std::vector<SSHProfile> getAllConnectionProfiles() const;
    
    // Batch operations
    bool startMultipleConnections(const std::vector<std::string>& profile_names);
    bool stopMultipleConnections(const std::vector<std::string>& profile_names);
    bool restartMultipleConnections(const std::vector<std::string>& profile_names);
    
    // Statistics and monitoring
    std::map<std::string, ConnectionStats> getAllConnectionStatistics() const;
    ConnectionStats getConnectionStatistics(const std::string& profile_name) const;
    void resetAllStatistics();
    void resetConnectionStatistics(const std::string& profile_name);
    
    // Global configuration
    void setGlobalConnectionConfig(const ConnectionConfig& config);
    ConnectionConfig getGlobalConnectionConfig() const;
    void setMaxConcurrentConnections(int max);
    int getMaxConcurrentConnections() const;
    
    // Event handling
    using GlobalConnectionEventHandler = std::function<void(const std::string& profile_name, ConnectionStatus status)>;
    using GlobalErrorEventHandler = std::function<void(const std::string& profile_name, const std::string& error)>;
    using GlobalStatisticsEventHandler = std::function<void(const std::string& profile_name, const ConnectionStats& stats)>;
    
    void setGlobalConnectionEventHandler(GlobalConnectionEventHandler handler);
    void setGlobalErrorEventHandler(GlobalErrorEventHandler handler);
    void setGlobalStatisticsEventHandler(GlobalStatisticsEventHandler handler);
    
    // Health monitoring
    void enableHealthMonitoring(bool enable);
    bool isHealthMonitoringEnabled() const;
    void setHealthCheckInterval(std::chrono::seconds interval);
    std::chrono::seconds getHealthCheckInterval() const;
    std::map<std::string, bool> getAllConnectionHealthStatus() const;
    
    // Auto-reconnection settings
    void setAutoReconnect(bool enable);
    bool isAutoReconnectEnabled() const;
    void setMaxReconnectAttempts(int attempts);
    int getMaxReconnectAttempts() const;
    void setReconnectDelay(std::chrono::seconds delay);
    std::chrono::seconds getReconnectDelay() const;
    
    // Performance optimization
    void setConnectionPoolSize(int size);
    int getConnectionPoolSize() const;
    bool enableConnectionPooling(bool enable);
    bool isConnectionPoolingEnabled() const;
    
    // Logging and debugging
    void setVerboseLogging(bool enable);
    bool isVerboseLoggingEnabled() const;
    void generateConnectionReport(const std::string& output_file = "") const;
    std::string getConnectionReport() const;
    
    // Configuration management
    void reloadConfiguration();
    bool saveConnectionStates();
    bool restoreConnectionStates();
    
    // Thread safety
    void lock() const { manager_mutex_.lock(); }
    void unlock() const { manager_mutex_.unlock(); }
    bool tryLock() const { return manager_mutex_.try_lock(); }
    void lockShared() const { manager_mutex_.lock_shared(); }
    void unlockShared() const { manager_mutex_.unlock_shared(); }
    
    // Utility methods
    std::string getManagerSummary() const;
    void performMaintenance();
    
private:
    // Dependencies
    std::shared_ptr<ConfigManager> config_manager_;
    std::shared_ptr<Logger> logger_;
    
    // Connection storage
    ConnectionMap connections_;
    std::shared_mutex connections_mutex_;
    
    // Global configuration
    ConnectionConfig global_config_;
    std::atomic<int> max_concurrent_connections_{10};
    std::atomic<bool> health_monitoring_enabled_{true};
    std::atomic<std::chrono::seconds> health_check_interval_{60};
    
    // Auto-reconnection settings
    std::atomic<bool> auto_reconnect_enabled_{true};
    std::atomic<int> max_reconnect_attempts_{3};
    std::atomic<std::chrono::seconds> reconnect_delay_{5};
    
    // Performance optimization
    std::atomic<int> connection_pool_size_{5};
    std::atomic<bool> connection_pooling_enabled_{false};
    
    // Logging and debugging
    std::atomic<bool> verbose_logging_{false};
    
    // Threading
    mutable std::shared_mutex manager_mutex_;
    std::thread maintenance_thread_;
    std::atomic<bool> should_stop_{false};
    
    // Event handlers
    GlobalConnectionEventHandler global_connection_handler_;
    GlobalErrorEventHandler global_error_handler_;
    GlobalStatisticsEventHandler global_statistics_handler_;
    
    // Internal methods
    void maintenanceLoop();
    void handleConnectionEvent(const std::string& profile_name, ConnectionStatus status);
    void handleConnectionError(const std::string& profile_name, const std::string& error);
    void handleConnectionStatistics(const std::string& profile_name, const ConnectionStats& stats);
    
    // Connection creation and management
    std::shared_ptr<Connection> createConnection(const std::string& profile_name, const SSHProfile& profile);
    bool validateConnectionLimit() const;
    void cleanupInactiveConnections();
    
    // Batch operation helpers
    std::vector<std::string> validateProfileNames(const std::vector<std::string>& profile_names) const;
    bool executeBatchOperation(const std::vector<std::string>& profile_names, 
                              std::function<bool(const std::string&)> operation);
    
    // Configuration synchronization
    void synchronizeWithConfigManager();
    void handleConfigManagerEvents();
    
    // Health monitoring
    void monitorAllConnections();
    void checkConnectionHealth(const std::string& profile_name);
    
    // Statistics aggregation
    void updateGlobalStatistics();
    ConnectionStats aggregateConnectionStatistics() const;
    
    // Error handling
    void handleManagerError(const std::string& error);
    void logConnectionEvent(const std::string& profile_name, const std::string& event, const std::string& details = "");
};

// Connection manager factory and utilities
namespace ConnectionManagerUtils {
    // Connection testing
    bool testConnectionProfile(const SSHProfile& profile, int timeout_seconds = 10);
    std::vector<std::string> findProblematicConnections(const std::map<std::string, ConnectionStatus>& statuses);
    
    // Performance analysis
    std::map<std::string, double> calculateConnectionSuccessRates(const std::map<std::string, ConnectionStats>& stats);
    std::map<std::string, std::chrono::milliseconds> calculateAverageConnectionTimes(const std::map<std::string, ConnectionStats>& stats);
    
    // Optimization recommendations
    std::vector<std::string> getOptimizationRecommendations(const ConnectionManager& manager);
    bool suggestConnectionPoolSize(const std::vector<SSHProfile>& profiles, int& recommended_size);
    
    // Configuration validation
    bool validateConnectionConfiguration(const ConnectionConfig& config, std::vector<std::string>& errors);
    ConnectionConfig optimizeConnectionConfig(const ConnectionConfig& base_config, const std::vector<SSHProfile>& profiles);
}

// Exception classes for connection manager
class ConnectionManagerException : public std::runtime_error {
public:
    explicit ConnectionManagerException(const std::string& message) 
        : std::runtime_error("Connection manager error: " + message) {}
};

class ConnectionLimitException : public ConnectionManagerException {
public:
    explicit ConnectionLimitException(int limit, int requested)
        : ConnectionManagerException("Connection limit exceeded: requested " + std::to_string(requested) + 
                                    ", maximum " + std::to_string(limit)) {}
};

class InvalidConnectionException : public ConnectionManagerException {
public:
    explicit InvalidConnectionException(const std::string& profile_name, const std::string& reason)
        : ConnectionManagerException("Invalid connection for profile '" + profile_name + "': " + reason) {}
};

class ConnectionPoolException : public ConnectionManagerException {
public:
    explicit ConnectionPoolException(const std::string& operation, const std::string& reason)
        : ConnectionManagerException("Connection pool " + operation + " failed: " + reason) {}
};

} // namespace SSHVPN

#endif // CONNECTION_MANAGER_H