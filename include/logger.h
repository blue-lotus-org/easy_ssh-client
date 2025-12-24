#ifndef LOGGER_H
#define LOGGER_H

#include "types.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sink.h>
#include <spdlog/sinks/dist_sink.h>
#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <mutex>
#include <atomic>

namespace SSHVPN {

class Logger {
public:
    explicit Logger(const std::string& name = "sshvpn", 
                   const std::string& log_file = "",
                   LogLevel min_level = LogLevel::INFO);
    ~Logger() = default;
    
    // Delete copy constructor and assignment operator
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    // Logging methods
    void debug(const std::string& message, const std::string& category = "");
    void info(const std::string& message, const std::string& category = "");
    void warning(const std::string& message, const std::string& category = "");
    void error(const std::string& message, const std::string& category = "");
    void critical(const std::string& message, const std::string& category = "");
    
    // Structured logging with context
    void logWithContext(LogLevel level, const std::string& message, 
                       const std::map<std::string, std::string>& context = {});
    void logConnectionEvent(const std::string& profile_name, const std::string& event,
                           const std::string& details = "");
    void logSecurityEvent(const std::string& event, const std::string& details = "",
                         const std::string& severity = "medium");
    void logPerformanceMetric(const std::string& metric, double value,
                             const std::string& unit = "");
    
    // Configuration
    void setLogLevel(LogLevel level);
    void setLogFile(const std::string& log_file);
    void setMaxFileSize(size_t max_size);
    void setMaxFiles(int max_files);
    void enableConsoleLogging(bool enable);
    void enableFileLogging(bool enable);
    
    // Log file management
    bool rotateLogFile();
    bool flush();
    void clearLogs();
    
    // Log analysis and querying
    std::vector<std::string> getRecentLogs(int count = 100) const;
    std::vector<std::string> getLogsByLevel(LogLevel level) const;
    std::vector<std::string> getLogsByCategory(const std::string& category) const;
    std::vector<std::string> searchLogs(const std::string& pattern) const;
    
    // Statistics
    struct LogStats {
        size_t total_messages = 0;
        size_t debug_count = 0;
        size_t info_count = 0;
        size_t warning_count = 0;
        size_t error_count = 0;
        size_t critical_count = 0;
        std::chrono::steady_clock::time_point first_message;
        std::chrono::steady_clock::time_point last_message;
        size_t file_size_bytes = 0;
    };
    
    LogStats getStatistics() const;
    
    // Utility methods
    std::string getLogFilePath() const;
    bool isLoggingEnabled() const { return logging_enabled_; }
    LogLevel getCurrentLogLevel() const { return current_level_; }
    
    // Thread safety
    void lock() const { log_mutex_.lock(); }
    void unlock() const { log_mutex_.unlock(); }
    
    // Global logger access
    static std::shared_ptr<Logger> getGlobalLogger();
    static void setGlobalLogger(std::shared_ptr<Logger> logger);
    
    // Log levels conversion
    static spdlog::level::level_enum toSpdlogLevel(LogLevel level);
    static LogLevel fromSpdlogLevel(spdlog::level::level_enum level);
    
private:
    std::string name_;
    std::shared_ptr<spdlog::logger> logger_;
    std::shared_ptr<spdlog::sinks::rotating_file_sink_st> file_sink_;
    std::shared_ptr<spdlog::sinks::stdout_color_sink_st> console_sink_;
    std::shared_ptr<spdlog::sinks::dist_sink_st> sink_;
    
    mutable std::mutex log_mutex_;
    std::atomic<bool> logging_enabled_{true};
    LogLevel current_level_;
    std::atomic<size_t> max_file_size_{10 * 1024 * 1024}; // 10MB
    std::atomic<int> max_files_{5};
    
    // Internal helpers
    void initializeLogger();
    void setupSinks();
    std::string formatMessage(const std::string& level, const std::string& message, 
                             const std::string& category) const;
    std::string getCurrentTimestamp() const;
    
    // Log file utilities
    bool checkLogFileSize();
    void updateFileSink();
};

// Security-focused logger for sensitive operations
class SecurityLogger {
public:
    explicit SecurityLogger(std::shared_ptr<Logger> base_logger);
    ~SecurityLogger() = default;
    
    // Security-specific logging
    void logAuthAttempt(const std::string& profile, const std::string& method, bool success);
    void logCommandExecution(const std::string& profile, const std::string& command, bool success);
    void logFileAccess(const std::string& operation, const std::string& path, bool allowed);
    void logSecurityViolation(const std::string& violation_type, const std::string& details);
    void logConnectionAttempt(const std::string& profile, const std::string& host, bool success);
    void logConfigChange(const std::string& profile, const std::string& field, const std::string& old_value, const std::string& new_value);
    
    // Privacy-aware logging (sanitizes sensitive data)
    std::string sanitizeForLogging(const std::string& data) const;
    bool shouldLogSensitiveData() const { return log_sensitive_data_; }
    void setLogSensitiveData(bool enable) { log_sensitive_data_ = enable; }
    
private:
    std::shared_ptr<Logger> logger_;
    bool log_sensitive_data_ = false;
    
    // Data sanitization patterns
    static const std::vector<std::regex> sensitive_patterns_;
    
    std::string sanitizePassword(const std::string& password) const;
    std::string sanitizeKeyData(const std::string& key_data) const;
    std::string sanitizeIPAddress(const std::string& ip) const;
};

// Performance logger for monitoring and optimization
class PerformanceLogger {
public:
    explicit PerformanceLogger(std::shared_ptr<Logger> base_logger);
    ~PerformanceLogger() = default;
    
    // Performance metrics
    void logConnectionTime(const std::string& profile, std::chrono::milliseconds duration);
    void logCommandExecutionTime(const std::string& profile, const std::string& command, 
                                std::chrono::milliseconds duration);
    void logMemoryUsage(const std::string& component, size_t bytes);
    void logNetworkThroughput(const std::string& profile, size_t bytes_transferred, 
                             std::chrono::milliseconds duration);
    void logReconnectionAttempt(const std::string& profile, int attempt_number, bool success);
    
    // Performance alerts
    void logSlowOperation(const std::string& operation, std::chrono::milliseconds threshold);
    void logHighMemoryUsage(const std::string& component, size_t threshold);
    void logConnectionTimeout(const std::string& profile, std::chrono::milliseconds timeout_duration);
    
    // Performance analysis
    void generatePerformanceReport() const;
    std::map<std::string, double> getAverageConnectionTimes() const;
    std::map<std::string, size_t> getConnectionSuccessRates() const;
    
private:
    std::shared_ptr<Logger> logger_;
    
    // Performance data storage
    mutable std::mutex perf_mutex_;
    std::vector<std::chrono::steady_clock::time_point> connection_times_;
    std::vector<std::chrono::steady_clock::time_point> command_times_;
    std::map<std::string, std::vector<std::chrono::milliseconds>> profile_connection_times_;
};

// Exception-safe logging wrapper
class SafeLogger {
public:
    template<typename... Args>
    static void logSafely(std::shared_ptr<Logger> logger, LogLevel level, 
                         const std::string& format, Args&&... args) {
        try {
            if (logger && logger->isLoggingEnabled()) {
                logger->logWithContext(level, fmt::format(format, std::forward<Args>(args)...));
            }
        } catch (...) {
            // Silently ignore logging failures to prevent cascading errors
        }
    }
    
    template<typename... Args>
    static void debug(std::shared_ptr<Logger> logger, const std::string& format, Args&&... args) {
        logSafely(logger, LogLevel::DEBUG, format, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    static void info(std::shared_ptr<Logger> logger, const std::string& format, Args&&... args) {
        logSafely(logger, LogLevel::INFO, format, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    static void error(std::shared_ptr<Logger> logger, const std::string& format, Args&&... args) {
        logSafely(logger, LogLevel::ERROR, format, std::forward<Args>(args)...);
    }
};

// Logger factory for creating specialized loggers
class LoggerFactory {
public:
    static std::shared_ptr<Logger> createConsoleLogger(const std::string& name = "console");
    static std::shared_ptr<Logger> createFileLogger(const std::string& name, const std::string& file_path);
    static std::shared_ptr<Logger> createRotatingLogger(const std::string& name, const std::string& file_path, 
                                                       size_t max_size = 10*1024*1024, int max_files = 5);
    static std::shared_ptr<SecurityLogger> createSecurityLogger(std::shared_ptr<Logger> base_logger);
    static std::shared_ptr<PerformanceLogger> createPerformanceLogger(std::shared_ptr<Logger> base_logger);
};

} // namespace SSHVPN

#endif // LOGGER_H