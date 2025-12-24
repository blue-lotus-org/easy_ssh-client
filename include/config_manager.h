#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include "types.h"
#include "security.h"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <optional>

namespace SSHVPN {

class ConfigManager {
public:
    explicit ConfigManager(const ConfigManagerOptions& options = ConfigManagerOptions{});
    ~ConfigManager() = default;
    
    // Delete copy constructor and assignment operator
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    
    // Configuration file operations
    bool loadConfiguration(const std::string& filepath = "");
    bool saveConfiguration(const std::string& filepath = "");
    bool backupConfiguration();
    bool restoreConfiguration(const std::string& backup_path);
    
    // Profile management
    bool addProfile(const SSHProfile& profile);
    bool removeProfile(const std::string& profile_name);
    bool updateProfile(const std::string& profile_name, const SSHProfile& updated_profile);
    std::optional<SSHProfile> getProfile(const std::string& profile_name) const;
    std::vector<SSHProfile> getAllProfiles() const;
    bool profileExists(const std::string& profile_name) const;
    
    // Validation
    std::vector<std::string> validateConfiguration() const;
    bool isConfigurationValid() const;
    std::vector<std::string> validateProfile(const SSHProfile& profile) const;
    
    // Interactive profile creation
    SSHProfile createProfileInteractive();
    SSHProfile createProfileFromArgs(const std::map<std::string, std::string>& args);
    
    // Configuration validation and schema
    static nlohmann::json getConfigurationSchema();
    bool validateAgainstSchema(const nlohmann::json& config) const;
    
    // File system operations
    bool ensureDirectoriesExist() const;
    std::string getConfigFilePath() const;
    std::string getLogFilePath() const;
    std::string getPidFilePath(const std::string& profile_name) const;
    std::vector<std::string> listBackupFiles() const;
    
    // Configuration options
    ConfigManagerOptions getOptions() const { return options_; }
    void setOptions(const ConfigManagerOptions& options);
    
    // Thread safety
    void lock() const { config_mutex_.lock(); }
    void unlock() const { config_mutex_.unlock(); }
    bool tryLock() const { return config_mutex_.try_lock(); }
    void lockShared() const { config_mutex_.lock_shared(); }
    void unlockShared() const { config_mutex_.unlock_shared(); }
    
    // JSON operations
    nlohmann::json exportToJSON() const;
    bool importFromJSON(const nlohmann::json& json_config);
    std::string exportToJSONString() const;
    bool importFromJSONString(const std::string& json_string);
    
    // Configuration templates
    static SSHProfile getDefaultProfile();
    static std::vector<SSHProfile> getDefaultProfiles();
    bool createConfigurationFromTemplate(const std::string& template_name);
    
    // Profile validation helpers
    static bool isValidProfileName(const std::string& name);
    static bool isValidHost(const std::string& host);
    static bool isValidPort(const std::string& port);
    static bool isValidPort(int port);
    static bool isValidUser(const std::string& user);
    static bool isValidFilePath(const std::string& path);
    
    // Configuration migration and upgrade
    bool migrateConfiguration(const std::string& old_config_path);
    nlohmann::json upgradeConfiguration(const nlohmann::json& old_config);
    
    // Error handling
    class ConfigException : public std::runtime_error {
    public:
        explicit ConfigException(const std::string& message) 
            : std::runtime_error("Configuration error: " + message) {}
    };
    
    class FileException : public ConfigException {
    public:
        explicit FileException(const std::string& filepath, const std::string& reason)
            : ConfigException("File operation failed for '" + filepath + "': " + reason) {}
    };
    
    class ValidationException : public ConfigException {
    public:
        explicit ValidationException(const std::string& field, const std::string& value, const std::string& reason)
            : ConfigException("Validation failed for field '" + field + "' with value '" + value + "': " + reason) {}
    };
    
private:
    ConfigManagerOptions options_;
    mutable std::shared_mutex config_mutex_;
    std::filesystem::path config_file_path_;
    ProfileMap profiles_;
    SecurityManager security_;
    
    // Internal helpers
    bool parseConfiguration(const nlohmann::json& json_config);
    nlohmann::json serializeConfiguration() const;
    void validateAndSetConfigPath(const std::string& filepath);
    std::filesystem::path resolvePath(const std::string& path) const;
    
    // File operations
    bool readConfigFile(std::string& content) const;
    bool writeConfigFile(const std::string& content) const;
    bool createBackup(const std::string& config_path) const;
    std::vector<std::string> getBackupFilePaths() const;
    
    // Validation helpers
    std::vector<std::string> validateHost(const std::string& host) const;
    std::vector<std::string> validatePort(const std::string& port) const;
    std::vector<std::string> validateUser(const std::string& user) const;
    std::vector<std::string> validateFilePath(const std::string& path) const;
    
    // Schema validation
    bool validateSchemaField(const nlohmann::json& field, const std::string& field_name, 
                           const nlohmann::json& schema) const;
    std::vector<std::string> getSchemaValidationErrors(const nlohmann::json& config) const;
    
    // Security checks
    bool verifyConfigFileSecurity(const std::filesystem::path& path) const;
    bool secureConfigFile(const std::filesystem::path& path) const;
    
    // Configuration migration
    bool migrateFromLegacyFormat(const std::string& old_config);
    nlohmann::json transformLegacyConfig(const nlohmann::json& legacy_config) const;
    
    // Constants
    static constexpr const char* DEFAULT_CONFIG_FILENAME = "config.json";
    static constexpr const char* BACKUP_SUFFIX = ".backup";
    static constexpr int MAX_BACKUP_FILES = 10;
    static constexpr size_t MAX_CONFIG_SIZE = 1024 * 1024; // 1MB
};

// Configuration validation utilities
namespace ConfigValidation {
    // Profile validation
    bool isValidProfile(const SSHProfile& profile, std::vector<std::string>& errors);
    bool isValidProfileName(const std::string& name);
    bool isValidSSHConfig(const nlohmann::json& config);
    
    // Host validation
    bool isValidHostname(const std::string& hostname);
    bool isValidIPAddress(const std::string& ip);
    bool isValidHost(const std::string& host);
    
    // Port validation
    bool isValidPortNumber(int port);
    bool isValidPortString(const std::string& port);
    
    // Path validation
    bool isValidConfigPath(const std::string& path);
    bool isValidKeyFilePath(const std::string& path);
    bool pathExists(const std::string& path);
    
    // String validation
    bool isValidUsername(const std::string& username);
    bool isValidProfileDescription(const std::string& description);
}

} // namespace SSHVPN

#endif // CONFIG_MANAGER_H