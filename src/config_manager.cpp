#include "config_manager.h"
#include "utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <filesystem>

namespace SSHVPN {

ConfigManager::ConfigManager(const ConfigManagerOptions& options) 
    : options_(options), security_(SecurityConfig{}) {
    ensureDirectoriesExist();
    
    // Set default config file path
    config_file_path_ = resolvePath(options_.config_dir + "/" + DEFAULT_CONFIG_FILENAME);
}

bool ConfigManager::loadConfiguration(const std::string& filepath) {
    std::lock_guard<std::shared_mutex> lock(config_mutex_);
    
    try {
        if (!filepath.empty()) {
            validateAndSetConfigPath(filepath);
        }
        
        std::string content;
        if (!readConfigFile(content)) {
            logger_->warning("Configuration file not found, creating new configuration", "config");
            profiles_.clear();
            return saveConfiguration();
        }
        
        // Parse JSON
        nlohmann::json json_config;
        try {
            json_config = nlohmann::json::parse(content);
        } catch (const nlohmann::json::parse_error& e) {
            throw ConfigException("Invalid JSON format: " + std::string(e.what()));
        }
        
        // Validate against schema
        if (!validateAgainstSchema(json_config)) {
            throw ConfigException("Configuration does not match required schema");
        }
        
        // Parse configuration
        if (!parseConfiguration(json_config)) {
            throw ConfigException("Failed to parse configuration");
        }
        
        // Verify file security
        if (!verifyConfigFileSecurity(config_file_path_)) {
            logger_->warning("Configuration file has insecure permissions", "config");
            secureConfigFile(config_file_path_);
        }
        
        logger_->info("Configuration loaded successfully: " + config_file_path_.string(), "config");
        return true;
        
    } catch (const std::exception& e) {
        logger_->error("Failed to load configuration: " + std::string(e.what()), "config");
        profiles_.clear();
        return false;
    }
}

bool ConfigManager::saveConfiguration(const std::string& filepath) {
    std::lock_guard<std::shared_mutex> lock(config_mutex_);
    
    try {
        if (!filepath.empty()) {
            validateAndSetConfigPath(filepath);
        }
        
        // Ensure directory exists
        if (!ensureDirectoriesExist()) {
            throw ConfigException("Failed to create configuration directory");
        }
        
        // Serialize configuration
        nlohmann::json json_config = serializeConfiguration();
        
        // Validate before saving
        if (!validateAgainstSchema(json_config)) {
            throw ConfigException("Generated configuration does not match schema");
        }
        
        // Create backup if enabled
        if (options_.backup_on_save) {
            createBackup(config_file_path_.string());
        }
        
        // Write to file
        std::string content = json_config.dump(2);
        if (!writeConfigFile(content)) {
            throw ConfigException("Failed to write configuration file");
        }
        
        // Secure file permissions
        secureConfigFile(config_file_path_);
        
        logger_->info("Configuration saved successfully: " + config_file_path_.string(), "config");
        return true;
        
    } catch (const std::exception& e) {
        logger_->error("Failed to save configuration: " + std::string(e.what()), "config");
        return false;
    }
}

bool ConfigManager::backupConfiguration() {
    std::lock_guard<std::shared_mutex> lock(config_mutex_);
    
    try {
        return createBackup(config_file_path_.string());
    } catch (const std::exception& e) {
        logger_->error("Failed to create backup: " + std::string(e.what()), "config");
        return false;
    }
}

bool ConfigManager::restoreConfiguration(const std::string& backup_path) {
    std::lock_guard<std::shared_mutex> lock(config_mutex_);
    
    try {
        std::filesystem::path backup_file = resolvePath(backup_path);
        if (!ProcessUtils::fileExists(backup_file.string())) {
            throw ConfigException("Backup file not found: " + backup_path);
        }
        
        // Create backup of current configuration
        createBackup(config_file_path_.string());
        
        // Restore from backup
        std::string content;
        std::ifstream backup_file_stream(backup_file);
        if (!backup_file_stream.is_open()) {
            throw ConfigException("Failed to open backup file: " + backup_path);
        }
        
        std::stringstream buffer;
        buffer << backup_file_stream.rdbuf();
        content = buffer.str();
        backup_file_stream.close();
        
        // Parse and validate backup
        nlohmann::json json_config = nlohmann::json::parse(content);
        if (!validateAgainstSchema(json_config)) {
            throw ConfigException("Backup configuration is invalid");
        }
        
        // Parse backup configuration
        profiles_.clear();
        if (!parseConfiguration(json_config)) {
            throw ConfigException("Failed to parse backup configuration");
        }
        
        // Save restored configuration
        return saveConfiguration();
        
    } catch (const std::exception& e) {
        logger_->error("Failed to restore configuration: " + std::string(e.what()), "config");
        return false;
    }
}

bool ConfigManager::addProfile(const SSHProfile& profile) {
    std::lock_guard<std::shared_mutex> lock(config_mutex_);
    
    try {
        // Validate profile
        auto validation_errors = validateProfile(profile);
        if (!validation_errors.empty()) {
            std::string error_msg = "Profile validation failed:\n";
            for (const auto& error : validation_errors) {
                error_msg += "  - " + error + "\n";
            }
            throw ValidationException("profile", profile.name, error_msg);
        }
        
        // Check if profile already exists
        if (profiles_.find(profile.name) != profiles_.end()) {
            throw ConfigException("Profile '" + profile.name + "' already exists");
        }
        
        // Add profile
        profiles_[profile.name] = profile;
        
        logger_->info("Profile added: " + profile.name, "config");
        return true;
        
    } catch (const std::exception& e) {
        logger_->error("Failed to add profile: " + std::string(e.what()), "config");
        return false;
    }
}

bool ConfigManager::removeProfile(const std::string& profile_name) {
    std::lock_guard<std::shared_mutex> lock(config_mutex_);
    
    try {
        auto it = profiles_.find(profile_name);
        if (it == profiles_.end()) {
            throw ConfigException("Profile '" + profile_name + "' not found");
        }
        
        profiles_.erase(it);
        logger_->info("Profile removed: " + profile_name, "config");
        return true;
        
    } catch (const std::exception& e) {
        logger_->error("Failed to remove profile: " + std::string(e.what()), "config");
        return false;
    }
}

bool ConfigManager::updateProfile(const std::string& profile_name, const SSHProfile& updated_profile) {
    std::lock_guard<std::shared_mutex> lock(config_mutex_);
    
    try {
        // Check if profile exists
        if (profiles_.find(profile_name) == profiles_.end()) {
            throw ConfigException("Profile '" + profile_name + "' not found");
        }
        
        // Validate updated profile
        auto validation_errors = validateProfile(updated_profile);
        if (!validation_errors.empty()) {
            std::string error_msg = "Updated profile validation failed:\n";
            for (const auto& error : validation_errors) {
                error_msg += "  - " + error + "\n";
            }
            throw ValidationException("profile", updated_profile.name, error_msg);
        }
        
        // Update profile
        profiles_[profile_name] = updated_profile;
        
        logger_->info("Profile updated: " + profile_name, "config");
        return true;
        
    } catch (const std::exception& e) {
        logger_->error("Failed to update profile: " + std::string(e.what()), "config");
        return false;
    }
}

std::optional<SSHProfile> ConfigManager::getProfile(const std::string& profile_name) const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    
    auto it = profiles_.find(profile_name);
    if (it != profiles_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<SSHProfile> ConfigManager::getAllProfiles() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    
    std::vector<SSHProfile> profile_list;
    for (const auto& [name, profile] : profiles_) {
        profile_list.push_back(profile);
    }
    return profile_list;
}

bool ConfigManager::profileExists(const std::string& profile_name) const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return profiles_.find(profile_name) != profiles_.end();
}

std::vector<std::string> ConfigManager::validateConfiguration() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    
    std::vector<std::string> errors;
    
    for (const auto& [name, profile] : profiles_) {
        auto profile_errors = validateProfile(profile);
        errors.insert(errors.end(), profile_errors.begin(), profile_errors.end());
    }
    
    return errors;
}

bool ConfigManager::isConfigurationValid() const {
    return validateConfiguration().empty();
}

std::vector<std::string> ConfigManager::validateProfile(const SSHProfile& profile) const {
    std::vector<std::string> errors;
    
    // Validate required fields
    if (profile.name.empty()) {
        errors.push_back("Profile name cannot be empty");
    }
    
    if (profile.host.empty()) {
        errors.push_back("Host cannot be empty");
    }
    
    if (profile.user.empty()) {
        errors.push_back("User cannot be empty");
    }
    
    // Validate field formats
    if (!profile.name.empty() && !isValidProfileName(profile.name)) {
        errors.push_back("Invalid profile name format");
    }
    
    if (!profile.host.empty() && !isValidHost(profile.host)) {
        errors.push_back("Invalid host format");
    }
    
    if (!profile.port.empty() && !isValidPort(profile.port)) {
        errors.push_back("Invalid port format");
    }
    
    if (!profile.local_port.empty() && !isValidPort(profile.local_port)) {
        errors.push_back("Invalid local port format");
    }
    
    if (!profile.user.empty() && !isValidUser(profile.user)) {
        errors.push_back("Invalid username format");
    }
    
    // Validate optional fields
    if (profile.identity_file.has_value() && !isValidFilePath(profile.identity_file.value())) {
        errors.push_back("Invalid identity file path");
    }
    
    if (profile.prefix.has_value() && profile.prefix.value().length() > 1024) {
        errors.push_back("SSH prefix too long (max 1024 characters)");
    }
    
    return errors;
}

nlohmann::json ConfigManager::getConfigurationSchema() {
    nlohmann::json schema;
    
    schema["type"] = "array";
    schema["items"]["type"] = "object";
    schema["items"]["required"] = nlohmann::json::array({"name", "host", "user", "port", "local_port"});
    
    // Define field schemas
    schema["items"]["properties"]["name"]["type"] = "string";
    schema["items"]["properties"]["name"]["pattern"] = "^[a-zA-Z0-9_-]+$";
    schema["items"]["properties"]["name"]["maxLength"] = 50;
    
    schema["items"]["properties"]["host"]["type"] = "string";
    schema["items"]["properties"]["host"]["maxLength"] = 255;
    
    schema["items"]["properties"]["user"]["type"] = "string";
    schema["items"]["properties"]["user"]["maxLength"] = 32;
    
    schema["items"]["properties"]["port"]["type"] = "string";
    schema["items"]["properties"]["port"]["pattern"] = "^[1-9][0-9]{0,4}$";
    
    schema["items"]["properties"]["local_port"]["type"] = "string";
    schema["items"]["properties"]["local_port"]["pattern"] = "^[1-9][0-9]{0,4}$";
    
    schema["items"]["properties"]["identity_file"]["type"] = "string";
    schema["items"]["properties"]["identity_file"]["maxLength"] = 1024;
    
    schema["items"]["properties"]["prefix"]["type"] = "string";
    schema["items"]["properties"]["prefix"]["maxLength"] = 1024;
    
    schema["items"]["properties"]["password"]["type"] = "string";
    schema["items"]["properties"]["password"]["maxLength"] = 512;
    
    schema["items"]["properties"]["timeout"]["type"] = "integer";
    schema["items"]["properties"]["timeout"]["minimum"] = 1;
    schema["items"]["properties"]["timeout"]["maximum"] = 300;
    
    schema["items"]["properties"]["auto_reconnect"]["type"] = "boolean";
    
    schema["items"]["properties"]["reconnect_attempts"]["type"] = "integer";
    schema["items"]["properties"]["reconnect_attempts"]["minimum"] = 0;
    schema["items"]["properties"]["reconnect_attempts"]["maximum"] = 100;
    
    schema["items"]["properties"]["reconnect_delay"]["type"] = "integer";
    schema["items"]["properties"]["reconnect_delay"]["minimum"] = 1;
    schema["items"]["properties"]["reconnect_delay"]["maximum"] = 300;
    
    return schema;
}

bool ConfigManager::validateAgainstSchema(const nlohmann::json& config) const {
    try {
        auto schema = getConfigurationSchema();
        
        // Basic type validation
        if (!config.is_array()) {
            return false;
        }
        
        // Validate each item
        for (const auto& item : config) {
            if (!item.is_object()) {
                return false;
            }
            
            // Check required fields
            std::vector<std::string> required_fields = {"name", "host", "user", "port", "local_port"};
            for (const auto& field : required_fields) {
                if (!item.contains(field) || !item[field].is_string()) {
                    return false;
                }
            }
            
            // Validate field patterns and constraints
            std::string name = item["name"].get<std::string>();
            if (!isValidProfileName(name)) {
                return false;
            }
            
            std::string port = item["port"].get<std::string>();
            if (!isValidPort(port)) {
                return false;
            }
            
            std::string local_port = item["local_port"].get<std::string>();
            if (!isValidPort(local_port)) {
                return false;
            }
            
            // Validate optional fields if present
            if (item.contains("identity_file") && !item["identity_file"].is_null()) {
                if (!item["identity_file"].is_string()) {
                    return false;
                }
                std::string identity_file = item["identity_file"].get<std::string>();
                if (!isValidFilePath(identity_file)) {
                    return false;
                }
            }
            
            if (item.contains("prefix") && !item["prefix"].is_null()) {
                if (!item["prefix"].is_string()) {
                    return false;
                }
                std::string prefix = item["prefix"].get<std::string>();
                if (prefix.length() > 1024) {
                    return false;
                }
            }
        }
        
        return true;
        
    } catch (const std::exception&) {
        return false;
    }
}

std::string ConfigManager::getConfigFilePath() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return config_file_path_.string();
}

std::string ConfigManager::getLogFilePath() const {
    std::string log_dir = resolvePath(options_.log_dir).string();
    return log_dir + "/sshvpn.log";
}

std::string ConfigManager::getPidFilePath(const std::string& profile_name) const {
    std::string pid_dir = resolvePath(options_.pid_dir).string();
    return pid_dir + "/" + profile_name + ".pid";
}

std::vector<std::string> ConfigManager::listBackupFiles() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return getBackupFilePaths();
}

bool ConfigManager::ensureDirectoriesExist() const {
    try {
        std::filesystem::path config_dir = resolvePath(options_.config_dir);
        std::filesystem::path log_dir = resolvePath(options_.log_dir);
        std::filesystem::path pid_dir = resolvePath(options_.pid_dir);
        
        if (options_.create_directories) {
            std::filesystem::create_directories(config_dir);
            std::filesystem::create_directories(log_dir);
            std::filesystem::create_directories(pid_dir);
        }
        
        return std::filesystem::exists(config_dir) && 
               std::filesystem::exists(log_dir) && 
               std::filesystem::exists(pid_dir);
               
    } catch (const std::exception&) {
        return false;
    }
}

nlohmann::json ConfigManager::exportToJSON() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return serializeConfiguration();
}

bool ConfigManager::importFromJSON(const nlohmann::json& json_config) {
    std::lock_guard<std::shared_mutex> lock(config_mutex_);
    
    try {
        if (!validateAgainstSchema(json_config)) {
            throw ConfigException("Invalid JSON configuration format");
        }
        
        profiles_.clear();
        return parseConfiguration(json_config);
        
    } catch (const std::exception& e) {
        logger_->error("Failed to import JSON configuration: " + std::string(e.what()), "config");
        return false;
    }
}

std::string ConfigManager::exportToJSONString() const {
    auto json = exportToJSON();
    return json.dump(2);
}

bool ConfigManager::importFromJSONString(const std::string& json_string) {
    try {
        auto json_config = nlohmann::json::parse(json_string);
        return importFromJSON(json_config);
    } catch (const std::exception& e) {
        logger_->error("Failed to parse JSON string: " + std::string(e.what()), "config");
        return false;
    }
}

SSHProfile ConfigManager::getDefaultProfile() {
    SSHProfile profile;
    profile.name = "default";
    profile.host = "example.com";
    profile.user = "user";
    profile.port = "22";
    profile.local_port = "1080";
    return profile;
}

std::vector<SSHProfile> ConfigManager::getDefaultProfiles() {
    std::vector<SSHProfile> defaults;
    defaults.push_back(getDefaultProfile());
    return defaults;
}

bool ConfigManager::createConfigurationFromTemplate(const std::string& template_name) {
    std::lock_guard<std::shared_mutex> lock(config_mutex_);
    
    try {
        std::vector<SSHProfile> templates;
        
        if (template_name == "basic") {
            templates = getDefaultProfiles();
        } else if (template_name == "development") {
            SSHProfile dev_profile = getDefaultProfile();
            dev_profile.name = "dev-server";
            dev_profile.host = "dev.example.com";
            dev_profile.auto_reconnect = true;
            dev_profile.reconnect_attempts = 5;
            dev_profile.reconnect_delay = 3;
            templates.push_back(dev_profile);
        } else if (template_name == "production") {
            SSHProfile prod_profile = getDefaultProfile();
            prod_profile.name = "prod-server";
            prod_profile.host = "prod.example.com";
            prod_profile.identity_file = "~/.ssh/id_rsa";
            prod_profile.auto_reconnect = true;
            prod_profile.reconnect_attempts = 10;
            prod_profile.reconnect_delay = 5;
            templates.push_back(prod_profile);
        } else {
            throw ConfigException("Unknown template: " + template_name);
        }
        
        // Add templates to profiles
        for (const auto& template_profile : templates) {
            profiles_[template_profile.name] = template_profile;
        }
        
        return saveConfiguration();
        
    } catch (const std::exception& e) {
        logger_->error("Failed to create configuration from template: " + std::string(e.what()), "config");
        return false;
    }
}

bool ConfigManager::isValidProfileName(const std::string& name) {
    if (name.empty() || name.length() > 50) {
        return false;
    }
    
    // Check for valid characters (alphanumeric, underscore, hyphen)
    for (char c : name) {
        if (!std::isalnum(c) && c != '_' && c != '-') {
            return false;
        }
    }
    
    return true;
}

bool ConfigManager::isValidHost(const std::string& host) {
    if (host.empty() || host.length() > 255) {
        return false;
    }
    
    // Check for valid hostname/IP characters
    for (char c : host) {
        if (!std::isalnum(c) && c != '-' && c != '.' && c != ':') {
            return false;
        }
    }
    
    return true;
}

bool ConfigManager::isValidPort(const std::string& port) {
    try {
        int port_num = std::stoi(port);
        return isValidPort(port_num);
    } catch (const std::exception&) {
        return false;
    }
}

bool ConfigManager::isValidPort(int port) {
    return port >= 1 && port <= 65535;
}

bool ConfigManager::isValidUser(const std::string& user) {
    if (user.empty() || user.length() > 32) {
        return false;
    }
    
    // Check for valid username characters
    for (char c : user) {
        if (!std::isalnum(c) && c != '_' && c != '-' && c != '.') {
            return false;
        }
    }
    
    return true;
}

bool ConfigManager::isValidFilePath(const std::string& path) {
    if (path.empty() || path.length() > 1024) {
        return false;
    }
    
    // Check for path traversal
    if (path.find("..") != std::string::npos) {
        return false;
    }
    
    return true;
}

void ConfigManager::setOptions(const ConfigManagerOptions& options) {
    std::lock_guard<std::shared_mutex> lock(config_mutex_);
    options_ = options;
}

bool ConfigManager::parseConfiguration(const nlohmann::json& json_config) {
    try {
        profiles_.clear();
        
        for (const auto& item : json_config) {
            SSHProfile profile;
            
            // Parse required fields
            profile.name = item["name"].get<std::string>();
            profile.host = item["host"].get<std::string>();
            profile.user = item["user"].get<std::string>();
            profile.port = item["port"].get<std::string>();
            profile.local_port = item["local_port"].get<std::string>();
            
            // Parse optional fields
            if (item.contains("identity_file") && !item["identity_file"].is_null()) {
                profile.identity_file = item["identity_file"].get<std::string>();
            }
            
            if (item.contains("prefix") && !item["prefix"].is_null()) {
                profile.prefix = item["prefix"].get<std::string>();
            }
            
            if (item.contains("password") && !item["password"].is_null()) {
                profile.password = item["password"].get<std::string>();
            }
            
            if (item.contains("timeout") && !item["timeout"].is_null()) {
                profile.timeout = item["timeout"].get<int>();
            }
            
            if (item.contains("auto_reconnect") && !item["auto_reconnect"].is_null()) {
                profile.auto_reconnect = item["auto_reconnect"].get<bool>();
            }
            
            if (item.contains("reconnect_attempts") && !item["reconnect_attempts"].is_null()) {
                profile.reconnect_attempts = item["reconnect_attempts"].get<int>();
            }
            
            if (item.contains("reconnect_delay") && !item["reconnect_delay"].is_null()) {
                profile.reconnect_delay = item["reconnect_delay"].get<int>();
            }
            
            profiles_[profile.name] = profile;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        logger_->error("Failed to parse configuration: " + std::string(e.what()), "config");
        return false;
    }
}

nlohmann::json ConfigManager::serializeConfiguration() const {
    nlohmann::json json_config = nlohmann::json::array();
    
    for (const auto& [name, profile] : profiles_) {
        nlohmann::json item;
        item["name"] = profile.name;
        item["host"] = profile.host;
        item["user"] = profile.user;
        item["port"] = profile.port;
        item["local_port"] = profile.local_port;
        
        // Add optional fields if present
        if (profile.identity_file.has_value()) {
            item["identity_file"] = profile.identity_file.value();
        }
        
        if (profile.prefix.has_value()) {
            item["prefix"] = profile.prefix.value();
        }
        
        if (profile.password.has_value()) {
            item["password"] = profile.password.value();
        }
        
        if (profile.timeout.has_value()) {
            item["timeout"] = profile.timeout.value();
        }
        
        if (profile.auto_reconnect.has_value()) {
            item["auto_reconnect"] = profile.auto_reconnect.value();
        }
        
        if (profile.reconnect_attempts.has_value()) {
            item["reconnect_attempts"] = profile.reconnect_attempts.value();
        }
        
        if (profile.reconnect_delay.has_value()) {
            item["reconnect_delay"] = profile.reconnect_delay.value();
        }
        
        json_config.push_back(item);
    }
    
    return json_config;
}

void ConfigManager::validateAndSetConfigPath(const std::string& filepath) {
    config_file_path_ = resolvePath(filepath);
    
    // Validate directory exists or can be created
    std::string dir = config_file_path_.parent_path().string();
    if (!ProcessUtils::directoryExists(dir) && options_.create_directories) {
        std::filesystem::create_directories(dir);
    }
}

std::filesystem::path ConfigManager::resolvePath(const std::string& path) const {
    std::filesystem::path result(path);
    
    // Expand tilde
    if (!result.empty() && result.string().find('~') == 0) {
        std::string home = ProcessUtils::getHomeDirectory();
        result = result.string().substr(1);
        result = home / result;
    }
    
    // Make absolute
    if (result.is_relative()) {
        result = std::filesystem::absolute(result);
    }
    
    return result;
}

bool ConfigManager::readConfigFile(std::string& content) const {
    try {
        std::ifstream file(config_file_path_);
        if (!file.is_open()) {
            return false;
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        content = buffer.str();
        file.close();
        
        return true;
        
    } catch (const std::exception&) {
        return false;
    }
}

bool ConfigManager::writeConfigFile(const std::string& content) const {
    try {
        std::ofstream file(config_file_path_);
        if (!file.is_open()) {
            return false;
        }
        
        file << content;
        file.close();
        
        return true;
        
    } catch (const std::exception&) {
        return false;
    }
}

bool ConfigManager::createBackup(const std::string& config_path) const {
    try {
        std::filesystem::path source_path(config_path);
        std::string timestamp = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        std::string backup_name = source_path.stem().string() + "_" + timestamp + BACKUP_SUFFIX;
        std::filesystem::path backup_path = source_path.parent_path() / backup_name;
        
        std::filesystem::copy_file(source_path, backup_path, std::filesystem::copy_options::overwrite_existing);
        
        // Clean up old backups
        auto backup_files = getBackupFilePaths();
        if (backup_files.size() > MAX_BACKUP_FILES) {
            std::sort(backup_files.begin(), backup_files.end());
            for (size_t i = 0; i < backup_files.size() - MAX_BACKUP_FILES; ++i) {
                std::filesystem::remove(backup_files[i]);
            }
        }
        
        return true;
        
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<std::string> ConfigManager::getBackupFilePaths() const {
    std::vector<std::string> backup_files;
    
    try {
        std::filesystem::path config_dir = config_file_path_.parent_path();
        std::string stem = config_file_path_.stem().string();
        
        for (const auto& entry : std::filesystem::directory_iterator(config_dir)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                if (filename.find(stem) == 0 && filename.find(BACKUP_SUFFIX) != std::string::npos) {
                    backup_files.push_back(entry.path().string());
                }
            }
        }
        
        std::sort(backup_files.begin(), backup_files.end());
        
    } catch (const std::exception&) {
        // Ignore errors
    }
    
    return backup_files;
}

bool ConfigManager::verifyConfigFileSecurity(const std::filesystem::path& path) const {
    try {
        int permissions = ProcessUtils::getFilePermissions(path.string());
        // Check if file is readable by others (permissions > 644)
        return (permissions & 077) == 0; // Only owner has write access
    } catch (const std::exception&) {
        return false;
    }
}

bool ConfigManager::secureConfigFile(const std::filesystem::path& path) const {
    try {
        return ProcessUtils::setFilePermissions(path.string(), 0600); // Read/write for owner only
    } catch (const std::exception&) {
        return false;
    }
}

bool SSHProfile::isValid() const {
    return !name.empty() && !host.empty() && !user.empty() && 
           !port.empty() && !local_port.empty();
}

std::vector<std::string> SSHProfile::validate() const {
    std::vector<std::string> errors;
    
    if (name.empty()) {
        errors.push_back("Name cannot be empty");
    }
    
    if (host.empty()) {
        errors.push_back("Host cannot be empty");
    }
    
    if (user.empty()) {
        errors.push_back("User cannot be empty");
    }
    
    if (port.empty()) {
        errors.push_back("Port cannot be empty");
    }
    
    if (local_port.empty()) {
        errors.push_back("Local port cannot be empty");
    }
    
    return errors;
}

} // namespace SSHVPN