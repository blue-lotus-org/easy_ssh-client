#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <signal.h>
#include <unistd.h>

#include "config_manager.h"
#include "ssh_client.h"
#include "connection_manager.h"
#include "logger.h"
#include "security.h"
#include "utils.h"
#include "types.h"

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

using namespace SSHVPN;

class SSHVPNApplication {
public:
    SSHVPNApplication();
    ~SSHVPNApplication() = default;
    
    int run(int argc, char* argv[]);
    
private:
    CLIOptions options_;
    std::shared_ptr<Logger> logger_;
    std::shared_ptr<ConfigManager> config_manager_;
    std::shared_ptr<ConnectionManager> connection_manager_;
    std::shared_ptr<SecurityManager> security_manager_;
    
    // Signal handling
    static void signalHandler(int signum);
    static std::atomic<bool> shutdown_requested_;
    
    // Setup and initialization
    bool initialize(const CLIOptions& options);
    void setupSignalHandlers();
    void setupLogging();
    void setupComponents();
    
    // CLI command handlers
    int handleHelpCommand();
    int handleVersionCommand();
    int handleListCommand();
    int handleAddCommand(const std::vector<std::string>& args);
    int handleRemoveCommand(const std::string& profile_name);
    int handleStartCommand(const std::string& profile_name);
    int handleStopCommand(const std::string& profile_name);
    int handleRestartCommand(const std::string& profile_name);
    int handleStatusCommand();
    int handleLogsCommand();
    int handleTestCommand(const std::string& profile_name);
    int handleConfigCommand();
    
    // Utility methods
    void printUsage();
    void printHelp();
    void printVersion();
    void printProfiles();
    void printStatus();
    void printLogs();
    void printConfig();
    
    // Interactive methods
    SSHProfile createProfileInteractive();
    bool confirmAction(const std::string& message);
    
    // Error handling
    void handleError(const std::string& error, int exit_code = 1);
    void logCommandExecution(const std::string& command, const std::vector<std::string>& args);
    
    // Configuration validation
    bool validateOptions(const CLIOptions& options);
    bool checkDependencies();
    
    // Cleanup
    void cleanup();
};

// Static signal handler initialization
std::atomic<bool> SSHVPNApplication::shutdown_requested_{false};

SSHVPNApplication::SSHVPNApplication() {
    // Set up default logger
    logger_ = LoggerFactory::createRotatingLogger("sshvpn", 
        ProcessUtils::getHomeDirectory() + "/.cache/sshvpn/sshvpn.log",
        10 * 1024 * 1024, 5); // 10MB, 5 files
}

void SSHVPNApplication::signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ". Shutting down gracefully..." << std::endl;
    shutdown_requested_ = true;
    
    // Perform cleanup
    if (signum == SIGTERM || signum == SIGINT) {
        _exit(0);
    }
}

void SSHVPNApplication::setupSignalHandlers() {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGHUP, signalHandler);
}

bool SSHVPNApplication::initialize(const CLIOptions& options) {
    options_ = options;
    
    // Validate options
    if (!validateOptions(options)) {
        return false;
    }
    
    // Setup signal handlers
    setupSignalHandlers();
    
    // Setup logging
    setupLogging();
    
    // Check system dependencies
    if (!checkDependencies()) {
        return false;
    }
    
    // Setup components
    setupComponents();
    
    return true;
}

void SSHVPNApplication::setupLogging() {
    // Configure spdlog
    spdlog::set_level(spdlog::level::info);
    
    if (options_.verbose) {
        spdlog::set_level(spdlog::level::debug);
        logger_->setLogLevel(LogLevel::DEBUG);
    } else if (options_.quiet) {
        logger_->setLogLevel(LogLevel::WARNING);
    }
    
    // Set log file if specified
    if (!options_.log_file.empty()) {
        logger_->setLogFile(options_.log_file);
    }
    
    logger_->info("SSH VPN Client initialized", "main");
}

void SSHVPNApplication::setupComponents() {
    try {
        // Setup configuration manager
        ConfigManagerOptions config_options;
        if (!options_.config_file.empty()) {
            config_options.config_dir = ProcessUtils::getAbsolutePath(ProcessUtils::getDirectoryName(options_.config_file));
        }
        
        config_manager_ = std::make_shared<ConfigManager>(config_options);
        
        // Setup security manager
        SecurityConfig security_config;
        security_config.validate_inputs = true;
        security_config.sanitize_commands = true;
        security_config.check_file_permissions = true;
        security_config.restrict_file_access = true;
        security_config.disable_core_dumps = true;
        security_config.secure_memory_clear = true;
        
        security_manager_ = std::make_shared<SecurityManager>(security_config);
        
        // Setup connection manager
        connection_manager_ = std::make_shared<ConnectionManager>(config_manager_, logger_);
        
        // Load configuration
        if (!options_.config_file.empty()) {
            if (!config_manager_->loadConfiguration(options_.config_file)) {
                logger_->error("Failed to load configuration from: " + options_.config_file, "main");
            }
        } else {
            if (!config_manager_->loadConfiguration()) {
                logger_->info("No existing configuration found, creating new one", "main");
                config_manager_->ensureDirectoriesExist();
            }
        }
        
        logger_->info("All components initialized successfully", "main");
        
    } catch (const std::exception& e) {
        logger_->error("Failed to initialize components: " + std::string(e.what()), "main");
        throw;
    }
}

bool SSHVPNApplication::checkDependencies() {
    // Check for required system commands
    std::vector<std::string> required_commands = {"ssh", "sh"};
    
    for (const auto& cmd : required_commands) {
        if (!ProcessUtils::commandExists(cmd)) {
            std::cerr << "Error: Required command '" << cmd << "' not found in PATH" << std::endl;
            return false;
        }
    }
    
    // Check for optional SSH libraries
    #ifdef USE_LIBSSH
    logger_->info("Using libssh for SSH connections", "main");
    #else
    logger_->info("Using system ssh command for connections", "main");
    #endif
    
    return true;
}

int SSHVPNApplication::run(int argc, char* argv[]) {
    try {
        CLI::App app{"Secure SSH VPN Client - A robust and secure SSH tunnel manager"};
        
        // Global options
        app.add_option("--config,-c", options_.config_file, "Configuration file path");
        app.add_option("--log-file", options_.log_file, "Log file path");
        app.add_flag("--verbose,-v", options_.verbose, "Enable verbose logging");
        app.add_flag("--quiet,-q", options_.quiet, "Enable quiet mode (warnings and errors only)");
        app.add_flag("--daemon,-d", options_.daemon, "Run as daemon");
        app.add_flag("--version", options_.version, "Show version information");
        app.add_flag("--help", options_.help, "Show help information");
        
        // Subcommands
        CLI::App* help_cmd = app.add_subcommand("help", "Show help information");
        CLI::App* version_cmd = app.add_subcommand("version", "Show version information");
        CLI::App* list_cmd = app.add_subcommand("list", "List all profiles");
        CLI::App* add_cmd = app.add_subcommand("add", "Add a new profile");
        CLI::App* remove_cmd = app.add_subcommand("remove", "Remove a profile");
        CLI::App* start_cmd = app.add_subcommand("start", "Start a connection");
        CLI::App* stop_cmd = app.add_subcommand("stop", "Stop a connection");
        CLI::App* restart_cmd = app.add_subcommand("restart", "Restart a connection");
        CLI::App* status_cmd = app.add_subcommand("status", "Show connection status");
        CLI::App* logs_cmd = app.add_subcommand("logs", "Show recent logs");
        CLI::App* test_cmd = app.add_subcommand("test", "Test a connection");
        CLI::App* config_cmd = app.add_subcommand("config", "Show configuration");
        
        // Parse arguments
        try {
            app.parse(argc, argv);
        } catch (const CLI::ParseError &e) {
            std::cerr << "Parse error: " << e.what() << std::endl;
            printUsage();
            return 1;
        }
        
        // Handle global flags
        if (options_.help || app.got_subcommand("help")) {
            printHelp();
            return 0;
        }
        
        if (options_.version || app.got_subcommand("version")) {
            printVersion();
            return 0;
        }
        
        // Initialize application
        if (!initialize(options_)) {
            return 1;
        }
        
        // Handle daemon mode
        if (options_.daemon) {
            logger_->info("Running in daemon mode", "main");
            // TODO: Implement daemon functionality
        }
        
        // Handle subcommands
        if (app.got_subcommand("list")) {
            return handleListCommand();
        } else if (app.got_subcommand("add")) {
            std::vector<std::string> args;
            return handleAddCommand(args);
        } else if (app.got_subcommand("remove")) {
            std::string profile_name;
            remove_cmd->add_option("profile", profile_name, "Profile name to remove")->required();
            try {
                remove_cmd->parse(argc, argv);
                return handleRemoveCommand(profile_name);
            } catch (const CLI::ParseError &e) {
                std::cerr << "Parse error: " << e.what() << std::endl;
                return 1;
            }
        } else if (app.got_subcommand("start")) {
            std::string profile_name;
            start_cmd->add_option("profile", profile_name, "Profile name to start")->required();
            try {
                start_cmd->parse(argc, argv);
                return handleStartCommand(profile_name);
            } catch (const CLI::ParseError &e) {
                std::cerr << "Parse error: " << e.what() << std::endl;
                return 1;
            }
        } else if (app.got_subcommand("stop")) {
            std::string profile_name;
            stop_cmd->add_option("profile", profile_name, "Profile name to stop")->required();
            try {
                stop_cmd->parse(argc, argv);
                return handleStopCommand(profile_name);
            } catch (const CLI::ParseError &e) {
                std::cerr << "Parse error: " << e.what() << std::endl;
                return 1;
            }
        } else if (app.got_subcommand("restart")) {
            std::string profile_name;
            restart_cmd->add_option("profile", profile_name, "Profile name to restart")->required();
            try {
                restart_cmd->parse(argc, argv);
                return handleRestartCommand(profile_name);
            } catch (const CLI::ParseError &e) {
                std::cerr << "Parse error: " << e.what() << std::endl;
                return 1;
            }
        } else if (app.got_subcommand("status")) {
            return handleStatusCommand();
        } else if (app.got_subcommand("logs")) {
            return handleLogsCommand();
        } else if (app.got_subcommand("test")) {
            std::string profile_name;
            test_cmd->add_option("profile", profile_name, "Profile name to test")->required();
            try {
                test_cmd->parse(argc, argv);
                return handleTestCommand(profile_name);
            } catch (const CLI::ParseError &e) {
                std::cerr << "Parse error: " << e.what() << std::endl;
                return 1;
            }
        } else if (app.got_subcommand("config")) {
            return handleConfigCommand();
        } else {
            // No subcommand specified, show help
            printUsage();
            return 0;
        }
        
    } catch (const std::exception& e) {
        logger_->critical("Unhandled exception: " + std::string(e.what()), "main");
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

void SSHVPNApplication::printUsage() {
    std::cout << "Usage: sshvpn [OPTIONS] COMMAND [ARGUMENTS]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  help              Show this help message" << std::endl;
    std::cout << "  version           Show version information" << std::endl;
    std::cout << "  list              List all profiles" << std::endl;
    std::cout << "  add               Add a new profile" << std::endl;
    std::cout << "  remove <profile>  Remove a profile" << std::endl;
    std::cout << "  start <profile>   Start a connection" << std::endl;
    std::cout << "  stop <profile>    Stop a connection" << std::endl;
    std::cout << "  restart <profile> Restart a connection" << std::endl;
    std::cout << "  status            Show connection status" << std::endl;
    std::cout << "  logs              Show recent logs" << std::endl;
    std::cout << "  test <profile>    Test a connection" << std::endl;
    std::cout << "  config            Show configuration" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --config, -c      Configuration file path" << std::endl;
    std::cout << "  --log-file        Log file path" << std::endl;
    std::cout << "  --verbose, -v     Enable verbose logging" << std::endl;
    std::cout << "  --quiet, -q       Enable quiet mode" << std::endl;
    std::cout << "  --daemon, -d      Run as daemon" << std::endl;
    std::cout << "  --help            Show this help message" << std::endl;
    std::cout << "  --version         Show version information" << std::endl;
}

void SSHVPNApplication::printHelp() {
    printUsage();
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  sshvpn add                    # Interactive profile creation" << std::endl;
    std::cout << "  sshvpn start myprofile        # Start connection to myprofile" << std::endl;
    std::cout << "  sshvpn status                 # Show all connection statuses" << std::endl;
    std::cout << "  sshvpn logs --follow          # Follow logs in real-time" << std::endl;
    std::cout << std::endl;
    std::cout << "For more information, visit: https://github.com/minimax/sshvpn" << std::endl;
}

void SSHVPNApplication::printVersion() {
    std::cout << "SSH VPN Client v1.0.0" << std::endl;
    std::cout << "Secure SSH tunnel manager with enhanced security features" << std::endl;
    std::cout << "Built with C++17, libssh2, and modern security practices" << std::endl;
    std::cout << "Author: MiniMax Agent" << std::endl;
}

int SSHVPNApplication::handleListCommand() {
    logger_->info("Listing all profiles", "cli");
    
    auto profiles = config_manager_->getAllProfiles();
    
    if (profiles.empty()) {
        std::cout << "No profiles configured." << std::endl;
        std::cout << "Use 'sshvpn add' to create your first profile." << std::endl;
        return 0;
    }
    
    std::cout << "Configured Profiles:" << std::endl;
    std::cout << std::string(50, '-') << std::endl;
    
    for (const auto& profile : profiles) {
        std::cout << "Name: " << profile.name << std::endl;
        std::cout << "Host: " << profile.user << "@" << profile.host << ":" << profile.port << std::endl;
        std::cout << "Local Port: " << profile.local_port << std::endl;
        
        if (profile.identity_file.has_value()) {
            std::cout << "Key File: " << profile.identity_file.value() << std::endl;
        }
        
        if (profile.prefix.has_value()) {
            std::cout << "SSH Options: " << profile.prefix.value() << std::endl;
        }
        
        // Show connection status
        auto status = connection_manager_->getConnectionStatus(profile.name);
        std::cout << "Status: ";
        switch (status) {
            case ConnectionStatus::CONNECTED:
                std::cout << "Connected ✓" << std::endl;
                break;
            case ConnectionStatus::CONNECTING:
                std::cout << "Connecting..." << std::endl;
                break;
            case ConnectionStatus::ERROR:
                std::cout << "Error ✗" << std::endl;
                break;
            case ConnectionStatus::DISCONNECTED:
            default:
                std::cout << "Disconnected" << std::endl;
                break;
        }
        
        std::cout << std::endl;
    }
    
    return 0;
}

int SSHVPNApplication::handleAddCommand(const std::vector<std::string>& args) {
    logger_->info("Adding new profile", "cli");
    
    SSHProfile profile;
    
    try {
        profile = createProfileInteractive();
        
        // Validate profile
        auto validation_errors = config_manager_->validateProfile(profile);
        if (!validation_errors.empty()) {
            std::cout << "Profile validation failed:" << std::endl;
            for (const auto& error : validation_errors) {
                std::cout << "  - " << error << std::endl;
            }
            return 1;
        }
        
        // Add profile
        if (config_manager_->addProfile(profile)) {
            std::cout << "Profile '" << profile.name << "' added successfully." << std::endl;
            logger_->info("Profile added: " + profile.name, "cli");
            return 0;
        } else {
            std::cout << "Failed to add profile. Profile may already exist." << std::endl;
            return 1;
        }
        
    } catch (const std::exception& e) {
        logger_->error("Failed to add profile: " + std::string(e.what()), "cli");
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
}

SSHProfile SSHVPNApplication::createProfileInteractive() {
    SSHProfile profile;
    
    std::cout << "Creating new SSH profile..." << std::endl;
    std::cout << std::endl;
    
    // Profile name
    do {
        std::cout << "Profile name: ";
        std::getline(std::cin, profile.name);
        profile.name = ProcessUtils::trimString(profile.name);
        
        if (profile.name.empty()) {
            std::cout << "Profile name cannot be empty." << std::endl;
            continue;
        }
        
        if (config_manager_->profileExists(profile.name)) {
            std::cout << "Profile '" << profile.name << "' already exists." << std::endl;
            std::cout << "Please choose a different name." << std::endl;
            profile.name.clear();
        }
    } while (profile.name.empty());
    
    // Host
    do {
        std::cout << "SSH host: ";
        std::getline(std::cin, profile.host);
        profile.host = ProcessUtils::trimString(profile.host);
        
        if (profile.host.empty()) {
            std::cout << "Host cannot be empty." << std::endl;
        }
    } while (profile.host.empty());
    
    // User
    do {
        std::cout << "SSH user: ";
        std::getline(std::cin, profile.user);
        profile.user = ProcessUtils::trimString(profile.user);
        
        if (profile.user.empty()) {
            std::cout << "User cannot be empty." << std::endl;
        }
    } while (profile.user.empty());
    
    // Port
    std::cout << "SSH port (default: 22): ";
    std::string port_str;
    std::getline(std::cin, port_str);
    port_str = ProcessUtils::trimString(port_str);
    profile.port = port_str.empty() ? "22" : port_str;
    
    // Local port
    std::cout << "Local SOCKS proxy port (default: 1080): ";
    std::string local_port_str;
    std::getline(std::cin, local_port_str);
    local_port_str = ProcessUtils::trimString(local_port_str);
    profile.local_port = local_port_str.empty() ? "1080" : local_port_str;
    
    // Authentication method
    std::cout << "Authentication method:" << std::endl;
    std::cout << "1. SSH Key" << std::endl;
    std::cout << "2. Password" << std::endl;
    std::cout << "3. SSH Agent" << std::endl;
    std::cout << "Choice (1-3): ";
    
    std::string auth_choice;
    std::getline(std::cin, auth_choice);
    auth_choice = ProcessUtils::trimString(auth_choice);
    
    if (auth_choice == "1") {
        std::cout << "SSH key file path: ";
        std::string key_path;
        std::getline(std::cin, key_path);
        key_path = ProcessUtils::trimString(key_path);
        
        if (!key_path.empty()) {
            profile.identity_file = key_path;
        }
    } else if (auth_choice == "2") {
        std::cout << "Note: Password will be requested when starting the connection." << std::endl;
    } else if (auth_choice == "3") {
        std::cout << "Using SSH agent for authentication." << std::endl;
    }
    
    // Advanced options
    std::cout << std::endl;
    std::cout << "Configure advanced SSH options? (y/N): ";
    std::string advanced;
    std::getline(std::cin, advanced);
    advanced = ProcessUtils::trimString(advanced);
    
    if (advanced == "y" || advanced == "Y") {
        std::cout << "SSH command prefix (e.g., '-D 9090 -L 8080:localhost:80'): ";
        std::string prefix;
        std::getline(std::cin, prefix);
        prefix = ProcessUtils::trimString(prefix);
        
        if (!prefix.empty()) {
            profile.prefix = prefix;
        }
        
        std::cout << "Connection timeout in seconds (default: 30): ";
        std::string timeout_str;
        std::getline(std::cin, timeout_str);
        timeout_str = ProcessUtils::trimString(timeout_str);
        
        if (!timeout_str.empty()) {
            try {
                profile.timeout = std::stoi(timeout_str);
            } catch (const std::exception&) {
                std::cout << "Invalid timeout, using default (30 seconds)." << std::endl;
            }
        }
        
        std::cout << "Auto-reconnect on failure? (y/N): ";
        std::string auto_reconnect;
        std::getline(std::cin, auto_reconnect);
        auto_reconnect = ProcessUtils::trimString(auto_reconnect);
        
        if (auto_reconnect == "y" || auto_reconnect == "Y") {
            profile.auto_reconnect = true;
            
            std::cout << "Maximum reconnect attempts (default: 3): ";
            std::string attempts_str;
            std::getline(std::cin, attempts_str);
            attempts_str = ProcessUtils::trimString(attempts_str);
            
            if (!attempts_str.empty()) {
                try {
                    profile.reconnect_attempts = std::stoi(attempts_str);
                } catch (const std::exception&) {
                    std::cout << "Invalid number, using default (3 attempts)." << std::endl;
                }
            }
            
            std::cout << "Reconnect delay in seconds (default: 5): ";
            std::string delay_str;
            std::getline(std::cin, delay_str);
            delay_str = ProcessUtils::trimString(delay_str);
            
            if (!delay_str.empty()) {
                try {
                    profile.reconnect_delay = std::stoi(delay_str);
                } catch (const std::exception&) {
                    std::cout << "Invalid number, using default (5 seconds)." << std::endl;
                }
            }
        }
    }
    
    std::cout << std::endl;
    std::cout << "Profile summary:" << std::endl;
    std::cout << "  Name: " << profile.name << std::endl;
    std::cout << "  Host: " << profile.user << "@" << profile.host << ":" << profile.port << std::endl;
    std::cout << "  Local Port: " << profile.local_port << std::endl;
    if (profile.identity_file.has_value()) {
        std::cout << "  Key File: " << profile.identity_file.value() << std::endl;
    }
    if (profile.prefix.has_value()) {
        std::cout << "  SSH Options: " << profile.prefix.value() << std::endl;
    }
    
    std::cout << std::endl;
    if (!confirmAction("Save this profile?")) {
        throw std::runtime_error("Profile creation cancelled by user");
    }
    
    return profile;
}

bool SSHVPNApplication::confirmAction(const std::string& message) {
    std::cout << message << " (y/N): ";
    std::string response;
    std::getline(std::cin, response);
    response = ProcessUtils::trimString(response);
    
    return response == "y" || response == "Y";
}

int SSHVPNApplication::handleRemoveCommand(const std::string& profile_name) {
    logger_->info("Removing profile: " + profile_name, "cli");
    
    // Check if profile exists
    if (!config_manager_->profileExists(profile_name)) {
        std::cout << "Profile '" << profile_name << "' not found." << std::endl;
        return 1;
    }
    
    // Check if connection is active
    if (connection_manager_->isConnectionActive(profile_name)) {
        std::cout << "Connection is currently active. Stop it first with 'sshvpn stop " << profile_name << "'" << std::endl;
        return 1;
    }
    
    // Confirm removal
    std::cout << "Are you sure you want to remove profile '" << profile_name << "'? (y/N): ";
    std::string response;
    std::getline(std::cin, response);
    response = ProcessUtils::trimString(response);
    
    if (response != "y" && response != "Y") {
        std::cout << "Removal cancelled." << std::endl;
        return 0;
    }
    
    // Remove profile
    if (config_manager_->removeProfile(profile_name)) {
        std::cout << "Profile '" << profile_name << "' removed successfully." << std::endl;
        logger_->info("Profile removed: " + profile_name, "cli");
        return 0;
    } else {
        std::cout << "Failed to remove profile." << std::endl;
        return 1;
    }
}

int SSHVPNApplication::handleStartCommand(const std::string& profile_name) {
    logger_->info("Starting connection: " + profile_name, "cli");
    
    // Check if profile exists
    auto profile = config_manager_->getProfile(profile_name);
    if (!profile.has_value()) {
        std::cout << "Profile '" << profile_name << "' not found." << std::endl;
        return 1;
    }
    
    // Check if already connected
    if (connection_manager_->isConnectionActive(profile_name)) {
        std::cout << "Connection to '" << profile_name << "' is already active." << std::endl;
        return 0;
    }
    
    std::cout << "Starting connection to " << profile_name << "..." << std::endl;
    
    // Start connection
    if (connection_manager_->startConnection(profile_name)) {
        std::cout << "Connection to '" << profile_name << "' started successfully." << std::endl;
        std::cout << "SOCKS5 proxy available at: localhost:" << profile.value().local_port << std::endl;
        
        // Show usage instructions
        std::cout << std::endl;
        std::cout << "To use this proxy:" << std::endl;
        std::cout << "  curl --socks5 localhost:" << profile.value().local_port << " http://ifconfig.me" << std::endl;
        std::cout << "  Or configure your browser to use SOCKS5 proxy at localhost:" << profile.value().local_port << std::endl;
        
        logger_->info("Connection started successfully: " + profile_name, "cli");
        return 0;
    } else {
        std::cout << "Failed to start connection to '" << profile_name << "'." << std::endl;
        logger_->error("Failed to start connection: " + profile_name, "cli");
        return 1;
    }
}

int SSHVPNApplication::handleStopCommand(const std::string& profile_name) {
    logger_->info("Stopping connection: " + profile_name, "cli");
    
    // Check if profile exists
    if (!config_manager_->profileExists(profile_name)) {
        std::cout << "Profile '" << profile_name << "' not found." << std::endl;
        return 1;
    }
    
    // Check if connection is active
    if (!connection_manager_->isConnectionActive(profile_name)) {
        std::cout << "Connection to '" << profile_name << "' is not active." << std::endl;
        return 0;
    }
    
    std::cout << "Stopping connection to " << profile_name << "..." << std::endl;
    
    // Stop connection
    if (connection_manager_->stopConnection(profile_name)) {
        std::cout << "Connection to '" << profile_name << "' stopped successfully." << std::endl;
        logger_->info("Connection stopped: " + profile_name, "cli");
        return 0;
    } else {
        std::cout << "Failed to stop connection to '" << profile_name << "'." << std::endl;
        logger_->error("Failed to stop connection: " + profile_name, "cli");
        return 1;
    }
}

int SSHVPNApplication::handleRestartCommand(const std::string& profile_name) {
    logger_->info("Restarting connection: " + profile_name, "cli");
    
    // Check if profile exists
    if (!config_manager_->profileExists(profile_name)) {
        std::cout << "Profile '" << profile_name << "' not found." << std::endl;
        return 1;
    }
    
    std::cout << "Restarting connection to " << profile_name << "..." << std::endl;
    
    // Stop connection first
    connection_manager_->stopConnection(profile_name);
    
    // Wait a moment for clean shutdown
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Start connection
    if (connection_manager_->startConnection(profile_name)) {
        std::cout << "Connection to '" << profile_name << "' restarted successfully." << std::endl;
        logger_->info("Connection restarted: " + profile_name, "cli");
        return 0;
    } else {
        std::cout << "Failed to restart connection to '" << profile_name << "'." << std::endl;
        logger_->error("Failed to restart connection: " + profile_name, "cli");
        return 1;
    }
}

int SSHVPNApplication::handleStatusCommand() {
    logger_->info("Showing connection status", "cli");
    
    auto profiles = config_manager_->getAllProfiles();
    
    if (profiles.empty()) {
        std::cout << "No profiles configured." << std::endl;
        return 0;
    }
    
    auto statuses = connection_manager_->getAllConnectionStatuses();
    auto stats = connection_manager_->getAllConnectionStatistics();
    
    std::cout << "Connection Status:" << std::endl;
    std::cout << std::string(80, '=') << std::endl;
    std::cout << std::setw(20) << std::left << "Profile" 
              << std::setw(15) << "Status" 
              << std::setw(20) << "Host" 
              << std::setw(15) << "Port" 
              << std::setw(10) << "Uptime" << std::endl;
    std::cout << std::string(80, '-') << std::endl;
    
    for (const auto& profile : profiles) {
        auto status_it = statuses.find(profile.name);
        auto stats_it = stats.find(profile.name);
        
        std::string status_str = "Disconnected";
        std::string uptime_str = "-";
        
        if (status_it != statuses.end()) {
            switch (status_it->second) {
                case ConnectionStatus::CONNECTED:
                    status_str = "Connected ✓";
                    if (stats_it != stats.end() && stats_it->second.is_active) {
                        auto uptime = std::chrono::steady_clock::now() - stats_it->second.connection_start;
                        uptime_str = ProcessUtils::formatDuration(std::chrono::duration_cast<std::chrono::milliseconds>(uptime));
                    }
                    break;
                case ConnectionStatus::CONNECTING:
                    status_str = "Connecting...";
                    break;
                case ConnectionStatus::ERROR:
                    status_str = "Error ✗";
                    break;
                case ConnectionStatus::TIMEOUT:
                    status_str = "Timeout ⏰";
                    break;
                default:
                    status_str = "Disconnected";
                    break;
            }
        }
        
        std::cout << std::setw(20) << std::left << profile.name
                  << std::setw(15) << status_str
                  << std::setw(20) << profile.host
                  << std::setw(15) << profile.port
                  << std::setw(10) << uptime_str << std::endl;
    }
    
    return 0;
}

int SSHVPNApplication::handleLogsCommand() {
    logger_->info("Showing recent logs", "cli");
    
    auto recent_logs = logger_->getRecentLogs(50);
    
    if (recent_logs.empty()) {
        std::cout << "No logs available." << std::endl;
        return 0;
    }
    
    std::cout << "Recent Logs (last 50 entries):" << std::endl;
    std::cout << std::string(80, '=') << std::endl;
    
    for (const auto& log_entry : recent_logs) {
        std::cout << log_entry << std::endl;
    }
    
    std::cout << std::string(80, '=') << std::endl;
    std::cout << "For more detailed logs, check: " << logger_->getLogFilePath() << std::endl;
    
    return 0;
}

int SSHVPNApplication::handleTestCommand(const std::string& profile_name) {
    logger_->info("Testing connection: " + profile_name, "cli");
    
    // Check if profile exists
    auto profile = config_manager_->getProfile(profile_name);
    if (!profile.has_value()) {
        std::cout << "Profile '" << profile_name << "' not found." << std::endl;
        return 1;
    }
    
    std::cout << "Testing connection to " << profile_name << "..." << std::endl;
    
    // Create a test SSH client
    auto test_client = std::make_shared<SSHClient>(logger_);
    
    // Test the connection
    if (test_client->testConnection(profile.value(), 30)) {
        std::cout << "✓ Connection test successful!" << std::endl;
        std::cout << "  Host: " << profile.value().host << std::endl;
        std::cout << "  User: " << profile.value().user << std::endl;
        std::cout << "  Port: " << profile.value().port << std::endl;
        std::cout << "  Authentication: " << (profile.value().identity_file.has_value() ? "SSH Key" : "Password/Agent") << std::endl;
        
        logger_->info("Connection test successful: " + profile_name, "cli");
        return 0;
    } else {
        std::cout << "✗ Connection test failed!" << std::endl;
        std::cout << "  Error: " << test_client->getLastError() << std::endl;
        
        logger_->error("Connection test failed: " + profile_name + " - " + test_client->getLastError(), "cli");
        return 1;
    }
}

int SSHVPNApplication::handleConfigCommand() {
    logger_->info("Showing configuration", "cli");
    
    auto profiles = config_manager_->getAllProfiles();
    auto config_options = config_manager_->getOptions();
    
    std::cout << "Configuration:" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    
    std::cout << "Configuration Directory: " << config_options.config_dir << std::endl;
    std::cout << "Log Directory: " << config_options.log_dir << std::endl;
    std::cout << "PID Directory: " << config_options.pid_dir << std::endl;
    std::cout << "Auto Create Directories: " << (config_options.create_directories ? "Yes" : "No") << std::endl;
    std::cout << "Backup on Save: " << (config_options.backup_on_save ? "Yes" : "No") << std::endl;
    std::cout << "Max Backup Files: " << config_options.max_backup_files << std::endl;
    std::cout << std::endl;
    
    std::cout << "Total Profiles: " << profiles.size() << std::endl;
    std::cout << "Active Connections: " << connection_manager_->getActiveConnections().size() << std::endl;
    
    // Show global connection configuration
    auto global_config = connection_manager_->getGlobalConnectionConfig();
    std::cout << std::endl;
    std::cout << "Global Connection Settings:" << std::endl;
    std::cout << "  Max Retry Attempts: " << global_config.max_retry_attempts << std::endl;
    std::cout << "  Retry Delay: " << global_config.retry_delay_seconds << " seconds" << std::endl;
    std::cout << "  Connection Timeout: " << global_config.connection_timeout_seconds << " seconds" << std::endl;
    std::cout << "  Command Timeout: " << global_config.command_timeout_seconds << " seconds" << std::endl;
    std::cout << "  Keep Alive: " << (global_config.keep_alive ? "Yes" : "No") << std::endl;
    std::cout << "  Keep Alive Interval: " << global_config.keep_alive_interval << " seconds" << std::endl;
    
    return 0;
}

bool SSHVPNApplication::validateOptions(const CLIOptions& options) {
    // Validate config file if specified
    if (!options.config_file.empty()) {
        std::string abs_path = ProcessUtils::getAbsolutePath(options.config_file);
        if (!ProcessUtils::fileExists(abs_path) && !ProcessUtils::directoryExists(ProcessUtils::getDirectoryName(abs_path))) {
            std::cerr << "Error: Configuration file directory does not exist: " << ProcessUtils::getDirectoryName(abs_path) << std::endl;
            return false;
        }
    }
    
    // Validate log file if specified
    if (!options.log_file.empty()) {
        std::string abs_path = ProcessUtils::getAbsolutePath(options.log_file);
        std::string dir = ProcessUtils::getDirectoryName(abs_path);
        if (!ProcessUtils::directoryExists(dir)) {
            std::cerr << "Error: Log file directory does not exist: " << dir << std::endl;
            return false;
        }
    }
    
    // Check for conflicting options
    if (options.verbose && options.quiet) {
        std::cerr << "Error: Cannot use both --verbose and --quiet options" << std::endl;
        return false;
    }
    
    return true;
}

void SSHVPNApplication::cleanup() {
    logger_->info("Cleaning up application", "main");
    
    if (connection_manager_) {
        connection_manager_->stopAllConnections();
    }
    
    if (logger_) {
        logger_->flush();
    }
}

int main(int argc, char* argv[]) {
    SSHVPNApplication app;
    
    try {
        int result = app.run(argc, argv);
        app.cleanup();
        return result;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}