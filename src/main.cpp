#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <dirent.h>
#include <cstring>
#include <ctime>
#include <chrono>

// Colors for output
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_RESET "\033[0m"

class ConfigManager {
private:
    std::string configPath;
    std::map<std::string, std::map<std::string, std::string>> profiles;
    
public:
    ConfigManager() {
        const char* home = getenv("HOME");
        configPath = std::string(home) + "/.config/vpn/config.json";
        
        // Create config directory if it doesn't exist
        std::string configDir = std::string(home) + "/.config/vpn";
        system(("mkdir -p " + configDir).c_str());
    }
    
    // Simple JSON parser for our specific format
    std::string parseJsonValue(const std::string& line, const std::string& key) {
        size_t pos = line.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        
        size_t colonPos = line.find(":", pos);
        if (colonPos == std::string::npos) return "";
        
        size_t valueStart = line.find("\"", colonPos + 1);
        if (valueStart == std::string::npos) return "";
        
        size_t valueEnd = line.find("\"", valueStart + 1);
        if (valueEnd == std::string::npos) return "";
        
        return line.substr(valueStart + 1, valueEnd - valueStart - 1);
    }
    
    bool loadConfig() {
        std::ifstream file(configPath);
        if (!file.is_open()) {
            return false;
        }
        
        std::string line;
        std::string currentProfile;
        bool inProfile = false;
        
        while (std::getline(file, line)) {
            // Trim whitespace
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            
            if (line.find("{") != std::string::npos) {
                inProfile = true;
            } else if (line.find("}") != std::string::npos) {
                inProfile = false;
                currentProfile = "";
            } else if (inProfile && line.find("\"name\"") != std::string::npos) {
                currentProfile = parseJsonValue(line, "name");
                profiles[currentProfile] = std::map<std::string, std::string>();
            } else if (inProfile && !currentProfile.empty()) {
                std::vector<std::string> keys = {"host", "user", "port", "local_port", "identity_file", "prefix"};
                for (const auto& key : keys) {
                    if (line.find("\"" + key + "\"") != std::string::npos) {
                        profiles[currentProfile][key] = parseJsonValue(line, key);
                    }
                }
            }
        }
        
        file.close();
        return true;
    }
    
    bool saveConfig() {
        std::ofstream file(configPath);
        if (!file.is_open()) {
            return false;
        }
        
        file << "[\n";
        bool first = true;
        for (const auto& profile : profiles) {
            if (!first) file << ",\n";
            first = false;
            
            file << "  {\n";
            file << "    \"name\": \"" << profile.first << "\",\n";
            
            bool firstField = true;
            for (const auto& field : profile.second) {
                if (!firstField) file << ",\n";
                firstField = false;
                
                file << "    \"" << field.first << "\": \"" << field.second << "\"";
            }
            file << "\n  }";
        }
        file << "\n]\n";
        
        file.close();
        return true;
    }
    
    bool addProfile(const std::string& name, const std::map<std::string, std::string>& data) {
        profiles[name] = data;
        return saveConfig();
    }
    
    bool removeProfile(const std::string& name) {
        if (profiles.erase(name)) {
            return saveConfig();
        }
        return false;
    }
    
    std::map<std::string, std::map<std::string, std::string>> getProfiles() {
        return profiles;
    }
    
    std::map<std::string, std::string> getProfile(const std::string& name) {
        auto it = profiles.find(name);
        if (it != profiles.end()) {
            return it->second;
        }
        return {};
    }
};

class VPNManager {
private:
    std::string pidFile;
    ConfigManager config;
    
    std::string getPidFilePath() {
        const char* home = getenv("HOME");
        return std::string(home) + "/.cache/vpn/pids.json";
    }
    
    void ensureCacheDir() {
        const char* home = getenv("HOME");
        std::string cacheDir = std::string(home) + "/.cache/vpn";
        system(("mkdir -p " + cacheDir).c_str());
    }
    
    void writeLog(const std::string& message) {
        ensureCacheDir();
        const char* home = getenv("HOME");
        std::string logFile = std::string(home) + "/.cache/vpn/vpn.log";
        
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::string timeStr = std::ctime(&time_t);
        timeStr.pop_back(); // Remove newline
        
        std::ofstream log(logFile, std::ios::app);
        if (log.is_open()) {
            log << "[" << timeStr << "] " << message << std::endl;
            log.close();
        }
    }
    
public:
    VPNManager() {
        ensureCacheDir();
    }
    
    bool startVPN(const std::string& profileName) {
        auto profile = config.getProfile(profileName);
        if (profile.empty()) {
            std::cout << COLOR_RED << "✗ Profile '" << profileName << "' not found" << COLOR_RESET << std::endl;
            return false;
        }
        
        // Check if already running
        if (isVPNRunning(profileName)) {
            std::cout << COLOR_YELLOW << "⚠ VPN profile '" << profileName << "' is already running" << COLOR_RESET << std::endl;
            return true;
        }
        
        std::string host = profile["host"];
        std::string user = profile["user"];
        std::string port = profile.count("port") ? profile["port"] : "22";
        std::string localPort = profile.count("local_port") ? profile["local_port"] : "1080";
        std::string identityFile = profile.count("identity_file") ? profile["identity_file"] : "";
        std::string prefix = profile.count("prefix") ? profile["prefix"] : "-D " + localPort;
        
        std::cout << COLOR_BLUE << "Connecting to " << user << "@" << host << ":" << port << "..." << COLOR_RESET << std::endl;
        
        // Get password
        std::string password = getPassword();
        if (password.empty()) {
            std::cout << COLOR_RED << "✗ Password required" << COLOR_RESET << std::endl;
            return false;
        }
        
        // Build SSH command
        std::string sshCmd = "ssh " + prefix + " -N -p " + port + " " + user + "@" + host;
        if (!identityFile.empty()) {
            sshCmd += " -i " + identityFile;
        }
        
        // Set up environment for password
        setenv("SSH_PASSWORD", password.c_str(), 1);
        
        writeLog("Starting VPN: " + profileName);
        
        // Start SSH tunnel in background
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            setsid(); // Create new session
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            
            // Execute SSH command
            execl("/bin/sh", "sh", "-c", sshCmd.c_str(), (char*)NULL);
            _exit(1);
        } else if (pid > 0) {
            // Parent process
            savePID(profileName, pid);
            
            // Wait a moment to check if connection was successful
            sleep(2);
            
            if (isVPNRunning(profileName)) {
                std::cout << COLOR_GREEN << "✓ Connected to '" << profileName << "' on port " << localPort << COLOR_RESET << std::endl;
                writeLog("VPN started successfully: " + profileName);
                return true;
            } else {
                std::cout << COLOR_RED << "✗ Failed to connect to SSH server" << COLOR_RESET << std::endl;
                writeLog("VPN start failed: " + profileName);
                return false;
            }
        } else {
            std::cout << COLOR_RED << "✗ Failed to fork process" << COLOR_RESET << std::endl;
            return false;
        }
    }
    
    bool stopVPN(const std::string& profileName) {
        int pid = getPID(profileName);
        if (pid <= 0) {
            std::cout << COLOR_YELLOW << "⚠ VPN profile '" << profileName << "' is not running" << COLOR_RESET << std::endl;
            return true;
        }
        
        std::cout << COLOR_BLUE << "Stopping VPN '" << profileName << "'..." << COLOR_RESET << std::endl;
        
        // Kill the process
        if (kill(pid, SIGTERM) == 0) {
            // Wait for process to terminate
            int status;
            waitpid(pid, &status, 0);
            
            removePID(profileName);
            std::cout << COLOR_GREEN << "✓ VPN '" << profileName << "' stopped" << COLOR_RESET << std::endl;
            writeLog("VPN stopped: " + profileName);
            return true;
        } else {
            std::cout << COLOR_RED << "✗ Failed to stop VPN" << COLOR_RESET << std::endl;
            return false;
        }
    }
    
    void listVPNs() {
        auto profiles = config.getProfiles();
        if (profiles.empty()) {
            std::cout << "No VPN profiles configured." << std::endl;
            return;
        }
        
        std::cout << "Configured VPN profiles:" << std::endl;
        for (const auto& profile : profiles) {
            std::string status = isVPNRunning(profile.first) ? "Running" : "Stopped";
            std::string statusColor = isVPNRunning(profile.first) ? COLOR_GREEN : COLOR_YELLOW;
            
            auto user_it = profile.second.find("user");
            auto host_it = profile.second.find("host");
            auto port_it = profile.second.find("port");
            
            std::string user = user_it != profile.second.end() ? user_it->second : "unknown";
            std::string host = host_it != profile.second.end() ? host_it->second : "unknown";
            std::string port = port_it != profile.second.end() ? port_it->second : "22";
            
            std::cout << "  " << profile.first << " - " << statusColor << status << COLOR_RESET 
                     << " (" << user << "@" << host 
                     << ":" << port << ")" << std::endl;
        }
    }
    
    void statusVPNs() {
        auto profiles = config.getProfiles();
        bool foundRunning = false;
        
        for (const auto& profile : profiles) {
            if (isVPNRunning(profile.first)) {
                if (!foundRunning) {
                    std::cout << "Running VPN connections:" << std::endl;
                    foundRunning = true;
                }
                
                int pid = getPID(profile.first);
                auto localPort_it = profile.second.find("local_port");
                std::string localPort = localPort_it != profile.second.end() ? localPort_it->second : "1080";
                
                std::cout << "  " << COLOR_GREEN << profile.first << COLOR_RESET 
                         << " (PID: " << pid << ", Port: " << localPort << ")" << std::endl;
            }
        }
        
        if (!foundRunning) {
            std::cout << "No VPN connections running." << std::endl;
        }
    }
    
    void addProfileInteractive() {
        std::map<std::string, std::string> profile;
        
        std::cout << "Adding new VPN profile..." << std::endl;
        
        std::cout << "Profile name: ";
        std::getline(std::cin, profile["name"]);
        
        std::cout << "SSH host: ";
        std::getline(std::cin, profile["host"]);
        
        std::cout << "SSH user: ";
        std::getline(std::cin, profile["user"]);
        
        std::cout << "SSH port (default 22): ";
        std::string port;
        std::getline(std::cin, port);
        if (port.empty()) port = "22";
        profile["port"] = port;
        
        std::cout << "Local SOCKS port (default 1080): ";
        std::string localPort;
        std::getline(std::cin, localPort);
        if (localPort.empty()) localPort = "1080";
        profile["local_port"] = localPort;
        
        std::cout << "SSH identity file (optional, press Enter to skip): ";
        std::string identityFile;
        std::getline(std::cin, identityFile);
        if (!identityFile.empty()) {
            profile["identity_file"] = identityFile;
        }
        
        std::cout << "SSH prefix options (optional, e.g., '-D 9090 -L 8080:localhost:80', press Enter for default SOCKS): ";
        std::string prefix;
        std::getline(std::cin, prefix);
        if (!prefix.empty()) {
            profile["prefix"] = prefix;
        }
        
        if (config.addProfile(profile["name"], profile)) {
            std::cout << COLOR_GREEN << "✓ Profile '" << profile["name"] << "' added successfully" << COLOR_RESET << std::endl;
        } else {
            std::cout << COLOR_RED << "✗ Failed to add profile" << COLOR_RESET << std::endl;
        }
    }
    
    std::string getPassword() {
        // First check environment variable
        const char* envPass = getenv("VPN_SSH_PASS");
        if (envPass && strlen(envPass) > 0) {
            return std::string(envPass);
        }
        
        // Then ask user
        std::cout << "SSH Password: ";
        
        struct termios oldSettings, newSettings;
        tcgetattr(STDIN_FILENO, &oldSettings);
        newSettings = oldSettings;
        newSettings.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newSettings);
        
        std::string password;
        std::getline(std::cin, password);
        
        tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);
        std::cout << std::endl;
        
        return password;
    }
    
private:
    void savePID(const std::string& profileName, pid_t pid) {
        ensureCacheDir();
        std::string pidFilePath = getPidFilePath();
        
        // Load existing PIDs
        std::map<std::string, pid_t> pids;
        std::ifstream pidFile(pidFilePath);
        if (pidFile.is_open()) {
            std::string line;
            while (std::getline(pidFile, line)) {
                size_t colonPos = line.find(":");
                if (colonPos != std::string::npos) {
                    std::string name = line.substr(0, colonPos);
                    pid_t storedPid = atoi(line.substr(colonPos + 1).c_str());
                    if (storedPid > 0 && kill(storedPid, 0) == 0) {
                        pids[name] = storedPid;
                    }
                }
            }
            pidFile.close();
        }
        
        // Add new PID
        pids[profileName] = pid;
        
        // Save back to file
        std::ofstream outFile(pidFilePath);
        if (outFile.is_open()) {
            for (const auto& p : pids) {
                outFile << p.first << ":" << p.second << std::endl;
            }
            outFile.close();
        }
    }
    
    int getPID(const std::string& profileName) {
        std::string pidFilePath = getPidFilePath();
        std::ifstream pidFile(pidFilePath);
        
        if (!pidFile.is_open()) {
            return 0;
        }
        
        std::string line;
        while (std::getline(pidFile, line)) {
            size_t colonPos = line.find(":");
            if (colonPos != std::string::npos) {
                std::string name = line.substr(0, colonPos);
                if (name == profileName) {
                    pid_t pid = atoi(line.substr(colonPos + 1).c_str());
                    if (pid > 0 && kill(pid, 0) == 0) {
                        return pid;
                    }
                }
            }
        }
        
        return 0;
    }
    
    bool isVPNRunning(const std::string& profileName) {
        return getPID(profileName) > 0;
    }
    
    void removePID(const std::string& profileName) {
        std::string pidFilePath = getPidFilePath();
        std::map<std::string, pid_t> pids;
        
        // Load existing PIDs
        std::ifstream pidFile(pidFilePath);
        if (pidFile.is_open()) {
            std::string line;
            while (std::getline(pidFile, line)) {
                size_t colonPos = line.find(":");
                if (colonPos != std::string::npos) {
                    std::string name = line.substr(0, colonPos);
                    pid_t storedPid = atoi(line.substr(colonPos + 1).c_str());
                    if (storedPid > 0 && kill(storedPid, 0) == 0 && name != profileName) {
                        pids[name] = storedPid;
                    }
                }
            }
            pidFile.close();
        }
        
        // Save back to file (without the removed profile)
        std::ofstream outFile(pidFilePath);
        if (outFile.is_open()) {
            for (const auto& p : pids) {
                outFile << p.first << ":" << p.second << std::endl;
            }
            outFile.close();
        }
    }
};

void printHelp() {
    std::cout << "VPN - SSH SOCKS Proxy Manager" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage: vpn <command> [profile_name]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  start <profile>    Start VPN connection for specified profile" << std::endl;
    std::cout << "  stop <profile>     Stop VPN connection for specified profile" << std::endl;
    std::cout << "  status             Show status of all running VPN connections" << std::endl;
    std::cout << "  list               List all configured VPN profiles" << std::endl;
    std::cout << "  add                Add a new VPN profile interactively" << std::endl;
    std::cout << "  help               Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Environment Variables:" << std::endl;
    std::cout << "  VPN_SSH_PASS       SSH password (alternative to interactive input)" << std::endl;
    std::cout << std::endl;
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Config file: ~/.config/vpn/config.json" << std::endl;
    std::cout << "  Log file: ~/.cache/vpn/vpn.log" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printHelp();
        return 1;
    }
    
    std::string command = argv[1];
    VPNManager vpn;
    
    if (command == "start") {
        if (argc < 3) {
            std::cout << COLOR_RED << "✗ Profile name required" << COLOR_RESET << std::endl;
            return 1;
        }
        vpn.startVPN(argv[2]);
    } else if (command == "stop") {
        if (argc < 3) {
            std::cout << COLOR_RED << "✗ Profile name required" << COLOR_RESET << std::endl;
            return 1;
        }
        vpn.stopVPN(argv[2]);
    } else if (command == "status") {
        vpn.statusVPNs();
    } else if (command == "list") {
        vpn.listVPNs();
    } else if (command == "add") {
        vpn.addProfileInteractive();
    } else if (command == "help" || command == "--help" || command == "-h") {
        printHelp();
    } else {
        std::cout << COLOR_RED << "✗ Unknown command: " << command << COLOR_RESET << std::endl;
        printHelp();
        return 1;
    }
    
    return 0;
}