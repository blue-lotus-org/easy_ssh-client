#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../include/security.h"
#include "../include/config_manager.h"
#include "../include/utils.h"
#include <iostream>
#include <string>
#include <vector>

using namespace SSHVPN;

// Test fixture for security tests
class SecurityManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        security_manager_ = std::make_shared<SecurityManager>();
    }
    
    std::shared_ptr<SecurityManager> security_manager_;
};

// Test input validation
TEST_F(SecurityManagerTest, ValidateHost) {
    // Valid hosts
    EXPECT_TRUE(security_manager_->validateHost("example.com"));
    EXPECT_TRUE(security_manager_->validateHost("192.168.1.1"));
    EXPECT_TRUE(security_manager_->validateHost("localhost"));
    EXPECT_TRUE(security_manager_->validateHost("server.domain.org"));
    
    // Invalid hosts
    EXPECT_FALSE(security_manager_->validateHost(""));
    EXPECT_FALSE(security_manager_->validateHost("host with spaces"));
    EXPECT_FALSE(security_manager_->validateHost("'; DROP TABLE users; --"));
    EXPECT_FALSE(security_manager_->validateHost("../../../etc/passwd"));
}

TEST_F(SecurityManagerTest, ValidatePort) {
    // Valid ports
    EXPECT_TRUE(security_manager_->validatePort("22"));
    EXPECT_TRUE(security_manager_->validatePort("1080"));
    EXPECT_TRUE(security_manager_->validatePort("65535"));
    EXPECT_TRUE(security_manager_->validatePort(22));
    EXPECT_TRUE(security_manager_->validatePort(1080));
    
    // Invalid ports
    EXPECT_FALSE(security_manager_->validatePort("0"));
    EXPECT_FALSE(security_manager_->validatePort("65536"));
    EXPECT_FALSE(security_manager_->validatePort("-1"));
    EXPECT_FALSE(security_manager_->validatePort("abc"));
    EXPECT_FALSE(security_manager_->validatePort(0));
    EXPECT_FALSE(security_manager_->validatePort(70000));
}

TEST_F(SecurityManagerTest, ValidateUser) {
    // Valid users
    EXPECT_TRUE(security_manager_->validateUser("admin"));
    EXPECT_TRUE(security_manager_->validateUser("user123"));
    EXPECT_TRUE(security_manager_->validateUser("test_user"));
    EXPECT_TRUE(security_manager_->validateUser("john.doe"));
    
    // Invalid users
    EXPECT_FALSE(security_manager_->validateUser(""));
    EXPECT_FALSE(security_manager_->validateUser("user with spaces"));
    EXPECT_FALSE(security_manager_->validateUser("'; DROP TABLE users; --"));
    EXPECT_FALSE(security_manager_->validateUser("root"));  // Reserved
    EXPECT_FALSE(security_manager_->validateUser("admin")); // Reserved
}

TEST_F(SecurityManagerTest, SanitizeShellArgument) {
    // Test shell argument sanitization
    std::string result = security_manager_->sanitizeShellArgument("test arg");
    EXPECT_EQ(result, "test\\ arg");
    
    result = security_manager_->sanitizeShellArgument("'quoted'");
    EXPECT_THAT(result, ::testing::HasSubstr("\\'"));
    
    result = security_manager_->sanitizeShellArgument("$(rm -rf /)");
    EXPECT_THAT(result, ::testing::HasSubstr("\\$"));
}

TEST_F(SecurityManagerTest, DetectInjectionAttempt) {
    // Test injection detection
    EXPECT_TRUE(security_manager_->detectInjectionAttempt("'; DROP TABLE users; --"));
    EXPECT_TRUE(security_manager_->detectInjectionAttempt("<script>alert('xss')</script>"));
    EXPECT_TRUE(security_manager_->detectInjectionAttempt("SELECT * FROM users"));
    
    // Normal inputs should not trigger detection
    EXPECT_FALSE(security_manager_->detectInjectionAttempt("normal input"));
    EXPECT_FALSE(security_manager_->detectInjectionAttempt("user@example.com"));
    EXPECT_FALSE(security_manager_->detectInjectionAttempt("192.168.1.1"));
}

TEST_F(SecurityManagerTest, BuildSecureSSHCommand) {
    // Test secure SSH command construction
    SSHProfile profile;
    profile.name = "test";
    profile.host = "example.com";
    profile.user = "testuser";
    profile.port = "22";
    profile.local_port = "1080";
    profile.identity_file = "~/.ssh/id_rsa";
    
    auto command = security_manager_->buildSecureSSHCommand(profile);
    
    // Should contain expected components
    EXPECT_THAT(command, ::testing::ElementsAre(
        "ssh", "-i", ::testing::HasSubstr("id_rsa"), "-D", "1080", "-N", "-T",
        "ServerAliveInterval=60", "ServerAliveCountMax=3", "ConnectTimeout=30",
        "testuser@example.com"
    ));
    
    // Should be safe to execute
    EXPECT_TRUE(security_manager_->isCommandSafe(command));
}

TEST_F(SecurityManagerTest, PathTraversalProtection) {
    // Test path traversal detection
    EXPECT_TRUE(security_manager_->isPathTraversalAttempt("../../../etc/passwd"));
    EXPECT_TRUE(security_manager_->isPathTraversalAttempt("..\\..\\windows\\system32\\config\\sam"));
    EXPECT_TRUE(security_manager_->isPathTraversalAttempt("%2e%2e%2f"));
    
    // Normal paths should not trigger detection
    EXPECT_FALSE(security_manager_->isPathTraversalAttempt("normal/path/file.txt"));
    EXPECT_FALSE(security_manager_->isPathTraversalAttempt("/absolute/path/file.txt"));
}

// Test fixture for configuration tests
class ConfigManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        config_manager_ = std::make_shared<ConfigManager>();
    }
    
    std::shared_ptr<ConfigManager> config_manager_;
};

TEST_F(ConfigManagerTest, ValidateProfile) {
    // Valid profile
    SSHProfile valid_profile;
    valid_profile.name = "test";
    valid_profile.host = "example.com";
    valid_profile.user = "testuser";
    valid_profile.port = "22";
    valid_profile.local_port = "1080";
    
    auto errors = config_manager_->validateProfile(valid_profile);
    EXPECT_TRUE(errors.empty());
    
    // Invalid profiles
    SSHProfile invalid_profile;
    invalid_profile.name = "";
    invalid_profile.host = "";
    invalid_profile.user = "";
    invalid_profile.port = "";
    invalid_profile.local_port = "";
    
    errors = config_manager_->validateProfile(invalid_profile);
    EXPECT_FALSE(errors.empty());
    EXPECT_GT(errors.size(), 0);
}

TEST_F(ConfigManagerTest, ProfileNameValidation) {
    // Valid profile names
    EXPECT_TRUE(ConfigManager::isValidProfileName("test"));
    EXPECT_TRUE(ConfigManager::isValidProfileName("my_profile"));
    EXPECT_TRUE(ConfigManager::isValidProfileName("profile-123"));
    EXPECT_TRUE(ConfigManager::isValidProfileName("PROFILE"));
    
    // Invalid profile names
    EXPECT_FALSE(ConfigManager::isValidProfileName(""));
    EXPECT_FALSE(ConfigManager::isValidProfileName("test profile"));
    EXPECT_FALSE(ConfigManager::isValidProfileName("test/profile"));
    EXPECT_FALSE(ConfigManager::isValidProfileName("test@profile"));
    EXPECT_FALSE(ConfigManager::isValidProfileName("test.profile!"));
}

TEST_F(ConfigManagerTest, HostValidation) {
    // Valid hosts
    EXPECT_TRUE(ConfigManager::isValidHost("example.com"));
    EXPECT_TRUE(ConfigManager::isValidHost("192.168.1.1"));
    EXPECT_TRUE(ConfigManager::isValidHost("localhost"));
    EXPECT_TRUE(ConfigManager::isValidHost("server.domain.org"));
    
    // Invalid hosts
    EXPECT_FALSE(ConfigManager::isValidHost(""));
    EXPECT_FALSE(ConfigManager::isValidHost("host with spaces"));
    EXPECT_FALSE(ConfigManager::isValidHost("host@invalid"));
    EXPECT_FALSE(ConfigManager::isValidHost(std::string(256, 'a'))); // Too long
}

TEST_F(ConfigManagerTest, PortValidation) {
    // Valid ports
    EXPECT_TRUE(ConfigManager::isValidPort("22"));
    EXPECT_TRUE(ConfigManager::isValidPort("1080"));
    EXPECT_TRUE(ConfigManager::isValidPort("65535"));
    EXPECT_TRUE(ConfigManager::isValidPort(22));
    EXPECT_TRUE(ConfigManager::isValidPort(1080));
    
    // Invalid ports
    EXPECT_FALSE(ConfigManager::isValidPort("0"));
    EXPECT_FALSE(ConfigManager::isValidPort("65536"));
    EXPECT_FALSE(ConfigManager::isValidPort("-1"));
    EXPECT_FALSE(ConfigManager::isValidPort("abc"));
    EXPECT_FALSE(ConfigManager::isValidPort(0));
    EXPECT_FALSE(ConfigManager::isValidPort(70000));
}

// Test fixture for utility tests
class UtilsTest : public ::testing::Test {
protected:
    // Utility tests don't need setup
};

TEST_F(UtilsTest, StringUtilities) {
    // Test string splitting
    auto parts = ProcessUtils::splitString("a,b,c", ',');
    EXPECT_EQ(parts.size(), 3);
    EXPECT_EQ(parts[0], "a");
    EXPECT_EQ(parts[1], "b");
    EXPECT_EQ(parts[2], "c");
    
    // Test string trimming
    EXPECT_EQ(ProcessUtils::trimString("  hello  "), "hello");
    EXPECT_EQ(ProcessUtils::trimString("\t\nworld\r\n"), "world");
    
    // Test case conversion
    EXPECT_EQ(ProcessUtils::toUpperCase("hello"), "HELLO");
    EXPECT_EQ(ProcessUtils::toLowerCase("WORLD"), "world");
}

TEST_F(UtilsTest, FileUtilities) {
    // Test file existence
    EXPECT_TRUE(ProcessUtils::fileExists("/tmp")); // Directory should exist
    EXPECT_TRUE(ProcessUtils::directoryExists("/tmp"));
    
    // Test absolute path
    std::string abs_path = ProcessUtils::getAbsolutePath(".");
    EXPECT_TRUE(!abs_path.empty());
    EXPECT_EQ(abs_path[0], '/'); // Should start with /
}

TEST_F(UtilsTest, NetworkUtilities) {
    // Test IP address validation
    EXPECT_TRUE(ProcessUtils::isValidIPAddress("192.168.1.1"));
    EXPECT_TRUE(ProcessUtils::isValidIPAddress("127.0.0.1"));
    EXPECT_FALSE(ProcessUtils::isValidIPAddress("999.999.999.999"));
    EXPECT_FALSE(ProcessUtils::isValidIPAddress("not.an.ip"));
    
    // Test hostname validation
    EXPECT_TRUE(ProcessUtils::isValidHostname("example.com"));
    EXPECT_TRUE(ProcessUtils::isValidHostname("localhost"));
    EXPECT_FALSE(ProcessUtils::isValidHostname("host with spaces"));
}

TEST_F(UtilsTest, TimeUtilities) {
    // Test current time
    auto start_time = ProcessUtils::getCurrentTime();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto end_time = ProcessUtils::getCurrentTime();
    
    EXPECT_GT(end_time.time_since_epoch().count(), start_time.time_since_epoch().count());
    
    // Test duration formatting
    auto duration = std::chrono::milliseconds(1234);
    std::string formatted = ProcessUtils::formatDuration(duration);
    EXPECT_THAT(formatted, ::testing::HasSubstr("1"));
    EXPECT_THAT(formatted, ::testing::HasSubstr("s"));
}

// Integration test for security and configuration
TEST(SecurityConfigIntegration, EndToEndValidation) {
    auto security_manager = std::make_shared<SecurityManager>();
    auto config_manager = std::make_shared<ConfigManager>();
    
    // Create a potentially malicious profile
    SSHProfile malicious_profile;
    malicious_profile.name = "'; DROP TABLE users; --";
    malicious_profile.host = "evil.com";
    malicious_profile.user = "admin";
    malicious_profile.port = "22";
    malicious_profile.local_port = "1080";
    
    // Security manager should detect malicious inputs
    EXPECT_FALSE(security_manager->validateProfileName(malicious_profile.name));
    EXPECT_FALSE(security_manager->validateHost(malicious_profile.host));
    
    // Config manager should reject invalid profile
    auto errors = config_manager->validateProfile(malicious_profile);
    EXPECT_FALSE(errors.empty());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}