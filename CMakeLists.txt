cmake_minimum_required(VERSION 3.16)
project(ImprovedSSHVPNClient VERSION 1.0.0 LANGUAGES CXX)

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -fsanitize=address -fsanitize=undefined")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")

# Dependencies
find_package(Threads REQUIRED)
find_package(nlohmann_json 3.11.0 REQUIRED)
find_package(CLI11 REQUIRED)

# Library search paths
find_library(LIBSSH libssh REQUIRED)
if(NOT LIBSSH)
    message(WARNING "libssh not found, falling back to system ssh command")
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/config_manager.cpp
    src/ssh_client.cpp
    src/security.cpp
    src/logger.cpp
    src/utils.cpp
    src/connection_manager.cpp
)

# Header files
set(HEADERS
    include/config_manager.h
    include/ssh_client.h
    include/security.h
    include/logger.h
    include/utils.h
    include/connection_manager.h
    include/types.h
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(${PROJECT_NAME} 
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link libraries
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        Threads::Threads
        nlohmann_json::nlohmann_json
        CLI11::CLI11
)

# Conditionally link libssh if found
if(LIBSSH)
    target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBSSH})
    target_compile_definitions(${PROJECT_NAME} PRIVATE USE_LIBSSH=1)
endif()

# Install target
install(TARGETS ${PROJECT_NAME} DESTINATION bin)

# Testing setup
if(BUILD_TESTING)
    enable_testing()
    
    # Find Google Test
    find_package(GTest REQUIRED)
    
    # Test executable
    set(TEST_SOURCES
        tests/test_config_manager.cpp
        tests/test_security.cpp
        tests/test_utils.cpp
        tests/main_test.cpp
    )
    
    add_executable(${PROJECT_NAME}_test ${TEST_SOURCES})
    target_include_directories(${PROJECT_NAME}_test PRIVATE include)
    target_link_libraries(${PROJECT_NAME}_test 
        PRIVATE 
            GTest::gtest_main
            GTest::gmock_main
    )
    
    add_test(NAME UnitTests COMMAND ${PROJECT_NAME}_test)
endif()

# Create directories
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/docs)

# Copy configuration files
install(FILES configs/default_config.json DESTINATION etc/${PROJECT_NAME})

# Documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    
    add_custom_target(docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
endif()

# Packaging
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Secure and robust SSH VPN client")
set(CPACK_PACKAGE_VENDOR "MiniMax Agent")
set(CPACK_GENERATOR "TGZ;DEB")

include(CPack)