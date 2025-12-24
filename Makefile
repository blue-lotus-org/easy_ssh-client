# VPN SOCKS Proxy Manager - Makefile

CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra
TARGET = vpn
SRC = src/main.cpp

.PHONY: all clean install uninstall test help

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/$(TARGET)

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "Note: Configuration files are preserved in ~/.config/vpn/"

test: $(TARGET)
	./$(TARGET) help
	./$(TARGET) list

help:
	@echo "VPN SOCKS Proxy Manager - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all       - Build the VPN application (default)"
	@echo "  clean     - Remove compiled binary"
	@echo "  install   - Install to system (/usr/local/bin)"
	@echo "  uninstall - Remove from system"
	@echo "  test      - Build and test the application"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make           # Build the application"
	@echo "  make install   # Install to system"
	@echo "  make test      # Build and test"
	@echo "  make clean     # Clean build artifacts"