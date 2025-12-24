#!/bin/bash

# VPN Installation Script

set -e

echo "🚀 VPN SOCKS Proxy Manager - Installation"
echo "=========================================="

# Check if running as root for system installation
if [[ $EUID -eq 0 ]]; then
    INSTALL_DIR="/usr/local/bin"
    SYSTEM_INSTALL=true
else
    INSTALL_DIR="$HOME/.local/bin"
    SYSTEM_INSTALL=false
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$HOME/.config/vpn"
mkdir -p "$HOME/.cache/vpn"

# Compile the C++ application
echo "🔨 Compiling VPN application..."
cd src
g++ -o vpn main.cpp -std=c++17 -O2 -Wall -Wextra
cd ..

# Install the binary
echo "📦 Installing VPN binary..."
cp src/vpn "$INSTALL_DIR/vpn"

# Set execute permissions
chmod +x "$INSTALL_DIR/vpn"

# Add to PATH if not system install
if [[ "$SYSTEM_INSTALL" = false ]]; then
    echo ""
    echo "⚠️  Note: For non-system installation, add this to your PATH:"
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "You can add this to your ~/.bashrc or ~/.zshrc"
fi

# Create default configuration if it doesn't exist
if [[ ! -f "$HOME/.config/vpn/config.json" ]]; then
    echo "📝 Creating default configuration..."
    cat > "$HOME/.config/vpn/config.json" << 'EOF'
[
  {
    "name": "example",
    "host": "your-server.com",
    "user": "your-username",
    "port": "22",
    "local_port": "1080"
  }
]
EOF
fi

# Create log file
touch "$HOME/.cache/vpn/vpn.log"

echo ""
echo "✅ Installation complete!"
echo ""
echo "🎯 Quick start:"
echo "  1. Edit configuration: $HOME/.config/vpn/config.json"
echo "  2. Or add profiles interactively: vpn add"
echo "  3. Start VPN: vpn start <profile_name>"
echo "  4. Check status: vpn status"
echo "  5. Get help: vpn help"
echo ""
echo "🔐 Authentication:"
echo "  - Set password: export VPN_SSH_PASS='your-password'"
echo "  - Or enter interactively when starting VPN"
echo ""
echo "📚 Documentation: vpn help"