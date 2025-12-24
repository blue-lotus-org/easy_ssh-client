#!/bin/bash

# VPN Uninstallation Script

set -e

echo "🗑️  VPN SOCKS Proxy Manager - Uninstallation"
echo "============================================"

# Stop all running VPN processes first
echo "🛑 Stopping all VPN processes..."
pkill -f "ssh.*-D.*-N" 2>/dev/null || true

# Remove PID files
rm -f "$HOME/.cache/vpn/pids.json"

# Check for system or user installation
if [[ -f "/usr/local/bin/vpn" ]]; then
    INSTALL_DIR="/usr/local/bin"
    SYSTEM_INSTALL=true
else
    INSTALL_DIR="$HOME/.local/bin"
    SYSTEM_INSTALL=false
fi

# Remove the binary
echo "🗑️  Removing VPN binary..."
if [[ -f "$INSTALL_DIR/vpn" ]]; then
    rm -f "$INSTALL_DIR/vpn"
    echo "✓ Removed binary from $INSTALL_DIR"
else
    echo "⚠️  VPN binary not found in $INSTALL_DIR"
fi

# Ask about configuration files
echo ""
read -p "Remove configuration files? (y/N): " remove_config
if [[ "$remove_config" =~ ^[Yy]$ ]]; then
    echo "🗑️  Removing configuration files..."
    rm -rf "$HOME/.config/vpn"
    rm -rf "$HOME/.cache/vpn"
    echo "✓ Removed configuration and cache directories"
else
    echo "📁 Configuration files preserved:"
    echo "  - $HOME/.config/vpn/"
    echo "  - $HOME/.cache/vpn/"
fi

echo ""
echo "✅ Uninstallation complete!"
echo ""

# Check if PATH needs updating
if [[ "$SYSTEM_INSTALL" = false ]]; then
    echo "💡 Note: If you added ~/.local/bin to your PATH, you may want to remove it from:"
    echo "  - ~/.bashrc"
    echo "  - ~/.zshrc"
fi