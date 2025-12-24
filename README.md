# VPN - SSH SOCKS Proxy Manager

A lightweight C++ application that creates secure SOCKS5 proxies by tunneling through SSH connections. Manage multiple SSH server profiles with a simple CLI interface.

## Features

- 🔒 **Secure SSH Tunneling**: Create SOCKS5 proxies through SSH connections
- 📊 **Multiple Profiles**: Manage multiple SSH server configurations
- 🔐 **Flexible Authentication**: Support for SSH keys and password authentication
- 🎯 **Simple CLI**: Clean command-line interface with colored output
- 📝 **JSON Configuration**: Human-readable configuration file
- 📋 **Process Management**: Track and manage running VPN connections
- 🔍 **Status Monitoring**: Real-time status of all connections
- 📖 **Easy Setup**: Interactive profile creation and management

## Installation

### Quick Install

```bash
# Clone or download the vpn-app directory
cd vpn-app

# Run the installer
./scripts/install.sh
```

### Manual Installation

```bash
# Compile the application
cd src
g++ -o vpn main.cpp -std=c++17 -O2 -Wall -Wextra

# Install to system (requires sudo)
sudo cp vpn /usr/local/bin/

# Or install to user directory
mkdir -p ~/.local/bin
cp vpn ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"
```

## Usage

### Basic Commands

```bash
# Show help
vpn help

# List all configured profiles
vpn list

# Add a new profile interactively
vpn add

# Start VPN connection
vpn start myprofile

# Stop VPN connection
vpn stop myprofile

# Check status of running connections
vpn status
```

### Configuration

The configuration file is located at `~/.config/vpn/config.json`:

```json
[
  {
    "name": "us-east",
    "host": "server1.example.com",
    "user": "john",
    "port": "22",
    "local_port": "1080"
  },
  {
    "name": "eu-west",
    "host": "server2.example.com",
    "user": "john",
    "port": "22",
    "local_port": "1081",
    "identity_file": "/home/john/.ssh/id_rsa"
  }
]
```

#### Configuration Fields

- `name`: Unique profile identifier
- `host`: SSH server hostname or IP
- `user`: SSH username
- `port`: SSH server port (default: 22)
- `local_port`: Local SOCKS proxy port (default: 1080)
- `identity_file`: Path to SSH private key (optional)
- `prefix`: SSH command prefix options (e.g., '-D 9090 -L 8080:localhost:80')

### Authentication

#### Method 1: Environment Variable (Recommended)
```bash
export VPN_SSH_PASS='your-ssh-password'
vpn start myprofile
```

#### Method 2: Interactive Input
```bash
vpn start myprofile
# Will prompt for password
```

#### Method 3: SSH Keys
Configure `identity_file` in your profile configuration.

### Using the SOCKS Proxy

Once connected, configure your applications to use the SOCKS proxy:

#### Command Line (curl)
```bash
curl --socks5 localhost:1080 http://ifconfig.me
```

#### Browser (Firefox)
1. Settings → Network Settings → Manual proxy configuration
2. SOCKS Host: `localhost`, Port: `1080`
3. Select "SOCKS v5"

#### Environment Variables
```bash
export http_proxy=socks5://localhost:1080
export https_proxy=socks5://localhost:1080
```

### Advanced SSH Options

The `prefix` field allows you to specify custom SSH command options beyond the default SOCKS proxy setup. This enables complex tunneling scenarios:

#### SOCKS Proxy with Port Forwarding
```json
{
  "name": "forward",
  "host": "gateway.example.com",
  "user": "user",
  "prefix": "-D 9090 -L 8080:localhost:80"
}
```
This creates a SOCKS proxy on port 9090 and forwards local port 8080 to remote localhost:80.

#### Local Port Forwarding Only
```json
{
  "name": "local-only",
  "host": "server.example.com",
  "user": "user",
  "prefix": "-L 8080:localhost:80"
}
```
This sets up local port forwarding without creating a SOCKS proxy.

#### Remote Port Forwarding
```json
{
  "name": "remote-forward",
  "host": "server.example.com",
  "user": "user",
  "prefix": "-R 9090:localhost:8080"
}
```
This forwards remote port 9090 to local port 8080.

#### Multiple Options
```json
{
  "name": "complex",
  "host": "gateway.example.com",
  "user": "user",
  "prefix": "-D 9090 -L 8080:localhost:80 -L 443:localhost:443"
}
```
This combines SOCKS proxy with multiple local port forwards.

**Note**: When using `prefix`, the `local_port` field is ignored since the port is specified within the prefix options.

## Examples

### Setting Up Profiles

```bash
# Add profile interactively
$ vpn add
Adding new VPN profile...
Profile name: office
SSH host: office.example.com
SSH user: developer
SSH port (default 22): 
Local SOCKS port (default 1080): 
SSH identity file (optional, press Enter to skip): 
SSH prefix options (optional, e.g., '-D 9090 -L 8080:localhost:80', press Enter for default SOCKS): 
✓ Profile 'office' added successfully
```

### Starting and Managing Connections

```bash
# Start VPN
$ vpn start office
Connecting to developer@office.example.com:22...
✓ Connected to 'office' on port 1080

# Check status
$ vpn status
Running VPN connections:
  office (PID: 12345, Port: 1080)

# List all profiles
$ vpn list
Configured VPN profiles:
  office - Running (developer@office.example.com:22)
  home - Stopped (user@home.example.com:22)

# Stop VPN
$ vpn stop office
Stopping VPN 'office'...
✓ VPN 'office' stopped
```

### Using with Applications

```bash
# Test proxy with curl
curl --socks5 localhost:1080 http://httpbin.org/ip

# Test with wget
wget --proxy=on --proxy-type=socks5 --proxy=localhost:1080 http://httpbin.org/ip

# SSH through proxy (requires additional tools)
ssh -o ProxyCommand="nc -X 5 -x localhost:1080 %h %p" target-server
```

## Troubleshooting

### Common Issues

#### Connection Fails
- Check SSH credentials
- Verify firewall settings
- Ensure SSH server allows port forwarding

#### Port Already in Use
```bash
# Check what's using the port
lsof -i :1080

# Use a different local port in your profile
```

#### Authentication Issues
- Verify SSH password or key file
- Check SSH server logs
- Ensure user has SSH access

### Logs

VPN logs are stored in `~/.cache/vpn/vpn.log`:

```bash
# View recent logs
tail -f ~/.cache/vpn/vpn.log

# Check for errors
grep ERROR ~/.cache/vpn/vpn.log
```

## Security Considerations

- **Password Storage**: Never store passwords in plain text configuration
- **SSH Keys**: Prefer SSH key authentication over passwords
- **Port Binding**: VPN only binds to localhost (127.0.0.1) for security
- **Process Isolation**: Each VPN connection runs in isolation
- **Log Files**: Logs don't contain sensitive information

## Uninstallation

```bash
# Run uninstaller
./scripts/uninstall.sh

# Manual removal
sudo rm /usr/local/bin/vpn
rm -rf ~/.config/vpn
rm -rf ~/.cache/vpn
```

## Technical Details

### Dependencies
- C++17 standard library
- POSIX system calls
- Standard utilities: ssh, sh

### Architecture
- **Configuration Manager**: Handles JSON parsing and profile management
- **Process Manager**: Manages SSH tunnel processes and PIDs
- **VPN Manager**: Orchestrates connection lifecycle
- **Authentication**: Secure password handling with terminal echo control

### System Requirements
- Linux or macOS (POSIX-compliant)
- SSH client installed
- C++17 compiler (g++ 7+)

## License

Included MIT and this project is provided **as-is** for educational and personal use.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files in `~/.cache/vpn/vpn.log`
3. Verify SSH connectivity manually: `ssh user@host`

---

**Author**: LotusChain Innovation  
**Version**: 1.0.0