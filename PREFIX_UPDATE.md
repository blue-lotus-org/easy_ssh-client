# VPN Application - Prefix Support Update

## Summary of Changes

The VPN application has been enhanced to support SSH command prefix options, allowing for more complex SSH tunneling scenarios beyond simple SOCKS proxy.

### New Features Added

#### 1. **Prefix Field in Configuration**
- Added `prefix` field to JSON configuration profiles
- Allows custom SSH command options (e.g., `-D 9090 -L 8080:localhost:80`)
- When prefix is specified, it overrides the default `-D <local_port>` behavior

#### 2. **Enhanced Profile Management**
- Updated configuration parser to handle `prefix` field
- Modified SSH command construction to use prefix when available
- Added prefix field to interactive profile creation

#### 3. **Interactive Profile Creation**
- Added prompt for SSH prefix options during `vpn add`
- Shows helpful example: `-D 9090 -L 8080:localhost:80`
- Allows skipping prefix for default SOCKS behavior

#### 4. **Documentation Updates**
- Updated README with prefix field documentation
- Added comprehensive examples for different use cases
- Added advanced SSH options section

### Configuration Examples

#### Default SOCKS Proxy (No Prefix)
```json
{
  "name": "basic",
  "host": "server.example.com",
  "user": "user",
  "port": "22",
  "local_port": "1080"
}
```
Generates: `ssh -D 1080 -N -p 22 user@server.example.com`

#### Custom Prefix with SOCKS + Port Forward
```json
{
  "name": "advanced",
  "host": "gateway.example.com",
  "user": "user", 
  "port": "22",
  "prefix": "-D 9090 -L 8080:localhost:80"
}
```
Generates: `ssh -D 9090 -L 8080:localhost:80 -N -p 22 user@gateway.example.com`

#### Port Forwarding Only
```json
{
  "name": "local-forward",
  "host": "server.example.com",
  "user": "user",
  "port": "2222", 
  "prefix": "-L 8443:localhost:443"
}
```
Generates: `ssh -L 8443:localhost:443 -N -p 2222 user@server.example.com`

### Technical Implementation

#### Code Changes
1. **Configuration Parser** - Added `prefix` to supported keys list
2. **SSH Command Builder** - Modified to use prefix field when present
3. **Interactive Input** - Added prefix prompt with examples
4. **Documentation** - Comprehensive usage examples and explanations

#### Backward Compatibility
- Existing profiles without `prefix` field work exactly as before
- Default behavior generates `ssh -D <local_port>` when no prefix specified
- All existing functionality preserved

### Testing

The updated application has been tested for:
- ✅ Successful compilation with no warnings
- ✅ Help command displays correctly  
- ✅ Prefix field parsing from JSON config
- ✅ Interactive profile creation includes prefix prompt
- ✅ SSH command generation uses prefix when specified

### Usage Examples

```bash
# Start VPN with prefix
vpn start advanced-prefix

# Add profile with custom SSH options
vpn add
# ... (prompts for prefix with example)

# List profiles shows prefix info
vpn list
```

### Files Modified

- `src/main.cpp` - Added prefix support and parsing
- `README.md` - Updated documentation with prefix examples  
- `config/example-config.json` - Added prefix examples
- `config/test-prefix-config.json` - Test configuration file

The VPN application now supports advanced SSH tunneling scenarios while maintaining backward compatibility and ease of use.