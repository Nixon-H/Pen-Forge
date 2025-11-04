# Pen-Forge 🔨

**Pen-Forge** is an automated toolkit installer and manager designed for penetration testers, bug bounty hunters, and security researchers. It streamlines the installation of 150+ cybersecurity tools across multiple categories, handling dependencies, environment configuration, and system optimization automatically.

## ✨ Features

- **Comprehensive Tool Collection**: 150+ pre-configured security tools across 15 categories
- **Automated Dependency Management**: Handles Go, Rust, Python (pipx/pip3), and system packages
- **Smart Environment Setup**: Automatically configures shell environments (bash/zsh/profile)
- **Intelligent Swap Management**: Creates optimized swap files based on your system's RAM
- **Category-Based Installation**: Install tools by category or individually
- **Custom Tool Support**: Add and manage your own tool definitions
- **Force Re-installation**: Update existing tools with a single command
- **Interactive Menu System**: User-friendly terminal interface
- **Robust Error Handling**: Detailed logging and retry mechanisms
- **Multiple OS Support**: Kali Linux, Parrot OS, and Ubuntu

## 🎯 Tool Categories

1. **Reconnaissance & Enumeration** - Subdomain discovery, DNS enumeration, ASN mapping
2. **Web Crawling & Discovery** - URL extraction, JS parsing, archive mining
3. **SQL Injection (SQLi)** - Automated SQLi detection and exploitation
4. **XSS Detection** - Reflected, DOM, and Stored XSS scanners
5. **CRLF & HTTP Injection** - Header injection and HTTP splitting
6. **Directory & DNS Fuzzing** - Content discovery and brute forcing
7. **Port & Service Scanning** - Network reconnaissance and service detection
8. **Secrets & Credentials** - API keys, tokens, and credential discovery
9. **Authentication Issues** - CORS, auth bypass, origin detection
10. **URL & Parameter Analysis** - Parameter discovery and manipulation
11. **Vulnerability Scanning** - Template-based vuln detection (Nuclei, etc.)
12. **JavaScript Analysis** - Endpoint extraction from JS files
13. **Cloud & Infrastructure** - S3 buckets, subdomain takeovers, CDN detection
14. **Advanced Exploitation** - Advanced SQLi, complex exploits
15. **Misc Utilities** - Notifications, TLS analysis, timeouts

## 📦 Included Tools (Sample)

<details>
<summary>Click to expand tool list</summary>

### Reconnaissance
- Amass, Subfinder, Assetfinder, Crobat, Asnmap, Dnsx, Puredns, Chaos, Shuffledns

### Web Crawling
- Katana, Gospider, Hakrawler, Gau, Waybackurls, Waymore

### Vulnerability Scanning
- Nuclei, Dalfox, SQLMap, Jaeles, WPScan, Bbot

### Fuzzing
- Ffuf, Gobuster, Feroxbuster, Dirsearch, Arjun, Paramfinder

### JavaScript Analysis
- GetJS, Jsfinder, Jsubfinder, Jsluice, LinkFinder, Subjs

### Port Scanning
- Naabu, Masscan, Httpx, Httprobe, Gowitness

### Secrets Discovery
- Gitleaks, Trufflehog, Cariddi, Gitrepoenum

### And many more...
</details>

## 🚀 Quick Start

### Prerequisites

- **Supported OS**: Kali Linux, Parrot OS, or Ubuntu
- **Sudo Access**: Required for system package installation
- **Disk Space**: Minimum 15GB free space recommended
- **Internet Connection**: Required for downloading tools

### Installation

```bash
# Clone the repository
git clone https://github.com/Nixon-H/pen-forge.git
cd pen-forge

# Make the script executable
chmod +x pen-forge.sh

# Run the installer
./pen-forge.sh
```

### First Run

When you first run Pen-Forge, you'll see an interactive menu:

```
========================================
          Pen-Forge Toolkit Menu            
========================================
1. Install Toolkit (Full)
2. Manual Tool Installation
3. Uninstall Tools
4. Clean Logs
5. Custom Tool Management
6. Help
7. Exit
-----------------------------------------
```

## 📖 Usage Guide

### Option 1: Full Installation (Recommended for First-Time Users)

Installs all 150+ tools automatically:

1. Select option `1` from the main menu
2. Choose whether to force re-installation of existing tools (default: No)
3. The script will:
   - Update system packages
   - Install prerequisites (build tools, libraries)
   - Set up Go, Rust, and Python environments
   - Create/optimize swap file (16GB target)
   - Install all tools across all categories
   - Configure shell environment variables
   - Download essential wordlists

**Estimated Time**: 60-120 minutes depending on your system and internet speed

**Post-Installation**: Run `source ~/.bashrc` (or `~/.zshrc`) to apply environment changes

### Option 2: Manual Tool Installation

Install tools selectively by category:

1. Select option `2` from the main menu
2. On first run, prerequisites will be installed automatically
3. Choose a category (1-16) to view tools in that category
4. Select individual tools to install
5. Each tool shows:
   - Purpose and description
   - What it finds/detects
   - Installation command (visible during install)

**Best For**: Users who want specific tools or limited disk space

### Option 3: Uninstall Tools

Completely removes the toolkit:

1. Select option `3` from the main menu
2. Confirm the uninstallation (default: No)
3. The script will:
   - Remove all installed tools
   - Delete Go and Rust installations
   - Clean shell configuration files
   - Remove prerequisite packages
   - Reconfigure swap to a smaller, system-appropriate size
   - Generate a detailed log at `/tmp/toolkit_uninstall_<timestamp>.log`

**Warning**: This removes ALL toolkit components and reconfigures your system

### Option 4: Clean Logs

Removes temporary files and logs:

- **Clean Script Logs from /tmp/**: Removes pen-forge-install.log, toolkit_uninstall_*.log
- **Clean 'wget-log' files**: Removes wget-log* from current directory
- **Clean ALL**: Performs both cleanup operations

### Option 5: Custom Tool Management

Add, install, or remove your own tool definitions:

#### Adding a Custom Tool

1. Select option `5` → `2` from menus
2. Provide the following information:
   - **Tool Key**: Unique identifier (e.g., `mytool`)
   - **Display Name**: How it appears in menus (e.g., `My Awesome Scanner`)
   - **Category**: Grouping identifier (e.g., `custom-recon`)
   - **Install Command**: Full shell command to install
   - **Short Description**: Brief purpose
   - **Long Description**: What the tool finds

**Example**:
```
Tool Key: mytool
Display Name: My Awesome Scanner
Category: custom-recon
Install Command: go install github.com/user/mytool@latest
Short Description: Advanced web scanner
Long Description: Hidden directories, API endpoints, misconfigurations
```

Custom tools are saved to `~/.pen-forge-custom.db` and persist across sessions.

#### Installing Custom Tools

1. Select option `5` → `1` from menus
2. Choose from your added custom tools
3. Installation uses the same robust mechanism as built-in tools

#### Managing Custom Tools

1. Select option `5` → `3` from menus
2. View all custom tool definitions
3. Remove definitions you no longer need

**Note**: Removing a definition does NOT uninstall the tool itself

## 🔧 Advanced Features

### Force Re-installation

When running "Install Toolkit (Full)", you can force re-installation of ALL tools:

```
Force re-installation of all tools? (y/N): y
```

This is useful for:
- Updating tools to latest versions
- Fixing broken installations
- Refreshing after system changes

### Environment Variables

Pen-Forge automatically configures these in your shell:

```bash
export GOROOT=/usr/local/go
export GOPATH=$HOME/Tools/Go-Tools
export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH
```

### Swap Memory Optimization

The script intelligently manages swap:

**During Installation**:
- Creates 16GB swap file (optimal for tool compilation)
- Handles both standard and btrfs filesystems
- Persists configuration in `/etc/fstab`

**During Uninstallation**:
- Removes 16GB swap file
- Creates system-appropriate swap based on RAM:
  - < 2GB RAM: 4GB swap
  - 2-8GB RAM: Equal to RAM
  - > 8GB RAM: 8GB swap

### Binary Name Mapping

Some tools have display names different from their binary names. Pen-Forge automatically handles this:

```bash
BINARY_NAME_MAP=(
  ["xnlinkfinder"]="xnLinkFinder"
  ["golinkfinder"]="GoLinkFinder"
  ["gxss"]="Gxss"
  ["uforall"]="UForAll"
  ["wcvs"]="Web-Cache-Vulnerability-Scanner"
)
```

### Logging and Debugging

- **Installation logs**: `/tmp/pen-forge-install.log`
- **Uninstall logs**: `/tmp/toolkit_uninstall_<timestamp>.log`
- **Detailed command tracking**: All commands are logged with timestamps

## 🛠️ Troubleshooting

### Installation Hangs or Fails

**Symptom**: Spinner runs for 2+ minutes without progress

**Solutions**:
1. Press `Ctrl+C` to abort the current installation
2. Check `/tmp/pen-forge-install.log` for detailed error messages
3. Common issues:
   - Network timeouts (retry installation)
   - Out of memory (script will auto-create swap)
   - Package conflicts (run `sudo apt-get --fix-broken install`)

### Tool Not Found After Installation

**Symptom**: Tool shows as installed but command not found

**Solutions**:
1. Reload your shell environment:
   ```bash
   source ~/.bashrc  # or ~/.zshrc
   # OR restart your terminal
   ```

2. Check if the binary name differs:
   ```bash
   ls $HOME/Tools/Go-Tools/bin/
   ls $HOME/.local/bin/
   ```

3. Manually verify installation:
   ```bash
   which <toolname>
   command -v <toolname>
   ```

### Permission Errors

**Symptom**: "Permission denied" or "Cannot write to..."

**Solutions**:
1. Ensure you have sudo access:
   ```bash
   sudo -v
   ```

2. Check home directory permissions:
   ```bash
   ls -ld $HOME
   # Should show your user as owner
   ```

3. Fix permissions if needed:
   ```bash
   sudo chown -R $USER:$USER $HOME
   ```

### Swap Creation Fails

**Symptom**: "Failed to create swap file"

**Solutions**:
1. Check available disk space:
   ```bash
   df -h /
   ```

2. For btrfs filesystems, ensure subvolume creation is supported:
   ```bash
   sudo btrfs filesystem usage /
   ```

3. Manually create swap and re-run:
   ```bash
   sudo fallocate -l 16G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

### APT Lock Errors

**Symptom**: "Could not get lock /var/lib/dpkg/lock"

**Solution**: The script automatically handles this, but if it persists:
```bash
sudo killall apt apt-get
sudo rm /var/lib/apt/lists/lock
sudo rm /var/cache/apt/archives/lock
sudo rm /var/lib/dpkg/lock*
sudo dpkg --configure -a
```

## 📂 Directory Structure

After installation, your system will have:

```
$HOME/
├── Tools/
│   ├── Go-Tools/
│   │   └── bin/          # Go-based tool binaries
│   └── Wordlists/        # Downloaded wordlists
├── .cargo/               # Rust installation
├── .local/
│   └── bin/              # pipx-installed tools
├── .gf/                  # GF pattern files
└── build-temp/           # Temporary build directory (cleaned after install)

/usr/local/
├── go/                   # Go installation
└── bin/                  # System-wide binaries (massdns, etc.)
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Adding New Tools to the Database

Tools in Pen-Forge are defined in the `TOOLS_DB` associative array. Each entry follows this format:

```bash
["toolkey"]="category|DisplayName|install_command|short_description|long_description"
```

#### Step-by-Step Guide:

1. **Fork the repository** and clone your fork

2. **Open `pen-forge.sh`** and locate the `declare -A TOOLS_DB=(` section

3. **Add your tool entry** following the existing pattern:

```bash
["yourtool"]="category|YourTool|go install github.com/user/yourtool@latest|Brief purpose|What it finds/detects"
```

#### Field Breakdown:

| Field | Description | Example |
|-------|-------------|---------|
| `toolkey` | Unique identifier (lowercase, usually the binary name) | `subfinder` |
| `category` | Tool category (see categories below) | `recon-enum` |
| `DisplayName` | User-facing name (can have capitals/spaces) | `Subfinder` |
| `install_command` | Full installation command | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `short_description` | Brief one-line purpose | `Passive subdomain enumeration` |
| `long_description` | What the tool outputs/finds | `Subdomains from 30+ sources` |

#### Valid Categories:

- `recon-enum` - Reconnaissance & Enumeration
- `web-crawl` - Web Crawling & Discovery
- `sqli-detect` - SQL Injection
- `xss-detect` - XSS Detection
- `http-inject` - CRLF & HTTP Injection
- `fuzzing` - Directory & DNS Fuzzing
- `scanning` - Port & Service Scanning
- `secrets` - Secrets & Credentials
- `auth-test` - Authentication Issues
- `url-analysis` - URL & Parameter Analysis
- `vuln-scan` - Vulnerability Scanning
- `js-analysis` - JavaScript Analysis
- `cloud` - Cloud & Infrastructure
- `exploit` - Advanced Exploitation
- `misc-util` - Misc Utilities
- `proxy-manip` - Proxy Manipulation
- `osint-recon` - OSINT Reconnaissance
- `sub-takeover` - Subdomain Takeover

#### Example Entries:

**Go-based tool:**
```bash
["nuclei"]="vuln-scan|Nuclei|go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|Template-based vulnerability scanner|CVEs, RCE, SSRF, LFI, auth bypass"
```

**Python/pipx tool:**
```bash
["arjun"]="fuzzing|Arjun|pipx install arjun|HTTP parameter discovery suite|Hidden GET/POST parameters"
```

**Binary download:**
```bash
["feroxbuster"]="fuzzing|Feroxbuster|set -e; wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip -O /tmp/ferox.zip; unzip -o /tmp/ferox.zip -d /tmp; sudo dpkg -i /tmp/feroxbuster*.deb; rm /tmp/ferox.zip /tmp/feroxbuster*.deb|Recursive content discovery|Hidden files and directories"
```

**Source compilation:**
```bash
["massdns"]="recon-enum|MassDNS|( rm -rf \"$HOME/build-temp/massdns\" && timeout $GIT_CLONE_TIMEOUT git clone --depth 1 https://github.com/blechschmidt/massdns.git \"$HOME/build-temp/massdns\" && cd \"$HOME/build-temp/massdns\" && make && sudo cp bin/massdns /usr/local/bin/ )|High-speed DNS resolver|Resolved IP addresses for domain lists"
```

4. **Add to automated install section** (if applicable):

   Locate the appropriate section in the `install_tools()` function:
   - For Go tools: Around line 1100+ in "SECTION 3: Installing Go-based tools"
   - For Python tools: Around line 1300+ in "SECTION 4: Installing Python tools"
   - For Rust tools: Around line 1350+ in "SECTION 5: Installing Rust tools"
   - For source builds: Around line 1400+ in "SECTION 6: Building tools from source"

   Add your installation line:
   ```bash
   install_tool "YourTool" "yourtool" "go install github.com/user/yourtool@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
   ```

5. **Handle special binary names** (if needed):

   If your tool's display name differs from its binary name, add to `BINARY_NAME_MAP`:
   ```bash
   declare -gA BINARY_NAME_MAP=(
       ["yourtool"]="YourActualBinaryName"
   )
   ```

6. **Test your addition:**
   ```bash
   # Test manual installation
   ./pen-forge.sh
   # Choose: 2 → Find your category → Install your tool
   
   # Test full installation
   ./pen-forge.sh
   # Choose: 1 → Verify your tool installs without errors
   
   # Verify the tool works
   yourtool --help
   ```

7. **Submit a pull request** with:
   - Tool name and purpose in PR title
   - Link to tool's GitHub/official page
   - Category you assigned it to
   - Confirmation that you tested the installation

### Reporting Issues

When reporting issues, please include:
- Operating system and version
- Error messages (from logs)
- Steps to reproduce
- Expected vs actual behavior

### Suggesting Features

Open an issue with:
- Clear description of the feature
- Use case / benefit
- Proposed implementation (if applicable)

## ⚠️ Important Notes

### System Impact

- **Swap File**: Creates a 16GB swap file during installation
- **Disk Space**: Requires ~10GB for full installation
- **System Packages**: Installs development libraries and tools
- **Shell Configuration**: Modifies `.bashrc`/`.zshrc`/`.profile`

### Security Considerations

- Always verify tool sources before installation
- Tools are downloaded from official repositories
- Custom tools are user-defined and not verified by Pen-Forge
- Use tools responsibly and legally

### Performance

- **First Installation**: 60-120 minutes
- **Manual Installation**: 1-5 minutes per tool
- **Memory Usage**: Up to 2GB during compilation (limited by script)

## 🙏 Acknowledgments

- All tool authors and maintainers
- The cybersecurity research community
- Contributors and testers

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/Nixon-H/pen-forge/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Nixon-H/pen-forge/discussions)

## ⚖️ Disclaimer

This toolkit is intended for **legal security research, penetration testing, and educational purposes only**. Users are solely responsible for ensuring their usage complies with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this toolkit.

---

**Built with ❤️ by [Nixon-H](https://github.com/Nixon-H)**
