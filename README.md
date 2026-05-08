# JESUR - Enhanced SMB Share Scanner

**Version**: 2.1.0
**Developer**: Cuma KURT
**GitHub**: https://github.com/cumakurt/Jesur
**LinkedIn**: https://www.linkedin.com/in/cuma-kurt-34414917/

**Professional Penetration Testing Tool for SMB Share Discovery and Analysis**

JESUR is a comprehensive Python application designed to scan SMB shares across networks, analyze access permissions, detect sensitive files, and generate detailed reports. Built for penetration testers and security professionals.

##  Features

### Core Capabilities
- **Automatic SMB Share Discovery** - Scan entire networks or specific IP ranges
- **Multiple Authentication Methods** - Anonymous, Username/Password, NTLM Hash
- **True Parallel Scanning** - Multi-threaded scanning with configurable thread count
- **Sensitive Content Detection** - Advanced matching for credentials, cloud keys, tokens, connection strings, and private key material
- **High-Value File Discovery** - Finds pentest-relevant credentials, dumps, cloud/devops configs, backup exports, and assessment artifacts
- **Professional Reporting** - Unified interactive HTML dashboard with charts, filtering, severity labels, evidence links, and developer footer
- **Multiple Export Formats** - HTML, JSON, CSV exports
- **Configuration File Support** - Enterprise-ready configuration management
- **Real-time Progress** - Live progress tracking with ETA calculation

### Advanced Features
- **File Content Analysis** - Supports PDF, DOCX, XLSX, Text, and more
- **Severity Classification** - Marks findings as Critical, High, or Medium in HTML and CSV outputs
- **Path-Aware Detection** - Recognizes high-value locations such as `.aws/credentials`, `.ssh/id_*`, `.kube/config`, Docker config, Windows registry hives, and `ntds.dit`
- **Token & Secret Signatures** - Detects AWS, Google, GitHub, GitLab, Slack, JWT, basic-auth URLs, DB connection strings, VPN secrets, and PuTTY/private keys
- **Smart Filtering** - Filter by extension, size, filename patterns
- **Rate Limiting** - Control scan speed to avoid network overload
- **IP Exclusion Lists** - Skip specific IPs or networks
- **Share Filtering** - Include/exclude specific shares
- **Geo-location Scanning** - Scan IP ranges by country code
- **Timeout Protection** - Per-host timeout to prevent hangs
- **Bounded Scheduling** - Keeps large scans memory-safe by limiting pending host work
- **Graceful Shutdown** - Safe interruption with Ctrl+C

## 📋 Table of Contents

- [Installation](#installation)
  - [Option 1: Docker Installation](#option-1-docker-installation-recommended)
  - [Option 2: Traditional Installation](#option-2-traditional-installation)
  - [📖 Detailed Installation Guide](INSTALL.md)
- [Quick Start](#quick-start)
- [Configuration File](#configuration-file)
- [Usage Examples](#usage-examples)
  - [Docker Usage Examples](#docker-usage-examples)
- [Command Line Options](#command-line-options)
- [Sensitive File Detection](#sensitive-file-detection)
- [Sensitive Content Detection](#sensitive-content-detection)
- [Output Formats](#output-formats)
- [Performance Tuning](#performance-tuning)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🔧 Installation

> 📖 **For detailed installation instructions**, see [INSTALL.md](INSTALL.md) - Complete guide covering Docker, Python virtual environments, system-wide installation, and troubleshooting.

### Prerequisites
- Python 3.9 or higher
- Network access to target SMB shares
- Docker (optional, for containerized deployment)

### Option 1: Docker Installation (Recommended)

Docker provides an isolated environment with all dependencies pre-installed.

#### Quick Start with Docker

**⚠️ IMPORTANT: Volume Mounts Required!**

Docker containers are temporary. **You MUST use volume mounts (`-v`)** to save reports and downloaded files to your host machine, otherwise they will be lost when the container stops.

```bash
# Clone the repository
git clone https://github.com/cumakurt/Jesur.git
cd Jesur

# Build the Docker image
docker build -t jesur:latest .

# Create output directories on YOUR machine (not in container)
mkdir -p out_download reports

# Run a scan with volume mounts
# The -v flags map container directories to YOUR local directories
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u username -p password

# After scan, check YOUR local directories:
ls -la out_download/  # Downloaded sensitive files are HERE
ls -la reports/      # HTML, JSON, CSV reports are HERE
```

**What the volume mounts do:**
- `-v $(pwd)/out_download:/app/out_download` → Saves downloaded files to `./out_download/` on **your machine**
- `-v $(pwd)/reports:/app/reports` → Saves reports to `./reports/` on **your machine**
- Without `-v` flags, files stay inside container and are **deleted** when container stops!

#### Docker Compose (Easier Management)

```bash
# Using docker-compose.yml
docker-compose run --rm jesur 192.168.1.0/24 -u username -p password

# Or modify docker-compose.yml and run:
docker-compose up
```

#### Docker Examples

**⚠️ REMEMBER: Always use `-v` (volume mounts) to save files to your host machine!**

**Single IP Scan:**
```bash
# Create directory on YOUR machine first
mkdir -p out_download

# Run scan - files saved to YOUR ./out_download directory
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest 192.168.1.1 -u admin -p password123

# Verify files are on YOUR machine (not in container)
ls -la out_download/
```

**Network Scan with Config File:**
```bash
# Copy and edit config file on YOUR machine
cp jesur.conf.example jesur.conf
nano jesur.conf

# Create output directories on YOUR machine
mkdir -p out_download reports

# Run with mounted config and output directories
docker run --rm --network host \
  -v $(pwd)/jesur.conf:/app/jesur.conf:ro \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest

# All files are saved to YOUR local directories
ls -la out_download/ reports/
```

**Scan with Custom Output Directory (Absolute Paths):**
```bash
# Use absolute paths for custom locations on YOUR machine
docker run --rm --network host \
  -v /home/user/my_scans/out_download:/app/out_download \
  -v /home/user/my_scans/reports:/app/reports \
  jesur:latest 10.0.0.0/24 -u user -p pass --output-name custom_scan

# Files saved to /home/user/my_scans/ on YOUR machine
ls -la /home/user/my_scans/out_download/
ls -la /home/user/my_scans/reports/
```

**Windows Example:**
```bash
# Windows - use forward slashes or escaped backslashes
docker run --rm --network host \
  -v C:/Users/YourName/scans/out_download:/app/out_download \
  -v C:/Users/YourName/scans/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u user -p pass

# Files saved to C:\Users\YourName\scans\ on YOUR Windows machine
```

**❌ WRONG - Files Will Be Lost:**
```bash
# DON'T DO THIS - No volume mounts!
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u user -p pass
# All reports and downloads stay inside container and are DELETED when container stops!
```

**List Shares Only:**
```bash
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u guest -p "" --list-shares
```

**Verbose Mode with Rate Limiting:**
```bash
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest 192.168.1.0/24 -u user -p pass \
  --verbose --rate-limit 10 --threads 20
```

**Using Docker Compose with Custom Command:**
```yaml
# Edit docker-compose.yml
services:
  jesur:
    # ... existing config ...
    command: ["python3", "Jesur.py", "192.168.1.0/24", "-u", "user", "-p", "pass", "--verbose"]
```

Then run:
```bash
docker-compose up
```

#### Docker Volume Mounts

**⚠️ CRITICAL: Volume mounts are REQUIRED to save files to your host machine!**

Volume mounts (`-v`) map container directories to directories on **YOUR computer**. Without them, all files are lost when container stops.

**Required Volume Mounts:**

- **`/app/out_download`** → Maps to your local directory for downloaded sensitive files
  ```bash
  -v $(pwd)/out_download:/app/out_download
  # Files saved in container's /app/out_download appear in YOUR ./out_download/
  ```

- **`/app/reports`** → Maps to your local directory for generated reports (HTML, JSON, CSV)
  ```bash
  -v $(pwd)/reports:/app/reports
  # Reports saved in container's /app/reports appear in YOUR ./reports/
  ```

**Optional Volume Mounts:**

- **`/app/jesur.conf`** → Configuration file (read-only recommended)
  ```bash
  -v $(pwd)/jesur.conf:/app/jesur.conf:ro
  # :ro = read-only, prevents container from modifying your config file
  ```

- **`/app/networks.txt`** → Network list file if using `--file` option
  ```bash
  -v $(pwd)/networks.txt:/app/networks.txt:ro
  ```

**Complete Example with All Mounts:**
```bash
# 1. Create directories on YOUR machine
mkdir -p out_download reports

# 2. Run with all volume mounts
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/jesur.conf:/app/jesur.conf:ro \
  jesur:latest 192.168.1.0/24 -u user -p pass

# 3. Verify files are on YOUR machine
ls -la out_download/  # Downloaded files HERE
ls -la reports/       # Reports HERE
```

**Understanding Volume Mount Syntax:**
```bash
-v HOST_PATH:CONTAINER_PATH
-v $(pwd)/out_download:/app/out_download
   ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^
   Your machine        Inside container
```

**Verifying Volume Mounts Work:**
```bash
# Run a test scan
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest 127.0.0.1 -u guest -p "" --list-shares

# Check if directory exists on YOUR machine
ls -la out_download/

# If empty, that's normal for list-shares. Try a real scan to see files appear.
```

#### Docker Network Modes

**Host Network (Recommended for SMB):**
```bash
docker run --rm --network host ...
```
- Direct access to SMB ports (445, 139)
- No port mapping needed
- Best performance

**Bridge Network (Alternative):**
```bash
docker run --rm -p 445:445 -p 139:139 ...
```
- Requires port mapping
- May have connectivity issues

### Option 2: Traditional Installation

#### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/cumakurt/Jesur.git
cd Jesur

# Install requirements
pip install -r requirements.txt
```

#### Required Libraries
```
pysmb==1.2.10
jinja2==3.1.3
ipaddress==1.0.23
python-docx==0.8.11
openpyxl==3.1.2
pdfplumber==0.10.3
python-magic==0.4.27
requests==2.31.0
```

**Note:** On Linux, you may need to install `libmagic` system library:
```bash
# Debian/Ubuntu
sudo apt-get install libmagic1

# CentOS/RHEL
sudo yum install file-devel

# macOS
brew install libmagic
```

##  Quick Start

### Basic Network Scan

```bash
# Scan a single network
python3 Jesur.py 192.168.1.0/24

# Scan from file
python3 Jesur.py -f networks.txt

# Scan with authentication
python3 Jesur.py 192.168.1.0/24 -u administrator -p Password123 -d DOMAIN
```

### Using Configuration File

```bash
# Edit jesur.conf with your settings
# Then run without parameters (uses config defaults)
python3 Jesur.py

# Or override config with command line
python3 Jesur.py --config custom.conf 192.168.1.0/24 --threads 50
```

## ⚙️ Configuration File

JESUR supports a configuration file (`jesur.conf`) for enterprise deployments. All parameters can be set in the config file or overridden via command line.

### Example Configuration (`jesur.conf`)

```ini
[scan]
network=192.168.1.0/24
threads=20
rate_limit=0
host_timeout=180

[auth]
username=guest
password=
domain=WORKGROUP

[filters]
include_ext=
exclude_ext=.log,.tmp
min_size=0
max_size=50485760
max_read_bytes=1048576
exclude_shares=IPC$,ADMIN$,C$
include_admin_shares=false

[output]
output_json=true
output_csv=false
output_name=jesur
quiet=false
verbose=false
```

### Configuration Sections

- **`[scan]`** - Scan parameters (network, threads, timeouts)
- **`[auth]`** - Authentication credentials
- **`[filters]`** - File and share filtering options
- **`[output]`** - Output format and naming

## 💻 Usage Examples

### Docker Usage Examples

**Basic Docker Scan:**
```bash
# Build image once
docker build -t jesur:latest .

# Run scan
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest 192.168.1.0/24 -u username -p password
```

**Docker with All Options:**
```bash
docker run --rm --network host \
  -v $(pwd)/jesur.conf:/app/jesur.conf:ro \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest 192.168.1.0/24 \
  -u admin -p password123 \
  --threads 30 \
  --rate-limit 20 \
  --verbose \
  --output-json \
  --output-csv
```

**Docker Compose Workflow:**
```bash
# 1. Create output directories on YOUR machine FIRST
mkdir -p out_download reports

# 2. Edit docker-compose.yml if needed (volumes already configured)
nano docker-compose.yml

# 3. Run scan - volumes automatically mount to YOUR current directory
docker-compose run --rm jesur 192.168.1.0/24 -u user -p pass

# 4. View results on YOUR machine (not in container)
ls -la out_download/  # Downloaded files HERE on YOUR machine
ls -la reports/       # Reports HERE on YOUR machine
```

**Understanding docker-compose.yml volumes:**
```yaml
volumes:
  # These map container directories to YOUR local directories
  - ./out_download:/app/out_download    # Container → YOUR ./out_download/
  - ./reports:/app/reports              # Container → YOUR ./reports/
```

**Docker Interactive Mode (Debugging):**
```bash
# Run container interactively
docker run -it --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest /bin/bash

# Inside container, run manually
python3 Jesur.py 192.168.1.0/24 -u user -p pass --verbose
```

### Basic Scanning

```bash
# Single network scan
python3 Jesur.py 192.168.1.0/24

# Multiple networks from file
python3 Jesur.py -f targets.txt

# Country-based scanning
python3 Jesur.py --geo tr_TR  # Turkey
python3 Jesur.py --geo us_US  # United States
python3 Jesur.py --geo-list   # List all countries
```

### Authentication Methods

```bash
# Domain user with password
python3 Jesur.py 192.168.1.0/24 -u admin -p Password123 -d COMPANY

# Guest access (default)
python3 Jesur.py 192.168.1.0/24

# NTLM hash authentication (Pass-the-Hash)
# Format: LMHASH:NTHASH (both must be 32 hex characters)
python3 Jesur.py 192.168.1.0/24 -u administrator \
  --hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Hash authentication with domain
python3 Jesur.py 192.168.1.0/24 -u administrator -d DOMAIN \
  --hashes aad3b435b51404eeaad3b435b51404ee:dd1709faebc6745c7be95fa7d452a01b

# Hash authentication (single IP)
python3 Jesur.py 192.168.1.1 -u user --hashes LMHASH:NTHASH
```

**Hash Authentication Notes:**
- Both LM and NT hashes must be provided in format `LMHASH:NTHASH`
- Each hash must be exactly 32 hexadecimal characters
- If only NT hash is available, use empty LM hash: `aad3b435b51404eeaad3b435b51404ee:NTHASH`
- Domain parameter (`-d`) is recommended for domain environments
- Works with both NTLMv1 and NTLMv2 protocols

### Advanced Filtering

```bash
# Include only specific extensions
python3 Jesur.py 192.168.1.0/24 --include-ext txt,ini,config,xml

# Exclude binary files
python3 Jesur.py 192.168.1.0/24 --exclude-ext exe,dll,bin,iso

# File size filtering (1KB - 5MB)
python3 Jesur.py 192.168.1.0/24 --min-size 1024 --max-size 5242880

# Filename pattern matching (regex)
python3 Jesur.py 192.168.1.0/24 --filename-pattern ".*password.*|.*secret.*"

# Exclude specific shares
python3 Jesur.py 192.168.1.0/24 --exclude-shares "PRINT$,FAX$"

# Include admin shares (default: excluded)
python3 Jesur.py 192.168.1.0/24 --include-admin-shares
```

### Performance Tuning

```bash
# High-speed scanning (50 threads)
python3 Jesur.py 192.168.1.0/24 --threads 50

# Rate-limited scanning (5 IPs/second)
python3 Jesur.py 192.168.1.0/24 --rate-limit 5

# Custom host timeout (300 seconds)
python3 Jesur.py 192.168.1.0/24 --host-timeout 300

# Limit file read size (512KB max)
python3 Jesur.py 192.168.1.0/24 --max-read-bytes 524288
```

### Export Options

```bash
# JSON export
python3 Jesur.py 192.168.1.0/24 --output-json

# CSV export
python3 Jesur.py 192.168.1.0/24 --output-csv

# Both formats with custom name
python3 Jesur.py 192.168.1.0/24 --output-json --output-csv --output-name pentest_2024

# Quiet mode (minimal output)
python3 Jesur.py 192.168.1.0/24 --quiet --output-json

# Verbose mode (detailed logs)
python3 Jesur.py 192.168.1.0/24 --verbose
```

### Real-World Scenarios

```bash
# SCENARIO 1: Quick discovery (share listing only)
python3 Jesur.py 192.168.0.0/16 --list-shares --threads 50 --quiet

# SCENARIO 2: Credential hunting (config files only)
python3 Jesur.py 192.168.1.0/24 --include-ext ini,conf,config,xml,yaml,json --verbose

# SCENARIO 3: Stealth scanning (slow and quiet)
python3 Jesur.py 10.0.0.0/8 --rate-limit 2 --threads 5 --quiet

# SCENARIO 4: Large network scan
python3 Jesur.py -f corporate_networks.txt --threads 50 \
  --exclude-file exclude_list.txt --output-json

# SCENARIO 5: Country-wide scan
python3 Jesur.py --geo tr_TR --threads 100 --quiet \
  --output-json --output-csv
```

## 📖 Command Line Options

### Target Specification

| Option | Description | Example |
|--------|-------------|---------|
| `network` | Network in CIDR format | `192.168.1.0/24` |
| `-f, --file` | File containing networks | `-f targets.txt` |
| `--geo` | Country code | `--geo tr_TR` |
| `--geo-list` | List country codes | `--geo-list` |

### Authentication

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --username` | Username | `guest` |
| `-p, --password` | Password | (empty) |
| `--hashes` | NTLM hash in format `LMHASH:NTHASH` (both 32 hex chars) | None |
| `-d, --domain` | Domain name | `WORKGROUP` |

**Authentication Priority:**
- If `--hashes` is provided, hash authentication is used (password ignored)
- If `-p` is provided without `--hashes`, password authentication is used
- If neither is provided, anonymous/guest access is attempted

### Scan Options

| Option | Description | Default |
|--------|-------------|---------|
| `--share` | Scan specific share | All |
| `--list-shares` | List shares only | False |
| `--threads` | Number of threads | Auto (10-100) |
| `--rate-limit` | IPs per second | 0 (unlimited) |
| `--host-timeout` | Per-host timeout (seconds) | 180 |

### Filtering Options

| Option | Description | Default |
|--------|-------------|---------|
| `--include-ext` | Include extensions | All |
| `--exclude-ext` | Exclude extensions | None |
| `--min-size` | Min file size (bytes) | 0 |
| `--max-size` | Max file size (bytes) | 10MB |
| `--max-read-bytes` | Max bytes to read | 1MB |
| `--filename-pattern` | Regex pattern | None |
| `--exclude-shares` | Exclude shares | None |
| `--include-admin-shares` | Include admin shares | False |
| `--exclude-file` | IP exclude file | None |

### Output Options

| Option | Description | Default |
|--------|-------------|---------|
| `--output-json` | Export to JSON | False |
| `--output-csv` | Export to CSV | False |
| `--output-name` | Output filename | `jesur` |
| `--quiet, -q` | Quiet mode | False |
| `--verbose, -v` | Verbose mode | False |
| `--no-stats` | Hide statistics | False |
| `--config` | Config file path | `jesur.conf` |

## 🔍 Sensitive File Detection

JESUR automatically detects and downloads high-value files that are useful during authorized penetration tests. Filename, extension, and full SMB path are evaluated together, so common credential locations are found even when the filename alone is generic.

### Password Managers
- **KeePass**: Databases (`.kdbx`, `.kdb`), Key Files (`.key`)
- **1Password**: Import Files (`.1pif`), Vaults (`.opvault`, `.agilekeychain`)
- **LastPass**: Export Files (`lastpass.csv`, `lastpass_export.csv`)
- **Bitwarden**: Data Files (`data.json`, `bitwarden.json`)
- **Dashlane**: Database (`dashlane.db`)
- **RoboForm**: Data File (`RoboForm.dat`)
- **Password Safe**: Databases (`.psafe3`)
- **Browser Passwords**: Chrome/Edge (`Login Data`, `Web Data`), Firefox (`key4.db`, `logins.json`)

### Remote Connection Tools
- **PuTTY**: Private Keys (`.ppk`)
- **Remote Desktop**: Settings (`.rdp`, `.rdg`, `.rdm`)
- **Remmina**: Connection Files (`.remmina`), Preferences (`remmina.pref`)
- **SecureCRT**: Configuration (`SecureCRT.ini`, `Global.ini`)
- **RoyalTS**: Connection Packages (`.rtsz`, `.rtsx`)
- **SuperPuTTY**: Sessions (`SuperPuTTY.xml`, `sessions.xml`)
- **Terminals**: Configuration (`terminals.config`, `terminals.xml`)
- **Remote Desktop Manager**: Configuration (`RemoteDesktopManager.xml`)

### Connection Managers
- **mRemoteNG**: Configuration (`confCons.xml`)
- **WinSCP**: Configuration (`WinSCP.ini`)
- **FileZilla**: Settings (`FileZilla.xml`, `filezilla.xml`)
- **MobaXterm**: Configuration (`MobaXterm.ini`)

### SSH Configuration
- SSH Private Keys (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`)
- SSH Config Files (`config`, `known_hosts`, `authorized_keys`)
- Path-aware SSH artifacts (`.ssh/config`, `.ssh/id_*`, `.ssh/authorized_keys`)

### Certificates & Security
- SSL/TLS Certificates (`.crt`, `.pem`, `.cer`)
- PKCS#12 (`.pfx`, `.p12`)
- Java KeyStore (`.jks`, `.keystore`)
- OpenVPN Config (`.ovpn`)
- VNC Config (`.vnc`)
- System Files (`passwd`, `shadow`, `.htpasswd`)

### Cloud Credentials
- **AWS**: Credentials (`.aws/credentials`, `.aws/config`, `credentials.csv`)
- **Azure**: Profile (`azureProfile.json`), Credentials (`azureCredentials.json`, `accessTokens.json`)
- **GCP**: Service Accounts (`service-account.json`), Config directories
- **Terraform**: State Files (`.tfstate`), Variables (`.tfvars`)
- **HashiCorp Vault**: Configuration (`vault.hcl`), Tokens (`.vault-token`)
- **Kubernetes**: Path-aware config (`.kube/config`, `kubeconfig`)
- **Docker Registry**: Path-aware config (`.docker/config.json`, `.dockerconfigjson`)

### CI/CD & Development
- **Jenkins**: Credentials (`credentials.xml`), Config (`config.xml`)
- **GitLab**: CI Config (`.gitlab-ci.yml`), Secrets (`gitlab-secrets.json`)
- **GitHub**: Workflows (`.github/workflows/`), Tokens (`GITHUB_TOKEN`)
- **Docker**: Config (`config.json`), Compose (`docker-compose.yml`)
- **Kubernetes**: Config (`kubeconfig`), Secrets (`*.yaml`)
- **Ansible**: Vault Files (`secrets.yml`, `vault_pass`)
- **Package Managers**: NPM (`.npmrc`), Python (`pip.conf`, `.pypirc`), NuGet (`nuget.config`), Maven (`settings.xml`, `maven-settings.xml`, `.m2/settings.xml`), Gradle (`.gradle/gradle.properties`)

### Environment & Config Files
- Environment Variables (`.env`, `.env.local`, `.env.production`)
- Configuration Files (`config.ini`, `config.json`, `settings.json`)
- Application Properties (`application.properties`, `application.yml`)
- Web/Application Config (`web.config`, `app.config`, `appsettings*.json`, `connectionstrings.config`, `wp-config.php`, `database.yml`, `settings.py`, `local_settings.py`, `LocalSettings.php`)
- NPM Config (`.npmrc`)
- PIP Config (`pip.conf`, `.pypirc`)

### Database & Backup Files
- SQL Dumps (`.sql`, `.dump`)
- Database Files (`.db`, `.sqlite`, `.sqlite3`, `.mdb`)
- Backup Files (`.bak`, `.backup`, `.old`, `.orig`)
- Backup/Export Archives (`backup.zip`, `db_dump.sql`, `loot.zip`, and similar backup/export filenames)

### Windows & Active Directory Artifacts
- Active Directory database files (`ntds.dit`, `ntds.dit.bak`, `.dit`)
- Registry hives and backups (`Windows\System32\config\SAM`, `SYSTEM`, `SECURITY`, `sam.save`, `system.save`, `security.save`)
- Memory dumps (`lsass.dmp`, `.dmp`)
- Deployment secrets (`unattend.xml`, `autounattend.xml`, `sysprep.inf`, `sysprep.xml`)

### Pentest & Recon Artifacts
- Packet captures (`.pcap`, `.pcapng`, `.har`)
- Scanner exports (`.nessus`, `.nmap`, `.gnmap`, Nessus report filenames)
- Kerberos material (`.kirbi`, `.ccache`)
- Password/hash dumps (`.pwdump`, `.hccapx`, `hashdump.txt`, `secretsdump.txt`)
- Tool output (`mimikatz.log`, `sharphound.zip`, `bloodhound.zip`, PowerView/SharpHound/BloodHound-style filenames)

### Git Credentials
- Git Credentials (`.git-credentials`)
- Git Config (`.gitconfig`)

### Windows Credentials
- Credential Manager (`Credentials.xml`)

### CyberArk
- Vault Configuration (`vault.ini`, `cyberark.config`)

### Session & Token Files
- Session Files (`.session`, `session.dat`)
- Token Files (`.token`, `.api_key`)
- Findings are assigned a severity (`Critical`, `High`, or `Medium`) and this severity is included in HTML and CSV outputs.

## 🔎 Sensitive Content Detection

JESUR scans file contents using MIME detection, extension fallbacks, and text extraction for TXT/CSV/XML/JSON/YAML/TOML/config files, PDF, DOCX, and XLSX. Built-in signatures include:

- **Credentials** - Usernames, passwords, API keys
- **Cloud Keys** - AWS access keys, AWS secret keys, Google API keys
- **CI/CD Tokens** - GitHub, GitLab, and Slack tokens
- **Tokens** - JWTs, authentication tokens, session IDs
- **Database Connections** - PostgreSQL, MySQL, MSSQL, MongoDB, Redis, and JDBC connection strings
- **Embedded Credentials** - Basic-auth URLs and credential-bearing URLs
- **Private Key Material** - PEM private key blocks and PuTTY private key files
- **VPN/Tunnel Secrets** - Pre-shared keys, OpenVPN `auth-user-pass`, tunnel passwords
- **Cloud Credentials** - AWS, Azure, GCP, Terraform, Vault, and Kubernetes-related secrets
- **Email Information** - SMTP credentials, email addresses
- **Financial Data** - Credit cards, payment info
- **Internal IPs** - Private network addresses
- **Security Keywords** - Security-related patterns
- **Exploit Payloads** - Penetration testing tools
- **False Positive Reduction** - Minified frontend bundles, dictionary files, benign cache files, and UI password components are de-noised where possible

## 📊 Output Formats

### HTML Reports

A single unified HTML dashboard is generated:

**Unified Report** (`jesur_report_YYYYMMDD_HHMMSS.html`)
- Summary cards for hosts, shares, files, findings, bytes read, and downloaded evidence
- Finding distribution charts by category and file volume by host
- Searchable accessed-file table with file metadata and severity
- Searchable sensitive-finding table with severity, category, match, file type, and evidence links
- Category filter and pagination for large result sets
- Local `jesur_logo.png` copy for portable/offline reports
- Developer footer with project and version information

### JSON Export

```bash
python3 Jesur.py 192.168.1.0/24 --output-json
```

Generates:
- `jesur_files_YYYYMMDD_HHMMSS.json` - File listings
- `jesur_sensitive_YYYYMMDD_HHMMSS.json` - Sensitive findings
- `jesur_stats_YYYYMMDD_HHMMSS.json` - Scan statistics
- Sensitive findings include category, match, file type, downloaded file path, and severity

### CSV Export

```bash
python3 Jesur.py 192.168.1.0/24 --output-csv
```

Generates:
- `jesur_files_YYYYMMDD_HHMMSS.csv` - File listings
- `jesur_sensitive_YYYYMMDD_HHMMSS.csv` - Sensitive findings
- CSV exports include severity and are hardened against spreadsheet formula injection

### Downloaded Files

Sensitive files are automatically downloaded to:
```
out_download/[IP_ADDRESS]/[filename]
```

## ⚡ Performance Tuning

### Thread Configuration

```bash
# Small network (< 10 hosts)
--threads 10

# Medium network (10-50 hosts)
--threads 20-30

# Large network (> 50 hosts)
--threads 50-100
```

### Rate Limiting

```bash
# Slow scan (2 IPs/second)
--rate-limit 2

# Medium scan (10 IPs/second)
--rate-limit 10

# Fast scan (unlimited)
--rate-limit 0
```

### Memory Management

- File cache: 1000 entries max
- Share cache: 500 entries max
- Max memory: 500MB
- Per-file limit: 10MB

## 🛡️ Security Notes

⚠️ **IMPORTANT**: This tool is designed for authorized penetration testing only.

- ⚠️ Unauthorized network scanning may be illegal
- ⚠️ Only use on networks you own or have explicit permission to test
- ⚠️ Sensitive files are automatically downloaded
- ⚠️ All operations are logged and reported
- ⚠️ Use Ctrl+C for safe shutdown

## 🐛 Troubleshooting

### Common Issues

**Connection Timeouts**
```bash
# Increase host timeout
python3 Jesur.py 192.168.1.0/24 --host-timeout 300

# Docker version
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u user -p pass --host-timeout 300
```

**Memory Issues**
```bash
# Reduce max read bytes
python3 Jesur.py 192.168.1.0/24 --max-read-bytes 512000

# Docker version
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u user -p pass --max-read-bytes 512000
```

**Slow Scanning**
```bash
# Increase thread count
python3 Jesur.py 192.168.1.0/24 --threads 50

# Docker version
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u user -p pass --threads 50
```

**Authentication Failures**
```bash
# Use verbose mode for details
python3 Jesur.py 192.168.1.0/24 -u user -p pass --verbose

# Hash authentication troubleshooting
python3 Jesur.py 192.168.1.0/24 -u user -d DOMAIN \
  --hashes LMHASH:NTHASH --verbose

# Docker version
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u user -p pass --verbose

# Docker with hash authentication
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u user -d DOMAIN \
  --hashes LMHASH:NTHASH --verbose
```

**Docker Network Issues**
```bash
# If SMB connections fail, ensure host network mode
docker run --rm --network host ...

# Check if ports are accessible from container
docker run --rm --network host \
  jesur:latest --help

# Test connectivity
docker run --rm --network host \
  jesur:latest 192.168.1.1 -u guest -p "" --list-shares
```

**Docker Permission Issues**
```bash
# Ensure output directories are writable
mkdir -p out_download reports
chmod 777 out_download reports

# Or run with specific user
docker run --rm --network host \
  -u $(id -u):$(id -g) \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest 192.168.1.0/24 -u user -p pass
```

## 📝 Network File Format

Create a file (`networks.txt`) with one network per line:

```text
# Comments start with #
192.168.1.0/24
10.0.0.0/24
172.16.1.1        # Single IP (auto-converted to /32)
192.168.2.100/32  # Explicit CIDR
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

For major changes, please open an issue first.

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built for penetration testers and security professionals
- Inspired by the need for comprehensive SMB share analysis
- Thanks to all contributors and testers

## 🔗 Links

- **GitHub**: https://github.com/cumakurt/Jesur

---

**Made with ❤️ for Penetration Testers**
