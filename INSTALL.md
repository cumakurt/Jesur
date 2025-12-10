# JESUR Installation Guide

Complete installation guide for JESUR - Enhanced SMB Share Scanner

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation Methods](#installation-methods)
   - [Method 1: Docker Installation (Recommended)](#method-1-docker-installation-recommended)
   - [Method 2: Python Virtual Environment](#method-2-python-virtual-environment)
   - [Method 3: System-wide Installation](#method-3-system-wide-installation)
   - [Method 4: Development Installation](#method-4-development-installation)
3. [Post-Installation Configuration](#post-installation-configuration)
4. [Verification](#verification)
5. [Troubleshooting](#troubleshooting)
6. [Uninstallation](#uninstallation)

---

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows (with WSL recommended)
- **Python**: 3.7 or higher
- **RAM**: Minimum 512MB, Recommended 2GB+
- **Disk Space**: Minimum 100MB for application, additional space for reports
- **Network**: Access to target SMB shares (ports 445/139)

### Required System Libraries

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip libmagic1 libmagic-dev
```

#### Linux (CentOS/RHEL/Fedora)
```bash
sudo yum install -y python3 python3-pip file-devel
# or for newer versions:
sudo dnf install -y python3 python3-pip file-devel
```

#### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 libmagic
```

#### Windows
```bash
# Install Python from python.org
# Install libmagic via pip (python-magic-bin)
pip install python-magic-bin
```

### Docker Requirements (Optional)

- **Docker**: Version 20.10 or higher
- **Docker Compose**: Version 1.29 or higher (optional but recommended)

Check Docker installation:
```bash
docker --version
docker-compose --version
```

---

## Installation Methods

### Method 1: Docker Installation (Recommended)

Docker provides the easiest and most isolated installation method. All dependencies are pre-configured.

#### Step 1: Clone Repository

```bash
git clone https://github.com/cumakurt/Jesur.git
cd Jesur
```

#### Step 2: Build Docker Image

```bash
docker build -t jesur:latest .
```

This will:
- Download Python 3.12-slim base image
- Create optimized image using multi-stage build
- Install system dependencies (libmagic, file, ca-certificates)
- Install Python packages from requirements.txt
- Set up working directory and environment

**Build time**: ~2-5 minutes depending on internet speed (first build), faster on subsequent builds due to caching

#### Step 3: Verify Installation

```bash
docker run --rm jesur:latest --help
```

You should see the help menu.

#### Step 4: Create Output Directories (IMPORTANT!)

**⚠️ CRITICAL**: Docker containers are ephemeral. Without volume mounts, all reports and downloaded files will be lost when the container stops!

Create directories on your **host machine** (not inside container):

```bash
# Create directories in your current location
mkdir -p out_download reports

# Verify they exist
ls -la out_download reports
```

**Why this matters:**
- Files created inside Docker container are **lost** when container stops
- Volume mounts (`-v`) map container directories to **your host machine**
- Reports and downloads will persist on **your computer** even after container removal

#### Step 5: Run Your First Scan with Volume Mounts

**Basic Example:**
```bash
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u username -p password
```

**What happens:**
- `-v $(pwd)/out_download:/app/out_download` maps container's `/app/out_download` to your current directory's `out_download` folder
- `-v $(pwd)/reports:/app/reports` maps container's `/app/reports` to your current directory's `reports` folder
- All files saved to `/app/out_download` and `/app/reports` in container will appear in your local directories

**Verify files are on your machine:**
```bash
# After scan completes, check your local directories
ls -la out_download/
ls -la reports/
# You should see HTML, JSON, CSV files and downloaded sensitive files
```

**Custom Output Directory Example:**
```bash
# Use absolute paths for custom locations
docker run --rm --network host \
  -v /home/user/my_scans/out_download:/app/out_download \
  -v /home/user/my_scans/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u username -p password

# Files will be saved to /home/user/my_scans/ on your machine
```

**Windows Example:**
```bash
# Windows paths (use forward slashes or escaped backslashes)
docker run --rm --network host \
  -v C:/Users/YourName/scans/out_download:/app/out_download \
  -v C:/Users/YourName/scans/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u username -p password
```

**Without Volume Mounts (WRONG - Files will be lost!):**
```bash
# ❌ DON'T DO THIS - Files will be lost!
docker run --rm --network host \
  jesur:latest 192.168.1.0/24 -u username -p password
# All reports and downloads stay inside container and are deleted when it stops
```

#### Docker Compose Installation

For easier management, use docker-compose. **Volume mounts are pre-configured** in `docker-compose.yml`:

```bash
# 1. Create output directories on your host machine FIRST
mkdir -p out_download reports

# 2. Edit docker-compose.yml if needed (volumes are already configured)
nano docker-compose.yml

# 3. Run scan - volumes automatically mount to your current directory
docker-compose run --rm jesur 192.168.1.0/24 -u username -p password

# 4. Check your local directories for results
ls -la out_download/  # Downloaded sensitive files
ls -la reports/      # HTML, JSON, CSV reports
```

**docker-compose.yml Volume Configuration:**
```yaml
volumes:
  # Maps container /app/out_download to ./out_download on your machine
  - ./out_download:/app/out_download
  
  # Maps container /app/reports to ./reports on your machine
  - ./reports:/app/reports
  
  # Config file (read-only, optional)
  - ./jesur.conf:/app/jesur.conf:ro
```

**Custom Paths in docker-compose.yml:**
```yaml
volumes:
  # Use absolute paths for custom locations
  - /home/user/my_scans/out_download:/app/out_download
  - /home/user/my_scans/reports:/app/reports
```

**Verify Volume Mounts:**
```bash
# Check what volumes are mounted
docker-compose config

# Inspect running container volumes
docker inspect jesur-scanner | grep -A 10 Mounts
```

**Advantages:**
- ✅ No Python version conflicts
- ✅ No dependency management issues
- ✅ Consistent environment across systems
- ✅ Easy cleanup (just remove container)

**Disadvantages:**
- ❌ Requires Docker installation
- ❌ Slightly larger disk footprint (~500MB)

---

### Method 2: Python Virtual Environment

Recommended for users who want to avoid system-wide Python package installation.

#### Step 1: Clone Repository

```bash
git clone https://github.com/cumakurt/Jesur.git
cd Jesur
```

#### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

#### Step 3: Upgrade Pip

```bash
pip install --upgrade pip setuptools wheel
```

#### Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

**Installation time**: ~1-3 minutes

#### Step 5: Verify Installation

```bash
python3 Jesur.py --help
```

#### Step 6: Create Output Directories

```bash
mkdir -p out_download reports
```

#### Step 7: Run Your First Scan

```bash
python3 Jesur.py 192.168.1.0/24 -u username -p password
```

**To deactivate virtual environment:**
```bash
deactivate
```

**Advantages:**
- ✅ Isolated from system Python
- ✅ Easy to remove (just delete venv folder)
- ✅ No root/admin access needed

**Disadvantages:**
- ❌ Requires Python 3.7+ installed
- ❌ Need to activate environment each time

---

### Method 3: System-wide Installation

Install JESUR system-wide for all users. Requires admin/root access.

#### Step 1: Clone Repository

```bash
git clone https://github.com/cumakurt/Jesur.git
cd Jesur
```

#### Step 2: Install System Dependencies

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip libmagic1 libmagic-dev
```

**Linux (CentOS/RHEL):**
```bash
sudo yum install -y python3 python3-pip file-devel
```

**macOS:**
```bash
brew install python3 libmagic
```

#### Step 3: Install Python Dependencies

```bash
sudo pip3 install -r requirements.txt
```

**Or use --user flag to install for current user only:**
```bash
pip3 install --user -r requirements.txt
```

#### Step 4: Create Symbolic Link (Optional)

```bash
# Make Jesur.py executable
chmod +x Jesur.py

# Create symlink in /usr/local/bin (requires sudo)
sudo ln -s $(pwd)/Jesur.py /usr/local/bin/jesur

# Now you can run from anywhere:
jesur 192.168.1.0/24 -u username -p password
```

#### Step 5: Verify Installation

```bash
python3 Jesur.py --help
# or if symlink created:
jesur --help
```

**Advantages:**
- ✅ Available system-wide
- ✅ Can be run from any directory
- ✅ No activation needed

**Disadvantages:**
- ❌ Requires admin/root access
- ❌ May conflict with system Python packages
- ❌ Harder to uninstall

---

### Method 4: Development Installation

For developers who want to modify the code.

#### Step 1: Clone Repository

```bash
git clone https://github.com/cumakurt/Jesur.git
cd Jesur
```

#### Step 2: Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows
```

#### Step 3: Install in Editable Mode

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e .
```

#### Step 4: Install Development Tools (Optional)

```bash
pip install pytest pytest-cov flake8 black mypy
```

#### Step 5: Verify Installation

```bash
python3 Jesur.py --help
```

**Advantages:**
- ✅ Code changes immediately reflected
- ✅ Easy to test modifications
- ✅ Development tools included

**Disadvantages:**
- ❌ More complex setup
- ❌ Requires understanding of Python development

---

## Post-Installation Configuration

### 1. Create Configuration File

```bash
# Copy example config
cp jesur.conf.example jesur.conf

# Edit configuration
nano jesur.conf
# or
vim jesur.conf
```

### 2. Configure Basic Settings

Edit `jesur.conf`:

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
exclude_ext=.log,.tmp
max_read_bytes=1048576

[output]
output_json=true
output_csv=false
quiet=false
verbose=false
```

### 3. Create Output Directories

```bash
mkdir -p out_download reports
```

### 4. Set Permissions (Linux/macOS)

```bash
chmod 755 out_download reports
```

---

## Verification

### Test 1: Help Command

```bash
# Docker
docker run --rm jesur:latest --help

# Python
python3 Jesur.py --help
```

Expected output: Help menu with all available options

### Test 2: Version Check

```bash
# Check Python version
python3 --version  # Should be 3.7+ (3.12 if using Docker)

# Check Docker version
docker --version  # Should be 20.10+
```

### Test 3: Import Test

```bash
python3 -c "import jesur.main; import jesur.core.scanner; print('All imports successful')"
```

Expected output: `All imports successful`

### Test 4: List Shares Test

```bash
# Test with a local IP (replace with your test IP)
python3 Jesur.py 127.0.0.1 -u guest -p "" --list-shares
```

Expected output: Share list or connection error (both are normal)

### Test 5: Configuration File Test

```bash
# Create test config
echo "[scan]
network=127.0.0.1" > test.conf

# Test config loading
python3 Jesur.py --config test.conf --list-shares
```

---

## Troubleshooting

### Issue 1: "python-magic" Installation Fails

**Problem**: `pip install python-magic` fails on Linux

**Solution**:
```bash
# Install system library first
sudo apt-get install libmagic1 libmagic-dev  # Debian/Ubuntu
sudo yum install file-devel  # CentOS/RHEL
brew install libmagic  # macOS

# Then install Python package
pip install python-magic
```

### Issue 2: Docker Build Fails

**Problem**: Docker build fails with network errors

**Solution**:
```bash
# Check internet connection
ping google.com

# Try with --no-cache flag
docker build --no-cache -t jesur:latest .

# Check Docker daemon
sudo systemctl status docker  # Linux
```

### Issue 3: Permission Denied Errors

**Problem**: Permission errors when writing files

**Solution**:
```bash
# Fix directory permissions
chmod 755 out_download reports

# Or run with specific user (Docker)
docker run --rm --network host \
  -u $(id -u):$(id -g) \
  -v $(pwd)/out_download:/app/out_download \
  jesur:latest ...
```

### Issue 7: Files Not Appearing on Host Machine

**Problem**: Ran scan but can't find reports/downloads on your computer

**Solution**:
```bash
# 1. Verify volume mounts are present
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest --help

# 2. Check if directories exist BEFORE running scan
ls -la out_download/ reports/

# 3. Run scan and verify files appear
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u user -p pass

# 4. Check YOUR local directories (not container)
ls -la out_download/  # Should show downloaded files
ls -la reports/       # Should show HTML, JSON, CSV files

# 5. If still empty, check volume mount syntax
# Correct: -v $(pwd)/out_download:/app/out_download
# Wrong:   -v out_download:/app/out_download (missing $(pwd)/)
```

**Common Mistakes:**
```bash
# ❌ WRONG - Missing volume mounts
docker run --rm --network host jesur:latest ...
# Files stay in container and are lost!

# ❌ WRONG - Wrong path syntax
docker run --rm --network host \
  -v out_download:/app/out_download \
  jesur:latest ...
# Use $(pwd)/out_download or absolute path

# ✅ CORRECT - Proper volume mounts
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest ...
```

### Issue 4: Module Not Found Errors

**Problem**: `ModuleNotFoundError` when running

**Solution**:
```bash
# Verify virtual environment is activated
which python3  # Should show venv path

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Check Python path
python3 -c "import sys; print('\n'.join(sys.path))"
```

### Issue 5: SMB Connection Failures in Docker

**Problem**: Cannot connect to SMB shares from Docker container

**Solution**:
```bash
# Use host network mode
docker run --rm --network host ...

# Verify network access
docker run --rm --network host jesur:latest 192.168.1.1 -u guest -p "" --list-shares

# Check firewall rules
sudo iptables -L  # Linux
```

### Issue 6: Out of Memory Errors

**Problem**: Container or process runs out of memory

**Solution**:
```bash
# Reduce max_read_bytes in config
max_read_bytes=512000  # 512KB instead of 1MB

# Limit Docker memory
docker run --rm --network host --memory="512m" ...

# Reduce thread count
--threads 10  # Instead of 20+
```

---

## Uninstallation

### Docker Installation

```bash
# Remove Docker image
docker rmi jesur:latest

# Remove container (if exists)
docker rm jesur-scanner

# Remove volumes (optional)
docker volume prune
```

### Virtual Environment Installation

```bash
# Deactivate environment
deactivate

# Remove virtual environment directory
rm -rf venv

# Remove cloned repository (optional)
cd ..
rm -rf Jesur
```

### System-wide Installation

```bash
# Remove Python packages
pip3 uninstall -r requirements.txt

# Remove symlink (if created)
sudo rm /usr/local/bin/jesur

# Remove cloned repository
rm -rf Jesur
```

### Complete Cleanup

```bash
# Remove all traces
rm -rf venv __pycache__ .pytest_cache
rm -rf out_download reports
rm -f *.html *.json *.csv *.log
rm -f jesur.conf geo_ip_cache.json
```

---

## Quick Reference

### Docker Quick Start

```bash
# Build once
docker build -t jesur:latest .

# Create output directories on YOUR machine
mkdir -p out_download reports

# Run scan with volume mounts (REQUIRED!)
# Files saved to /app/out_download in container → appear in ./out_download/ on YOUR machine
docker run --rm --network host \
  -v $(pwd)/out_download:/app/out_download \
  -v $(pwd)/reports:/app/reports \
  jesur:latest 192.168.1.0/24 -u user -p pass

# Verify files are on YOUR machine
ls -la out_download/  # Downloaded files HERE
ls -la reports/       # Reports HERE
```

### Python Quick Start

```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run
python3 Jesur.py 192.168.1.0/24 -u user -p pass
```

### Docker Compose Quick Start

```bash
# Edit docker-compose.yml
nano docker-compose.yml

# Run
docker-compose run --rm jesur 192.168.1.0/24 -u user -p pass
```

---

## Additional Resources

- **Main Documentation**: See [README.md](README.md)
- **Turkish Documentation**: See [README.TR.md](README.TR.md)
- **Configuration Guide**: See [jesur.conf.example](jesur.conf.example)
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog**: See [CHANGELOG.md](CHANGELOG.md)

---

## Support

If you encounter issues during installation:

1. Check [Troubleshooting](#troubleshooting) section above
2. Review [README.md](README.md) for usage examples
3. Open an issue on [GitHub Issues](https://github.com/cumakurt/Jesur/issues)
4. Check existing issues for similar problems

---

**Version**: 2.0.0

