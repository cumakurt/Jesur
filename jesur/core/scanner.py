"""
JESUR - Enhanced SMB Share Scanner
SMB share scanning module

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
import os
import threading
import tempfile
import re
from datetime import datetime
from time import sleep
import time
from io import BytesIO
from typing import Optional, Dict, List, Any, Tuple

from jesur.core.context import scan_status, scan_stats, shutdown_flag, results, all_files
from jesur.core.connection import connection_pool, retry_on_failure, check_port
from jesur.core.analyzer import get_file_type, check_sensitive_patterns
from jesur.utils.cache import cache_manager
from jesur.utils.common import Colors, colored_print, print_section, print_finding, normalize_smb_path, verbose_print, quiet_print

# Import constants
from jesur.core.constants import (
    TIMEOUT_PORT_SCAN, TIMEOUT_CONNECTION, TIMEOUT_SHARE_LIST,
    TIMEOUT_FILE_READ, TIMEOUT_FILE_WRITE, TIMEOUT_DIR_LIST,
    TIMEOUT_AUTH, TIMEOUT_OPERATION, TIMEOUT_FILE_MINIMUM,
    TIMEOUT_LARGE_FILE, TIMEOUT_CHUNK_MAX,
    MAX_FILE_SIZE_DEFAULT, MAX_READ_BYTES_DEFAULT,
    CHUNK_SIZE_DEFAULT, MAX_CACHE_FILE_SIZE,
    LARGE_FILE_THRESHOLD
)

# Timeout configuration constants (for backward compatibility)
TIMEOUT_SETTINGS = {
    'port_scan': TIMEOUT_PORT_SCAN,
    'connection': TIMEOUT_CONNECTION,
    'share_list': TIMEOUT_SHARE_LIST,
    'file_read': TIMEOUT_FILE_READ,
    'file_write': TIMEOUT_FILE_WRITE,
    'dir_list': TIMEOUT_DIR_LIST,
    'auth': TIMEOUT_AUTH,
    'operation': TIMEOUT_OPERATION
}

# File size constants (for backward compatibility)
DEFAULT_MAX_FILE_SIZE = MAX_FILE_SIZE_DEFAULT
DEFAULT_MAX_READ_BYTES = MAX_READ_BYTES_DEFAULT
DEFAULT_CHUNK_SIZE = CHUNK_SIZE_DEFAULT
MIN_FILE_TIMEOUT = TIMEOUT_FILE_MINIMUM

# Sensitive file extensions (Hardcoded as they are structural logic, not just regex content)
SENSITIVE_EXTENSIONS = {
    # Password Managers
    '.kdbx': 'KeePass Password Database',
    '.kdb': 'KeePass Password Database (Legacy)',
    '.key': 'KeePass Key File',
    '.1pif': '1Password Import File',
    '.opvault': '1Password Vault',
    '.rtsz': 'RoyalTS Connection Package',
    '.rtsx': 'RoyalTS Connection File',
    
    # Remote Connection Tools
    '.ppk': 'PuTTY Private Key File',
    '.rdp': 'Remote Desktop Connection Settings',
    '.remmina': 'Remmina Remote Connection File',
    '.rdg': 'Remote Desktop Gateway Settings',
    '.rdm': 'Remote Desktop Manager Settings',
    
    # Certificates and Keys
    '.crt': 'SSL/TLS Certificate',
    '.pem': 'Privacy Enhanced Mail Certificate',
    '.cer': 'Security Certificate',
    '.pfx': 'PKCS#12 Certificate',
    '.p12': 'PKCS#12 Certificate Bundle',
    '.jks': 'Java KeyStore',
    '.keystore': 'Java KeyStore File',
    
    # VPN and Remote Access
    '.ovpn': 'OpenVPN Configuration File',
    '.vnc': 'VNC Configuration File',
    '.rdp': 'Remote Desktop Protocol File',
    
    # Cloud Credentials
    '.tfstate': 'Terraform State File',
    '.tfvars': 'Terraform Variables File',
    
    # Database Files
    '.sql': 'SQL Database Dump',
    '.dump': 'Database Dump File',
    '.db': 'Database File',
    '.sqlite': 'SQLite Database',
    '.sqlite3': 'SQLite3 Database',
    '.mdb': 'Microsoft Access Database',
    
    # Backup Files
    '.bak': 'Backup File',
    '.backup': 'Backup File',
    '.old': 'Old/Backup File',
    '.orig': 'Original/Backup File',
    
    # Configuration Files with Credentials
    '.env': 'Environment Variables File',
    '.htpasswd': 'Apache Password File',
    
    # Session and Token Files
    '.session': 'Session File',
    '.token': 'Token File',
    '.api_key': 'API Key File'
}

SENSITIVE_FILENAMES = {
    # SSH Keys and Configuration
    'id_rsa': 'SSH RSA Private Key',
    'id_dsa': 'SSH DSA Private Key',
    'id_ecdsa': 'SSH ECDSA Private Key',
    'id_ed25519': 'SSH ED25519 Private Key',
    'known_hosts': 'SSH Known Hosts File',
    'authorized_keys': 'SSH Authorized Keys File',
    'config': 'SSH Configuration File',
    
    # Remote Connection Managers
    'confCons.xml': 'mRemoteNG Connection Configuration',
    'WinSCP.ini': 'WinSCP Configuration File',
    'FileZilla.xml': 'FileZilla Connection Settings',
    'filezilla.xml': 'FileZilla Connection Settings',
    'MobaXterm.ini': 'MobaXterm Configuration File',
    'remmina.pref': 'Remmina Preferences File',
    'SecureCRT.ini': 'SecureCRT Configuration File',
    'Global.ini': 'SecureCRT Global Settings',
    'SuperPuTTY.xml': 'SuperPuTTY Sessions',
    'sessions.xml': 'Terminal Sessions Configuration',
    'terminals.config': 'Terminals Configuration',
    'terminals.xml': 'Terminals XML Configuration',
    'RemoteDesktopManager.xml': 'Remote Desktop Manager Configuration',
    
    # Password Manager Files
    'lastpass.csv': 'LastPass Export File',
    'lastpass_export.csv': 'LastPass Export File',
    'data.json': 'Bitwarden Data File',
    'bitwarden.json': 'Bitwarden Configuration',
    'dashlane.db': 'Dashlane Database',
    'RoboForm.dat': 'RoboForm Data File',
    '1Password.opvault': '1Password Vault Directory',
    
    # Browser Credentials
    'Login Data': 'Chrome/Edge Saved Passwords',
    'Web Data': 'Chrome/Edge Web Data',
    'key4.db': 'Firefox Password Database',
    'logins.json': 'Firefox Saved Logins',
    'key3.db': 'Firefox Legacy Password Database',
    
    # Cloud Credentials
    'credentials': 'AWS Credentials File',
    'config': 'AWS Config File',
    'azureProfile.json': 'Azure Profile',
    'azureCredentials.json': 'Azure Credentials',
    'service-account.json': 'GCP Service Account',
    'gcloud': 'GCP Configuration Directory',
    'terraform.tfstate': 'Terraform State File',
    'terraform.tfvars': 'Terraform Variables',
    'vault.hcl': 'HashiCorp Vault Configuration',
    '.vault-token': 'HashiCorp Vault Token',
    
    # CI/CD Credentials
    'credentials.xml': 'Jenkins Credentials',
    'config.xml': 'Jenkins Configuration',
    'gitlab-secrets.json': 'GitLab Secrets',
    '.gitlab-ci.yml': 'GitLab CI Configuration',
    'GITHUB_TOKEN': 'GitHub Token File',
    
    # Docker and Container Configs
    'config.json': 'Docker Configuration',
    'docker-compose.yml': 'Docker Compose Configuration',
    'kubeconfig': 'Kubernetes Configuration',
    
    # Development Credentials
    '.env': 'Environment Variables',
    '.env.local': 'Local Environment Variables',
    '.env.production': 'Production Environment Variables',
    '.env.development': 'Development Environment Variables',
    '.npmrc': 'NPM Configuration',
    'pip.conf': 'PIP Configuration',
    '.pypirc': 'Python Package Index Config',
    'secrets.yml': 'Ansible Vault Secrets',
    'secrets.yaml': 'Ansible Vault Secrets',
    'vault_pass': 'Ansible Vault Password',
    'application.properties': 'Java Application Properties',
    'application.yml': 'Java Application YAML',
    'settings.json': 'Application Settings',
    'config.ini': 'Configuration File',
    'config.json': 'Configuration JSON',
    
    # Git Credentials
    '.git-credentials': 'Git Credentials',
    '.gitconfig': 'Git Configuration',
    
    # Windows Credentials
    'Credentials.xml': 'Windows Credential Manager',
    
    # System Files
    'passwd': 'Password File',
    'shadow': 'Shadow Password File',
    '.htpasswd': 'Apache Password File',
    '.htaccess': 'Apache Configuration',
    
    # API Keys and Tokens
    'api_keys.txt': 'API Keys File',
    '.api_key': 'API Key File',
    'api_key': 'API Key File',
    'token': 'Token File',
    '.token': 'Token File',
    
    # Session Files
    'session.dat': 'Session Data',
    '.session': 'Session File',
    
    # CyberArk
    'vault.ini': 'CyberArk Vault Configuration',
    'cyberark.config': 'CyberArk Configuration'
}

BINARY_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.bin', '.dat', '.db', '.msi', '.com', '.ocx', '.drv', 
    '.efi', '.rom', '.so', '.dylib', '.o', '.obj', '.lib', '.a', '.pyc', '.pyo', 
    '.pyd', '.ko', '.class', '.jar', '.war', '.ear', '.iso', '.img', '.vhd', '.vmdk', 
    '.qcow2', '.vdi', '.mui'
}

def check_share_permissions(
    conn: Any,
    share_name: str,
    local_stats: Dict[str, int],
    timeout: int = TIMEOUT_SETTINGS['operation']
) -> Dict[str, bool]:
    """
    Check read and write permissions for a share.
    
    Args:
        conn: SMB connection object
        share_name: Name of the share to check
        local_stats: Thread-local statistics dictionary to update
        timeout: Operation timeout in seconds
        
    Returns:
        Dictionary with 'read' and 'write' boolean permissions
    """
    permissions = {'read': False, 'write': False}
    test_file_path = None
    try:
        # Check read permission
        try:
            verbose_print(f"\t\t[*] Checking read permission for {share_name}...")
            conn.listPath(share_name, '/', timeout=timeout)
            permissions['read'] = True
            verbose_print(f"\t\t[+] Read permission granted for {share_name}")
            local_stats['readable_shares'] += 1
        except (ConnectionError, TimeoutError, OSError) as e:
            verbose_print(f"\t\t[-] No read permission for {share_name}: {type(e).__name__}")
        except Exception as e:
            verbose_print(f"\t\t[-] Error checking read permission for {share_name}: {type(e).__name__}")
            
        # Check write permission
        if permissions['read']:
            try:
                verbose_print(f"\t\t[*] Checking write permission for {share_name}...")
                test_filename = '__jesur_test.tmp'
                test_data = b'test'
                with tempfile.NamedTemporaryFile() as temp_file:
                    temp_file.write(test_data)
                    temp_file.seek(0)
                    try:
                        test_file_path = f'/{test_filename}'
                        conn.storeFile(share_name, test_file_path, temp_file, timeout=TIMEOUT_SETTINGS['file_write'])
                        permissions['write'] = True
                        conn.deleteFiles(share_name, test_file_path, timeout=timeout)
                        verbose_print(f"\t\t[+] Write permission granted for {share_name}")
                        local_stats['writable_shares'] += 1
                    except (ConnectionError, TimeoutError, OSError, PermissionError) as e:
                        verbose_print(f"\t\t[-] No write permission for {share_name}: {type(e).__name__}")
                    except Exception as e:
                        verbose_print(f"\t\t[-] Error checking write permission for {share_name}: {type(e).__name__}")
            except (ConnectionError, TimeoutError, OSError) as e:
                verbose_print(f"\t\t[-] No write permission for {share_name}: {type(e).__name__}")
            except Exception as e:
                verbose_print(f"\t\t[-] Error checking write permission for {share_name}: {type(e).__name__}")
    except Exception as e:
        from jesur.utils.logger import log_debug
        log_debug(f"Unexpected error in permission check for {share_name}: {e}")
    finally:
        # Cleanup test file if it exists
        if test_file_path:
            try:
                conn.deleteFiles(share_name, test_file_path, timeout=timeout)
            except (ConnectionError, TimeoutError, OSError):
                # Expected - file may not exist or connection closed
                pass
            except Exception as e:
                from jesur.utils.logger import log_debug
                log_debug(f"Error cleaning up test file: {e}")
    return permissions

def read_file_content(
    conn: Any,
    share: str,
    file_path: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    timeout: int = TIMEOUT_SETTINGS['file_read']
) -> Optional[bytes]:
    """
    Read file content from SMB share with chunking and improved timeout management.
    
    Args:
        conn: SMB connection object
        share: Share name
        file_path: Path to file on share
        chunk_size: Size of each chunk to read in bytes
        timeout: Timeout per operation in seconds
        
    Returns:
        File content as bytes, or None if read failed
    """
    if shutdown_flag.is_set():
        return None
    
    from jesur.core import context
    filters = getattr(context, 'scan_filters', {})
    max_read_bytes = filters.get('max_read_bytes', DEFAULT_MAX_READ_BYTES)
    per_file_timeout = max(timeout, MIN_FILE_TIMEOUT)
    
    normalized_path = file_path.replace('\\', '/')
    if normalized_path.startswith('/'):
        normalized_path = normalized_path.lstrip('/')
    
    buf = BytesIO()
    offset = 0
    start_time = time.time()
    last_chunk_time = start_time
    
    try:
        while offset < max_read_bytes:
            if shutdown_flag.is_set():
                return None
            
            # Check overall timeout
            elapsed = time.time() - start_time
            if elapsed > per_file_timeout:
                verbose_print(f"[*] File read timeout after {elapsed:.1f}s: {file_path}")
                return None
            
            # Check per-chunk timeout (prevent hanging on slow reads)
            chunk_timeout = min(timeout, TIMEOUT_CHUNK_MAX)
            
            remaining = max_read_bytes - offset
            read_len = min(chunk_size, remaining)
            
            try:
                # retrieveFileFromOffset writes into file-like object starting at given offset length
                temp_chunk = BytesIO()
                chunk_start_time = time.time()
                conn.retrieveFileFromOffset(share, normalized_path, temp_chunk, offset, read_len, timeout=chunk_timeout)
                temp_chunk.seek(0)
                chunk = temp_chunk.read()
                
                if not chunk:
                    break
                
                buf.write(chunk)
                offset += len(chunk)
                last_chunk_time = time.time()
                
                # If chunk is smaller than requested, we've reached EOF
                if len(chunk) < read_len:
                    break
                    
            except (ConnectionError, TimeoutError, OSError) as e:
                # Network errors - check if we got any data
                if offset > 0:
                    from jesur.utils.logger import log_debug
                    log_debug(f"Network error during read, returning partial content: {e}")
                    return buf.getvalue()
                return None
            except Exception as e:
                from jesur.utils.logger import log_debug
                log_debug(f"Unexpected error reading file chunk: {e}")
                if offset > 0:
                    return buf.getvalue()
                return None
        
        return buf.getvalue()
    except (ConnectionError, TimeoutError, OSError) as e:
        from jesur.utils.logger import log_debug
        log_debug(f"Network error reading file {file_path}: {e}")
        return None
    except Exception as e:
        from jesur.utils.logger import log_error
        log_error(f"Unexpected error reading file {file_path}: {e}", exc_info=True)
        return None

def _sanitize_path(file_path: Optional[str]) -> Optional[str]:
    """
    Sanitize and normalize file path, prevent path traversal attacks.
    
    Args:
        file_path: Raw file path from SMB share
        
    Returns:
        Sanitized path or None if path is invalid/dangerous
    """
    if not file_path or not isinstance(file_path, str):
        return None
    
    # Normalize path separators
    normalized_path = file_path.replace('\\', '/')
    
    # Remove leading slashes
    normalized_path = normalized_path.lstrip('/')
    
    # Path traversal protection - check for various attack patterns
    dangerous_patterns = [
        '..',
        '../',
        '/..',
        '\\..',
        '..\\',
        '%2e%2e',  # URL encoded
        '%2E%2E',  # URL encoded uppercase
        '....',    # Double dot variations
    ]
    
    for pattern in dangerous_patterns:
        if pattern in normalized_path:
            verbose_print(f"[-] Path traversal attempt detected: {file_path}")
            return None
    
    # Check for absolute paths (should not start with drive letters or root)
    if normalized_path.startswith(('C:', 'D:', 'E:', '/', '\\')):
        verbose_print(f"[-] Absolute path detected: {file_path}")
        return None
    
    # Remove any remaining dangerous characters
    # Keep only alphanumeric, dots, dashes, underscores, and forward slashes
    import re
    if not re.match(r'^[\w\.\-\/\\]+$', normalized_path):
        verbose_print(f"[-] Invalid characters in path: {file_path}")
        return None
    
    return normalized_path

def _get_safe_output_path(normalized_path: str, ip: str) -> Tuple[str, str]:
    """
    Get safe output path for downloaded file.
    
    Args:
        normalized_path: Normalized file path
        ip: IP address of host
        
    Returns:
        Tuple of (absolute_output_path, relative_output_path)
    """
    out_dir = os.path.join('out_download', ip.replace('.', '_'))
    os.makedirs(out_dir, exist_ok=True)
    
    safe_filename = re.sub(r'[^\w\-_\.]', '_', normalized_path.replace('/', '_').replace('\\', '_'))
    out_path = os.path.join(out_dir, safe_filename)
    # Relative path is used for display/download links, keep it simple
    relative_path = os.path.join(ip.replace('.', '_'), safe_filename)
    
    return out_path, relative_path

def download_file_with_fallback(
    conn: Any,
    share: str,
    file_path: str,
    ip: str,
    file_size: Optional[int] = None,
    content: Optional[bytes] = None,
    timeout: int = TIMEOUT_SETTINGS['file_read']
) -> Optional[str]:
    """
    Download file with multiple fallback strategies.
    
    Args:
        conn: SMB connection object
        share: Share name
        file_path: Path to file on SMB share
        ip: IP address of host
        file_size: Size of file in bytes (optional)
        content: Pre-read file content (optional, used as fallback)
        timeout: Connection timeout in seconds
        
    Returns:
        Relative path to downloaded file, or None if download failed
    """
    # Strategy 1: Sanitize path
    normalized_path = _sanitize_path(file_path)
    if not normalized_path:
        verbose_print(f"[-] Invalid path detected: {file_path}")
        return None
    
    # Strategy 2: Get output path
    out_path, relative_path = _get_safe_output_path(normalized_path, ip)
    
    # Strategy 3: Check if file already exists
    if os.path.exists(out_path):
        return relative_path
    
    if shutdown_flag.is_set():
        return None
    
    # Strategy 4: Use provided content if available
    if content:
        try:
            with open(out_path, 'wb') as out_file:
                out_file.write(content)
            verbose_print(f"[+] Saved file from content: {out_path}")
            return relative_path
        except (PermissionError, IOError) as e:
            verbose_print(f"[-] File system error saving content: {type(e).__name__}")
        except Exception as e:
            verbose_print(f"[-] Unexpected error saving content: {type(e).__name__}: {str(e)}")
    
    # Strategy 5: Direct download with retry
    try:
        # Adjust timeout for large files
        if file_size and file_size > LARGE_FILE_THRESHOLD:
            download_timeout = max(timeout, TIMEOUT_LARGE_FILE)
            verbose_print(f"[*] Large file detected ({file_size} bytes), using extended timeout: {download_timeout}s")
        else:
            download_timeout = timeout
        
        from jesur.core.constants import RETRY_MAX_ATTEMPTS, RETRY_BASE_DELAY
        @retry_on_failure(max_attempts=RETRY_MAX_ATTEMPTS, base_delay=RETRY_BASE_DELAY)
        def _download_with_timeout():
            with open(out_path, 'wb') as out_file:
                conn.retrieveFile(share, normalized_path, out_file, timeout=download_timeout)
            return relative_path
        
        return _download_with_timeout()
    except (ConnectionError, TimeoutError, OSError) as e:
        from jesur.utils.logger import log_debug
        log_debug(f"Network error downloading file {file_path}: {e}")
    except (PermissionError, IOError) as e:
        from jesur.utils.logger import log_debug
        log_debug(f"File system error downloading {file_path}: {e}")
    except Exception as e:
        from jesur.utils.logger import log_error
        log_error(f"Unexpected error downloading file {file_path}: {e}", exc_info=True)
    
    # Strategy 6: Try reading content and saving
    try:
        file_content = read_file_content(conn, share, file_path)
        if file_content:
            with open(out_path, 'wb') as out_file:
                out_file.write(file_content)
            verbose_print(f"[+] Saved file after re-read: {out_path}")
            return relative_path
    except Exception as e:
        from jesur.utils.logger import log_debug
        log_debug(f"Error reading/saving file {file_path}: {e}")
    
    return None

def download_sensitive_file(
    conn: Any,
    share: str,
    file_path: str,
    ip: str,
    timeout: int = TIMEOUT_SETTINGS['file_read'],
    file_size: Optional[int] = None
) -> Optional[str]:
    """
    Download sensitive file - wrapper for backward compatibility.
    
    Args:
        conn: SMB connection object
        share: Share name
        file_path: Path to file on SMB share
        ip: IP address of host
        timeout: Connection timeout in seconds
        file_size: Size of file in bytes (optional)
        
    Returns:
        Relative path to downloaded file, or None if download failed
    """
    return download_file_with_fallback(conn, share, file_path, ip, file_size=file_size, timeout=timeout)

def scan_share(
    conn: Any,
    share_name: str,
    path: str,
    ip: str,
    local_stats: Dict[str, int],
    local_results: List[Dict[str, Any]],
    local_files: List[Dict[str, Any]],
    timeout: int = TIMEOUT_SETTINGS['operation']
) -> None:
    """
    Recursively scan SMB share for files and sensitive content.
    
    Args:
        conn: SMB connection object
        share_name: Name of the share to scan
        path: Current path within share (use "/" for root)
        ip: IP address of the host
        local_stats: Thread-local statistics dictionary
        local_results: Thread-local results list for sensitive findings
        local_files: Thread-local files list
        timeout: Operation timeout in seconds
        
    Returns:
        None (modifies local_stats, local_results, local_files in place)
    """
    if shutdown_flag.is_set(): return

    # Get filters from context
    from jesur.core import context
    filters = getattr(context, 'scan_filters', {})

    smb_path = path.replace('\\', '/')
    if smb_path.startswith('/'): smb_path = smb_path.lstrip('/')
    
    display_path = normalize_smb_path(path) if path != '/' else ''
    scan_status.update(share=share_name, action=f"Listing directory", path=display_path if display_path else 'root')
    
    try:
        cache_key = f"{ip}:{share_name}:{smb_path}"
        files = cache_manager.get_cached_share(ip, cache_key)
        
        if not files:
            if shutdown_flag.is_set(): return
            list_path = '' if not smb_path or smb_path == '/' else smb_path
            files = conn.listPath(share_name, list_path, timeout=TIMEOUT_SETTINGS['dir_list'])
            if files:
                cache_manager.cache_share(ip, cache_key, files)
        
        for file in files:
            if shutdown_flag.is_set(): break
            if file.filename in ['.', '..']: continue
            
            # Paths
            if not smb_path or smb_path == '/':
                smb_file_path = file.filename
            else:
                smb_file_path = f"{smb_path}/{file.filename}"
            
            display_file_path = normalize_smb_path(smb_file_path.replace('/', '\\'))
            file_extension = os.path.splitext(file.filename)[1].lower()
            
            # Apply filename pattern filter
            if filters.get('filename_pattern'):
                if not filters['filename_pattern'].search(file.filename):
                    verbose_print(f"[*] Skipping {file.filename} (pattern mismatch)")
                    continue
            
            # Apply extension filters (skip directories)
            if not file.isDirectory:
                if filters.get('include_ext'):
                    if file_extension.lstrip('.') not in filters['include_ext']:
                        continue
                
                if filters.get('exclude_ext'):
                    ext_normalized = file_extension.lstrip('.')
                    if ext_normalized in filters['exclude_ext']:
                        verbose_print(f"[*] Skipping {file.filename} (excluded extension: .{ext_normalized})")
                        continue
                
                # Apply size filters
                if file.file_size < filters.get('min_size', 0):
                    continue
                if file.file_size > filters.get('max_size', DEFAULT_MAX_FILE_SIZE):
                    verbose_print(f"[*] Skipping {file.filename} (too large: {file.file_size} bytes)")
                    continue
            
            # Check Sensitive Filenames/Extensions (before size check for max_read_bytes)
            # This allows large sensitive files to be detected and downloaded even if content can't be read
            is_sensitive = False
            sensitive_type = None
            
            # Check exact filename match
            if file.filename in SENSITIVE_FILENAMES:
                is_sensitive = True
                sensitive_type = SENSITIVE_FILENAMES[file.filename]
            # Check extension match
            elif file_extension in SENSITIVE_EXTENSIONS:
                is_sensitive = True
                sensitive_type = SENSITIVE_EXTENSIONS[file_extension]
            # Check for sensitive keywords in filename (case-insensitive)
            else:
                filename_lower = file.filename.lower()
                sensitive_keywords = {
                    'password': 'Password File',
                    'parola': 'Password File',
                    'secret': 'Secret File',
                    'sifre': 'Password File',
                    'credential': 'Credential File',
                    'hash': 'Hash File',
                    'key': 'Key File',
                    'token': 'Token File',
                    'api': 'API File',
                    'cred': 'Credential File',
                    'nessus': 'Nessus Scan File'
                }
                for keyword, desc in sensitive_keywords.items():
                    if keyword in filename_lower:
                        is_sensitive = True
                        sensitive_type = desc
                        break
            
            # Check if content reading should be skipped due to size
            skip_content_read = False
            if file.file_size > filters.get('max_read_bytes', DEFAULT_MAX_READ_BYTES):
                verbose_print(f"[*] Skipping content read for {file.filename} (size {file.file_size} > max_read_bytes)")
                skip_content_read = True
            
            if is_sensitive:
                # sensitive_type already determined above
                if not sensitive_type:
                    sensitive_type = 'Sensitive File'
                downloaded = download_file_with_fallback(conn, share_name, smb_file_path, ip, file_size=file.file_size)
                
                local_stats['sensitive_files_found'] += 1
                if downloaded:
                    local_stats['files_downloaded'] += 1
                
                local_results.append({
                    'category': 'sensitive_file',
                    'match': f'Found {sensitive_type}',
                    'ip': ip,
                    'share': share_name,
                    'path': display_file_path,
                    'file_type': sensitive_type,
                    'show_full_path': False,
                    'downloaded_file': downloaded
                })
                print_finding("SENSITIVE_FILE", f"Found {sensitive_type}", f"\\\\{ip}\\{share_name}\\{display_file_path}")

            if file.isDirectory:
                scan_share(conn, share_name, smb_file_path, ip, local_stats, local_results, local_files, timeout)
            else:
                # File Processing
                file_info = {
                    'ip': ip,
                    'share': share_name,
                    'path': display_file_path,
                    'size': file.file_size,
                    'create_time': datetime.fromtimestamp(file.create_time).strftime('%Y-%m-%d %H:%M:%S'),
                    'last_write_time': datetime.fromtimestamp(file.last_write_time).strftime('%Y-%m-%d %H:%M:%S'),
                    'show_full_path': False
                }
                local_files.append(file_info)
                local_stats['files_scanned'] += 1
                
                # Skip binary files unless they're sensitive
                if (file_extension in BINARY_EXTENSIONS and not is_sensitive) or (file.file_size > DEFAULT_MAX_FILE_SIZE and not is_sensitive):
                    continue
                
                # Read file content if not skipped
                content = None
                if not skip_content_read:
                    content = cache_manager.get_cached_file(display_file_path, file.file_size, file.last_write_time)
                    if not content:
                        scan_status.update(share=share_name, action="Reading file", path=display_file_path)
                        content = read_file_content(conn, share_name, smb_file_path)
                        if content:
                            cache_manager.cache_file(display_file_path, file.file_size, file.last_write_time, content)
                            local_stats['bytes_read'] += len(content)
                
                # Process content if available
                if content:
                    ftype = get_file_type(content)
                    file_info['file_type'] = ftype
                    
                    if not is_sensitive and any(x in ftype for x in ['application/x-executable', 'octet-stream']):
                        continue
                        
                    matches = check_sensitive_patterns(content, ftype, ip)
                    if matches:
                        full_path = f"\\\\{ip}\\{share_name}\\{display_file_path}"
                        print_section(f"Sensitive Content Detected")
                        quiet_print(f"  {Colors.CYAN}📍 File:{Colors.RESET} {Colors.WHITE}{Colors.BOLD}{full_path}{Colors.RESET}")
                        quiet_print(f"  {Colors.CYAN}📋 Type:{Colors.RESET} {Colors.WHITE}{ftype}{Colors.RESET}")
                        
                        # Download file once for all matches (avoid multiple downloads of same file)
                        downloaded = download_file_with_fallback(conn, share_name, smb_file_path, ip, file_size=file.file_size, content=content)
                        if downloaded:
                            local_stats['files_downloaded'] += 1
                        else:
                            verbose_print(f"[!] WARNING: Could not download file {smb_file_path} - Open File button will not appear")
                        
                        local_stats['sensitive_content_found'] += len(matches)
                        # Count file as sensitive file if it has sensitive content
                        local_stats['sensitive_files_found'] += 1
                        
                        for match in matches:
                            print_finding(match['category'], match['match'])
                            match.update({
                                'ip': ip,
                                'share': share_name,
                                'path': display_file_path,
                                'file_type': ftype,
                                'show_full_path': False,
                                'downloaded_file': downloaded
                            })
                            local_results.append(match)
                        quiet_print("")
                elif is_sensitive and skip_content_read:
                    # Large sensitive file - download it even if we can't read content
                    sensitive_type = SENSITIVE_FILENAMES.get(file.filename) or SENSITIVE_EXTENSIONS.get(file_extension) or 'Sensitive File (Large)'
                    downloaded = download_file_with_fallback(conn, share_name, smb_file_path, ip, file_size=file.file_size)
                    
                    local_stats['sensitive_files_found'] += 1
                    if downloaded:
                        local_stats['files_downloaded'] += 1
                    
                    local_results.append({
                        'category': 'sensitive_file',
                        'match': f'Found {sensitive_type} (Large file, content not analyzed)',
                        'ip': ip,
                        'share': share_name,
                        'path': display_file_path,
                        'file_type': sensitive_type,
                        'show_full_path': False,
                        'downloaded_file': downloaded
                    })
                    print_finding("SENSITIVE_FILE", f"Found {sensitive_type} (Large)", f"\\\\{ip}\\{share_name}\\{display_file_path}")

    except (ConnectionError, TimeoutError, OSError) as e:
        from jesur.utils.logger import log_debug
        log_debug(f"Network error scanning share {share_name}: {e}")
    except Exception as e:
        from jesur.utils.logger import log_error
        log_error(f"Unexpected error scanning share {share_name}: {e}", exc_info=True)

def scan_host(
    ip: str,
    target_share: Optional[str] = None,
    list_shares_only: bool = False,
    username: str = "guest",
    password: str = "",
    domain: str = "WORKGROUP",
    lm_hash: Optional[str] = None,
    nt_hash: Optional[str] = None
) -> Dict[str, Any]:
    """
    Scan a single host for SMB shares and files.
    
    Args:
        ip: IP address to scan
        target_share: Optional specific share to scan (None = all shares)
        list_shares_only: If True, only list shares without scanning contents
        username: SMB username
        password: SMB password
        domain: SMB domain/workgroup
        lm_hash: LM hash for pass-the-hash authentication (optional)
        nt_hash: NT hash for pass-the-hash authentication (optional)
        
    Returns:
        Dictionary with 'stats', 'results', and 'files' keys
    """
    # Thread-local stats to avoid race conditions
    local_stats = {
        'hosts_with_smb': 0,
        'shares_found': 0,
        'readable_shares': 0,
        'writable_shares': 0,
        'files_scanned': 0,
        'sensitive_files_found': 0,
        'sensitive_content_found': 0,
        'bytes_read': 0,
        'files_downloaded': 0
    }
    
    # Thread-local results and files lists
    local_results = []
    local_files = []
    
    scan_status.update(ip=ip, action="Scanning ports...")
    
    from jesur.core.constants import SMB_PORT_DIRECT, SMB_PORT_NETBIOS
    available_port = None
    for port in [SMB_PORT_DIRECT, SMB_PORT_NETBIOS]:
        if check_port(ip, port, timeout=TIMEOUT_SETTINGS['port_scan']):
            available_port = port
            break
            
    if not available_port:
        verbose_print(f"[-] No SMB ports open on {ip}")
        return {
            'stats': local_stats,
            'results': [],
            'files': []
        }

    scan_status.update(action="Authenticating...")
    
    if lm_hash or nt_hash:
        # Pass hashes separately; connection pool handles NTLMv1 setup
        password = password or ""

    try:
        conn = connection_pool.get_connection(
            ip, username, password, domain,
            is_direct_tcp=(available_port == 445),
            timeout=3,
            lm_hash=lm_hash,
            nt_hash=nt_hash
        )
        
        if conn:
            try:
                scan_status.update(action="Listing shares...")
                if shutdown_flag.is_set(): return local_stats
                
                shares = cache_manager.get_cached_share(ip, "shares")
                if not shares:
                    shares = conn.listShares(timeout=TIMEOUT_SETTINGS['share_list'])
                    cache_manager.cache_share(ip, "shares", shares)
                local_stats['hosts_with_smb'] = 1
                
                if shares:
                    local_stats['shares_found'] = len(shares)
                    quiet_print(f"\n[*] SMB Shares found: {ip}")
                    quiet_print(f"[+] Connection successful: {username}@{domain}")
                    verbose_print(f"\n[*] Share List ({ip}):", force=True)
                    verbose_print("-" * 60, force=True)
                    verbose_print(f"{'Share Name':<20} {'Type':<15} {'Read':<8} {'Write':<8} {'Comments':<30}", force=True)
                    verbose_print("-" * 60, force=True)
                    
                    # Get filters from context
                    from jesur.core import context
                    filters = getattr(context, 'scan_filters', {})
                    
                    for share in shares:
                        share_type = "Disk" if share.type == 0 else "Printer" if share.type == 1 else "IPC"
                        
                        # Check if share should be excluded (Case-Insensitive)
                        excluded_shares_upper = {s.upper() for s in filters.get('exclude_shares', set())}
                        if share.name.upper() in excluded_shares_upper:
                            verbose_print(f"[*] Skipping excluded share: {share.name}")
                            continue
                        
                        if target_share and share.name.lower() != target_share.lower():
                            continue
                        
                        if share.type == 0: # Disk
                            scan_status.update(share=share.name, action="Checking permissions...")
                            perms = check_share_permissions(conn, share.name, local_stats, timeout=5)
                            verbose_print(f"{share.name:<20} {share_type:<15} {'Yes' if perms['read'] else 'No':<8} {'Yes' if perms['write'] else 'No':<8} {share.comments:<30}", force=True)
                            
                            if perms['read'] and not list_shares_only:
                                scan_status.update(action="Scanning contents...")
                                scan_share(conn, share.name, "/", ip, local_stats, local_results, local_files)
                        else:
                            verbose_print(f"{share.name:<20} {share_type:<15} {'-':<8} {'-':<8} {share.comments:<30}", force=True)
                else:
                    verbose_print(f"[-] No shares found on {ip}")
            finally:
                # Release connection with auth info for proper key matching
                connection_pool.release_connection(ip, username, domain, password, lm_hash, nt_hash)
        else:
            verbose_print(f"[-] Failed to connect to {ip} - authentication may have failed")
    except (ConnectionError, TimeoutError, OSError) as e:
        from jesur.utils.logger import log_debug
        log_debug(f"Network error scanning {ip}: {e}")
    except Exception as e:
        from jesur.utils.logger import log_error
        log_error(f"Unexpected error scanning {ip}: {e}", exc_info=True)
    
    # Return stats, results, and files
    return {
        'stats': local_stats,
        'results': local_results,
        'files': local_files
    }

