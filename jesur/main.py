"""
JESUR - Enhanced SMB Share Scanner
Main application module

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
import sys
import os
import argparse
import signal
import time
import ipaddress
import traceback
import re
import logging
import configparser
from typing import Any, Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, wait

# Suppress pysmb debug messages
logging.getLogger('SMB').setLevel(logging.ERROR)
logging.getLogger('SMB.SMBConnection').setLevel(logging.ERROR)
logging.getLogger('nmb.NetBIOS').setLevel(logging.ERROR)

from jesur.core import context
from jesur.core.context import shutdown_flag, scan_status, scan_stats, results, all_files
from jesur.utils.common import Colors, print_header, print_section, format_bytes, format_duration, quiet_print, verbose_print
from jesur.utils.geo import list_country_codes, get_country_ip_ranges
from jesur.reporting.generator import save_results
from jesur.reporting.exporter import export_to_json, export_to_csv, get_export_filenames, export_statistics

# Global for tracking Ctrl+C press count
_shutdown_count = 0
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, 'jesur.conf')


def str_to_bool(val):
    return str(val).lower() in ['1', 'true', 'yes', 'y', 'on']


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from INI file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Dictionary containing configuration values
    """
    cfg = configparser.ConfigParser()
    if not os.path.exists(config_path):
        return {}
    cfg.read(config_path)
    conf: Dict[str, Any] = {}

    def optional(value):
        if value is None:
            return None
        if isinstance(value, str) and value.strip() == '':
            return None
        return value
    scan = cfg['scan'] if 'scan' in cfg else {}
    auth = cfg['auth'] if 'auth' in cfg else {}
    filters = cfg['filters'] if 'filters' in cfg else {}
    output = cfg['output'] if 'output' in cfg else {}

    # Scan section
    conf['network'] = optional(scan.get('network'))
    conf['file'] = optional(scan.get('file'))
    conf['geo'] = optional(scan.get('geo'))
    conf['geo_list'] = str_to_bool(scan.get('geo_list', False))
    conf['share'] = optional(scan.get('share'))
    conf['list_shares'] = str_to_bool(scan.get('list_shares', False))
    conf['threads'] = scan.getint('threads', fallback=None)
    from jesur.core.constants import RATE_LIMIT_UNLIMITED
    conf['rate_limit'] = scan.getint('rate_limit', fallback=RATE_LIMIT_UNLIMITED)
    from jesur.core.constants import TIMEOUT_HOST_DEFAULT
    conf['host_timeout'] = scan.getint('host_timeout', fallback=TIMEOUT_HOST_DEFAULT)

    # Auth section
    conf['username'] = optional(auth.get('username', 'guest')) or 'guest'
    conf['password'] = optional(auth.get('password', '')) or ''
    conf['hashes'] = optional(auth.get('hashes', None))
    conf['domain'] = optional(auth.get('domain', 'WORKGROUP')) or 'WORKGROUP'

    # Filters section
    conf['include_ext'] = optional(filters.get('include_ext'))
    conf['exclude_ext'] = optional(filters.get('exclude_ext'))
    conf['min_size'] = filters.getint('min_size', fallback=0)
    from jesur.core.constants import MAX_FILE_SIZE_DEFAULT, MAX_READ_BYTES_DEFAULT
    conf['max_size'] = filters.getint('max_size', fallback=MAX_FILE_SIZE_DEFAULT)
    conf['max_read_bytes'] = filters.getint('max_read_bytes', fallback=MAX_READ_BYTES_DEFAULT)
    conf['filename_pattern'] = optional(filters.get('filename_pattern'))
    conf['exclude_shares'] = optional(filters.get('exclude_shares'))
    conf['include_admin_shares'] = str_to_bool(filters.get('include_admin_shares', False))
    conf['exclude_file'] = optional(filters.get('exclude_file'))

    # Output section
    conf['output_json'] = str_to_bool(output.get('output_json', False))
    conf['output_csv'] = str_to_bool(output.get('output_csv', False))
    conf['output_name'] = output.get('output_name', 'jesur')
    conf['quiet'] = str_to_bool(output.get('quiet', False))
    conf['verbose'] = str_to_bool(output.get('verbose', False))
    conf['no_stats'] = str_to_bool(output.get('no_stats', False))

    return conf

def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate configuration values and raise ValueError for invalid settings.
    
    Args:
        config: Configuration dictionary to validate
        
    Returns:
        True if configuration is valid
        
    Raises:
        ValueError: If configuration contains invalid values
    """
    from jesur.core.constants import (
        MAX_THREADS, MIN_THREADS, TIMEOUT_HOST_DEFAULT,
        MAX_FILE_SIZE_DEFAULT, MAX_READ_BYTES_DEFAULT
    )
    
    errors = []
    
    # Validate threads
    if config.get('threads') is not None:
        threads = config['threads']
        if not isinstance(threads, int) or threads < 1 or threads > MAX_THREADS:
            errors.append(f"threads must be an integer between 1 and {MAX_THREADS}, got: {threads}")
    
    # Validate rate_limit
    if config.get('rate_limit') is not None:
        rate_limit = config['rate_limit']
        if not isinstance(rate_limit, int) or rate_limit < 0:
            errors.append(f"rate_limit must be a non-negative integer, got: {rate_limit}")
    
    # Validate host_timeout
    if config.get('host_timeout') is not None:
        host_timeout = config['host_timeout']
        if not isinstance(host_timeout, int) or host_timeout < 1:
            errors.append(f"host_timeout must be a positive integer (seconds), got: {host_timeout}")
    
    # Validate file size filters
    if config.get('min_size') is not None:
        min_size = config['min_size']
        if not isinstance(min_size, int) or min_size < 0:
            errors.append(f"min_size must be a non-negative integer (bytes), got: {min_size}")
    
    if config.get('max_size') is not None:
        max_size = config['max_size']
        if not isinstance(max_size, int) or max_size < 1:
            errors.append(f"max_size must be a positive integer (bytes), got: {max_size}")
        else:
            from jesur.core.constants import MAX_FILE_SIZE_LIMIT
            if max_size > MAX_FILE_SIZE_LIMIT:
                errors.append(f"max_size exceeds reasonable limit ({MAX_FILE_SIZE_LIMIT // (1024*1024)}MB), got: {max_size}")
    
    if config.get('max_read_bytes') is not None:
        max_read_bytes = config['max_read_bytes']
        if not isinstance(max_read_bytes, int) or max_read_bytes < 1:
            errors.append(f"max_read_bytes must be a positive integer (bytes), got: {max_read_bytes}")
        else:
            from jesur.core.constants import MAX_READ_BYTES_LIMIT
            if max_read_bytes > MAX_READ_BYTES_LIMIT:
                errors.append(f"max_read_bytes exceeds reasonable limit ({MAX_READ_BYTES_LIMIT // (1024*1024)}MB), got: {max_read_bytes}")
    
    # Validate size relationships
    if config.get('min_size') is not None and config.get('max_size') is not None:
        if config['min_size'] > config['max_size']:
            errors.append(f"min_size ({config['min_size']}) cannot be greater than max_size ({config['max_size']})")
    
    # Validate filename_pattern (regex)
    if config.get('filename_pattern'):
        try:
            import re
            re.compile(config['filename_pattern'])
        except re.error as e:
            errors.append(f"Invalid regex pattern in filename_pattern: {e}")
    
    # Validate hashes format if provided
    if config.get('hashes'):
        hashes = config['hashes']
        if ':' in hashes:
            parts = hashes.split(':')
            if len(parts) != 2:
                errors.append("hashes must be in format LMHASH:NTHASH (exactly 2 parts)")
            else:
                lm_hash, nt_hash = parts
                if len(lm_hash) != 32 or len(nt_hash) != 32:
                    errors.append("Each hash must be exactly 32 hexadecimal characters")
                else:
                    try:
                        int(lm_hash, 16)
                        int(nt_hash, 16)
                    except ValueError:
                        errors.append("Hashes must be valid hexadecimal strings")
        else:
            if len(hashes) != 32:
                errors.append("Single hash must be exactly 32 hexadecimal characters")
            else:
                try:
                    int(hashes, 16)
                except ValueError:
                    errors.append("Hash must be a valid hexadecimal string")
    
    if errors:
        error_msg = "Configuration validation errors:\n" + "\n".join(f"  - {e}" for e in errors)
        raise ValueError(error_msg)
    
    return True

def signal_handler(sig, frame):
    """Handle Ctrl+C signal - immediately shutdown and save reports."""
    global _shutdown_count
    _shutdown_count += 1
    
    if _shutdown_count == 1:
        shutdown_flag.set()
        print(f"\n\n{Colors.YELLOW}{Colors.BOLD}[!] Ctrl+C detected. Shutting down gracefully...{Colors.RESET}", flush=True)
        print(f"{Colors.DIM}[*] Press Ctrl+C again to force quit immediately{Colors.RESET}", flush=True)
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}[!!] Force quit!{Colors.RESET}", flush=True)
        import os
        os._exit(1)


def load_exclude_ips(exclude_file: Optional[str]) -> Set[ipaddress.IPv4Network]:
    """
    Load excluded IPs/networks from file.
    
    Args:
        exclude_file: Path to file containing IPs/networks to exclude
        
    Returns:
        Set of IPv4Network objects representing excluded networks
    """
    excluded: Set[ipaddress.IPv4Network] = set()
    if not exclude_file or not os.path.exists(exclude_file):
        return excluded
    
    try:
        with open(exclude_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    from jesur.core.constants import CIDR_DEFAULT_MASK
                    try:
                        if '/' not in line:
                            line = f"{line}/{CIDR_DEFAULT_MASK}"
                        net = ipaddress.IPv4Network(line, strict=False)
                        excluded.add(net)
                    except ValueError:
                        verbose_print(f"[!] Invalid exclude entry: {line}")
    except (IOError, OSError) as e:
        from jesur.utils.logger import log_error
        log_error(f"IO error loading exclude file {exclude_file}: {e}")
        print(f"{Colors.YELLOW}[!] Error loading exclude file: {e}{Colors.RESET}")
    except Exception as e:
        from jesur.utils.logger import log_error
        log_error(f"Unexpected error loading exclude file {exclude_file}: {e}", exc_info=True)
        print(f"{Colors.YELLOW}[!] Error loading exclude file: {e}{Colors.RESET}")
    
    return excluded

def is_ip_excluded(ip_str: str, excluded_networks: Set[ipaddress.IPv4Network]) -> bool:
    """
    Check if IP is in any excluded network.
    
    Args:
        ip_str: IP address as string
        excluded_networks: Set of excluded IPv4Network objects
        
    Returns:
        True if IP is excluded, False otherwise
    """
    if not excluded_networks:
        return False
    
    ip = ipaddress.IPv4Address(ip_str)
    for net in excluded_networks:
        if ip in net:
            return True
    return False

def print_statistics(stats_dict: Dict[str, Any]) -> None:
    """
    Print scan statistics in a formatted table.
    
    Args:
        stats_dict: Dictionary containing scan statistics
    """
    duration = stats_dict.get('end_time', time.time()) - stats_dict.get('start_time', time.time())
    
    print_section("Scan Statistics")
    print(f"  {Colors.CYAN}Duration:{Colors.RESET} {Colors.WHITE}{format_duration(duration)}{Colors.RESET}")
    print(f"  {Colors.CYAN}Hosts Scanned:{Colors.RESET} {Colors.WHITE}{stats_dict.get('hosts_scanned', 0)}{Colors.RESET}")
    print(f"  {Colors.CYAN}Hosts with SMB:{Colors.RESET} {Colors.WHITE}{stats_dict.get('hosts_with_smb', 0)}{Colors.RESET}")
    print(f"  {Colors.CYAN}Total Shares:{Colors.RESET} {Colors.WHITE}{stats_dict.get('shares_found', 0)}{Colors.RESET}")
    print(f"    {Colors.DIM}├─ Readable:{Colors.RESET} {Colors.WHITE}{stats_dict.get('readable_shares', 0)}{Colors.RESET}")
    print(f"    {Colors.DIM}└─ Writable:{Colors.RESET} {Colors.WHITE}{stats_dict.get('writable_shares', 0)}{Colors.RESET}")
    print(f"  {Colors.CYAN}Files Scanned:{Colors.RESET} {Colors.WHITE}{stats_dict.get('files_scanned', 0)}{Colors.RESET}")
    print(f"  {Colors.CYAN}Data Read:{Colors.RESET} {Colors.WHITE}{format_bytes(stats_dict.get('bytes_read', 0))}{Colors.RESET}")
    print(f"  {Colors.CYAN}Sensitive Findings:{Colors.RESET}")
    print(f"    {Colors.DIM}├─ Files:{Colors.RESET} {Colors.RED}{stats_dict.get('sensitive_files_found', 0)}{Colors.RESET}")
    print(f"    {Colors.DIM}├─ Content Matches:{Colors.RESET} {Colors.RED}{stats_dict.get('sensitive_content_found', 0)}{Colors.RESET}")
    print(f"    {Colors.DIM}└─ Downloaded:{Colors.RESET} {Colors.GREEN}{stats_dict.get('files_downloaded', 0)}{Colors.RESET}")
    print()

def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    initial_parser = argparse.ArgumentParser(add_help=False)
    initial_parser.add_argument('--config', help='Config file path', default=DEFAULT_CONFIG_PATH)
    initial_args, remaining_argv = initial_parser.parse_known_args()
    config_values = load_config(initial_args.config)
    
    # Validate configuration
    try:
        validate_config(config_values)
    except ValueError as e:
        print(f"{Colors.RED}[!] Configuration Error:{Colors.RESET}")
        print(str(e))
        sys.exit(1)

    parser = argparse.ArgumentParser(
        parents=[initial_parser],
        description='JESUR - SMB Share Scanner - Enhanced Penetration Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24                    # Scan a network
  %(prog)s -f targets.txt --threads 30       # Scan from file
  %(prog)s --geo tr_TR --quiet               # Scan Turkey IPs (quiet mode)
  %(prog)s 10.0.0.0/8 --exclude-ext exe,dll  # Exclude binary files
  %(prog)s 192.168.1.0/24 --min-size 1024    # Files >= 1KB only
        """
    )

    # Target specification
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('network', help='Network to scan (CIDR format, e.g.: 192.168.1.0/24)', nargs='?')
    group.add_argument('-f', '--file', help='File containing networks in CIDR format')
    group.add_argument('--geo', help='Country code to scan (e.g., tr_TR, us_US)')
    group.add_argument('--geo-list', help='List all available country codes', action='store_true')
    
    # Authentication
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument('-u', '--username', help='Domain username', default='guest')
    auth_group.add_argument('-p', '--password', help='User password', default='')
    auth_group.add_argument('--hashes', help='NTLM hashes (LMHASH:NTHASH)', default=None)
    auth_group.add_argument('-d', '--domain', help='Domain name', default='WORKGROUP')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--share', help='Scan only specified share')
    scan_group.add_argument('--list-shares', help='Only list shares, do not scan contents', action='store_true')
    scan_group.add_argument('--threads', help='Number of parallel connections (default: auto)', type=int)
    scan_group.add_argument('--rate-limit', help='Max IPs to scan per second (0=unlimited)', type=int, default=0)
    
    # Filtering options
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument('--include-ext', help='Only scan files with these extensions (comma-separated)', type=str)
    filter_group.add_argument('--exclude-ext', help='Skip files with these extensions (comma-separated)', type=str)
    filter_group.add_argument('--min-size', help='Minimum file size in bytes', type=int, default=0)
    from jesur.core.constants import MAX_FILE_SIZE_DEFAULT, MAX_READ_BYTES_DEFAULT
    filter_group.add_argument('--max-size', help='Maximum file size in bytes', type=int, default=MAX_FILE_SIZE_DEFAULT)
    filter_group.add_argument('--max-read-bytes', help='Maximum bytes to read from a file (content scan)', type=int, default=MAX_READ_BYTES_DEFAULT)
    filter_group.add_argument('--filename-pattern', help='Regex pattern for filename matching', type=str)
    filter_group.add_argument('--exclude-shares', help='Shares to exclude (comma-separated, e.g., IPC$,ADMIN$)', type=str)
    filter_group.add_argument('--include-admin-shares', help='Include administrative shares (C$, ADMIN$, etc.)', action='store_true')
    filter_group.add_argument('--exclude-file', help='File containing IPs/networks to exclude')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output-json', help='Export results to JSON', action='store_true')
    output_group.add_argument('--output-csv', help='Export results to CSV', action='store_true')
    output_group.add_argument('--output-name', help='Base name for output files', default='jesur')
    output_group.add_argument('--quiet', '-q', help='Quiet mode - minimal output', action='store_true')
    output_group.add_argument('--verbose', '-v', help='Verbose mode - detailed output', action='store_true')
    output_group.add_argument('--no-stats', help='Do not print statistics', action='store_true')
    parser.add_argument('--host-timeout', help='Per-host timeout (seconds)', type=int)

    parser.set_defaults(**config_values)
    args = parser.parse_args(remaining_argv)

    # Fill positional network from config if missing
    if not any([args.network, args.file, args.geo, args.geo_list]):
        if config_values.get('network'):
            args.network = config_values.get('network')
        elif config_values.get('file'):
            args.file = config_values.get('file')
        elif config_values.get('geo'):
            args.geo = config_values.get('geo')

    if not any([args.network, args.file, args.geo, args.geo_list]):
        parser.error('One of network, --file, --geo or --geo-list must be provided (CLI or config).')

    # Set global verbosity
    context.verbose_mode = args.verbose
    context.quiet_mode = args.quiet

    if args.geo_list:
        list_country_codes()
        sys.exit(0)

    # Parse filters
    def normalize_extensions(ext_str):
        """Normalize extension string: remove dots, spaces, and empty values."""
        if not ext_str:
            return None
        extensions = []
        for ext in ext_str.lower().split(','):
            ext = ext.strip().lstrip('.')
            if ext:
                extensions.append(ext)
        return set(extensions) if extensions else None
    
    scan_filters = {
        'include_ext': normalize_extensions(args.include_ext),
        'exclude_ext': normalize_extensions(args.exclude_ext),
        'min_size': args.min_size,
        'max_size': args.max_size,
        'max_read_bytes': args.max_read_bytes,
        'filename_pattern': re.compile(args.filename_pattern) if args.filename_pattern else None,
        'exclude_shares': set(s.upper().strip() for s in args.exclude_shares.split(',') if s.strip()) if args.exclude_shares else set(),
        'include_admin_shares': args.include_admin_shares,
    }
    
    # Debug: Show parsed filters
    if args.verbose:
        verbose_print(f"[DEBUG] Exclude extensions: {scan_filters['exclude_ext']}")
        verbose_print(f"[DEBUG] Include extensions: {scan_filters['include_ext']}")
    
    
    # Add default admin shares to exclude if not explicitly included
    if not scan_filters['include_admin_shares']:
        scan_filters['exclude_shares'].update(['IPC$', 'ADMIN$', 'C$', 'D$', 'E$', 'USERS'])
    
    # Store filters in context for scanner to access
    context.scan_filters = scan_filters

    # Parse Hashes
    lm_hash = nt_hash = None
    if args.hashes:
        try:
            if ':' in args.hashes:
                lm_hash, nt_hash = args.hashes.split(':')
            else:
                nt_hash = args.hashes
                lm_hash = "00000000000000000000000000000000"
        except (ValueError, AttributeError) as e:
            from jesur.utils.errors import ErrorMessages
            print(f"{Colors.RED}[!] Error: Invalid hash format.{Colors.RESET}")
            print(ErrorMessages.format(ErrorMessages.CONFIG_INVALID_HASH_FORMAT))
            sys.exit(1)
        except Exception as e:
            from jesur.utils.logger import log_error
            log_error(f"Unexpected error parsing hashes: {e}", exc_info=True)
            print(f"{Colors.RED}[!] Error: Invalid hash format.{Colors.RESET}")
            sys.exit(1)

    # Load excluded IPs
    excluded_networks = load_exclude_ips(args.exclude_file)
    if excluded_networks:
        verbose_print(f"[*] Loaded {len(excluded_networks)} excluded networks")

    # Prepare networks
    networks = []
    total_hosts = 0
    
    if args.geo:
        country_code = args.geo.split('_')[0].upper()
        networks = get_country_ip_ranges(country_code)
        if not networks:
            print(f"[-] No IP ranges found for {country_code}")
            sys.exit(1)
        total_hosts = sum(max(1, net.num_addresses - 2) for net in networks)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        from jesur.core.constants import CIDR_DEFAULT_MASK
                        try:
                            if '/' not in line: line = f"{line}/{CIDR_DEFAULT_MASK}"
                            net = ipaddress.IPv4Network(line, strict=False)
                            networks.append(net)
                            total_hosts += max(1, net.num_addresses - 2)
                        except ValueError:
                            print(f"[-] Invalid network: {line}")
        except FileNotFoundError:
            print(f"[-] File not found: {args.file}")
            sys.exit(1)
    else:
        try:
            net = ipaddress.IPv4Network(args.network, strict=False)
            networks.append(net)
            total_hosts = max(1, net.num_addresses - 2)
        except ValueError:
            print(f"[-] Invalid network format: {args.network}")
            sys.exit(1)

    # Threading calc
    from jesur.core.constants import (
        MAX_THREADS, MIN_THREADS, DEFAULT_THREADS_SMALL_NETWORK,
        DEFAULT_THREADS_MEDIUM_NETWORK, SMALL_NETWORK_THRESHOLD,
        MEDIUM_NETWORK_THRESHOLD
    )
    if args.threads:
        max_workers = min(args.threads, MAX_THREADS)
    else:
        if total_hosts <= SMALL_NETWORK_THRESHOLD:
            max_workers = DEFAULT_THREADS_SMALL_NETWORK
        elif total_hosts <= MEDIUM_NETWORK_THRESHOLD:
            max_workers = total_hosts
        else:
            max_workers = min(DEFAULT_THREADS_MEDIUM_NETWORK, total_hosts // 2)

    print_header("JESUR - SMB Share Scanner")
    
    if not args.quiet:
        print_section("Scan Configuration")
        print(f"  {Colors.CYAN}Target Hosts:{Colors.RESET} {Colors.WHITE}{total_hosts}{Colors.RESET}")
        print(f"  {Colors.CYAN}Threads:{Colors.RESET} {Colors.WHITE}{max_workers}{Colors.RESET}")
        print(f"  {Colors.CYAN}Auth:{Colors.RESET} {Colors.WHITE}{args.username}@{args.domain}{Colors.RESET}")
        if args.rate_limit:
            print(f"  {Colors.CYAN}Rate Limit:{Colors.RESET} {Colors.WHITE}{args.rate_limit} IPs/sec{Colors.RESET}")
        if scan_filters['include_ext']:
            print(f"  {Colors.CYAN}Include Extensions:{Colors.RESET} {Colors.WHITE}{', '.join(scan_filters['include_ext'])}{Colors.RESET}")
        if scan_filters['exclude_ext']:
            print(f"  {Colors.CYAN}Exclude Extensions:{Colors.RESET} {Colors.WHITE}{', '.join(scan_filters['exclude_ext'])}{Colors.RESET}")
        if scan_filters['filename_pattern']:
            print(f"  {Colors.CYAN}Filename Pattern:{Colors.RESET} {Colors.WHITE}{args.filename_pattern}{Colors.RESET}")
        print()

    # Execution
    completed_hosts = 0
    start_time = time.time()
    last_progress_update = 0
    scan_stats.start_time = start_time
    from jesur.core.constants import TIMEOUT_HOST_DEFAULT
    host_timeout = args.host_timeout if args.host_timeout else TIMEOUT_HOST_DEFAULT
    
    # Rate limiting
    last_submit_time = time.time()
    rate_limit_delay = 1.0 / args.rate_limit if args.rate_limit > 0 else 0
    
    # Build IP list for scanning
    ip_list = []
    for net in networks:
        for ip in net.hosts():
            if shutdown_flag.is_set(): 
                break
            ip_str = str(ip)
            if is_ip_excluded(ip_str, excluded_networks):
                verbose_print(f"[*] Skipping excluded IP: {ip_str}")
                continue
            ip_list.append(ip_str)

    total_hosts = len(ip_list)
    
    # Import scanner
    from jesur.core.process_scanner import scan_host_with_timeout
    
    quiet_print(f"\n{Colors.CYAN}Progress:{Colors.RESET} Starting scan...")
    
    # Progress monitor
    import threading
    completed_lock = threading.Lock()
    def get_completed():
        with completed_lock:
            return completed_hosts
    
    from jesur.core.constants import PROGRESS_UPDATE_INTERVAL, PROGRESS_MONITOR_SLEEP
    def progress_monitor():
        last_monitor_update = 0
        while not shutdown_flag.is_set():
            current_time = time.time()
            if (current_time - last_monitor_update) >= PROGRESS_UPDATE_INTERVAL:
                last_monitor_update = current_time
                status = scan_status.get_status()
                elapsed = current_time - start_time
                done = get_completed()
                progress = (done / total_hosts) * 100 if total_hosts > 0 else 0
                
                if done > 0:
                    rate = done / elapsed
                    remaining = total_hosts - done
                    eta = remaining / rate if rate > 0 else 0
                    eta_str = f"ETA: {format_duration(eta)}"
                else:
                    eta_str = "ETA: calculating..."
                
                action_parts = []
                if status.get('share'):
                    action_parts.append(status['share'])
                if status.get('path'):
                    action_parts.append(status['path'])
                if status.get('action'):
                    action_parts.append(status['action'])
                action_str = " / ".join([str(x) for x in action_parts if x])
                
                msg = f"\r{Colors.CYAN}Progress:{Colors.RESET} [{done}/{total_hosts}] {progress:.1f}% | {Colors.DIM}{status['ip']} {action_str}{Colors.RESET} | {Colors.DIM}{eta_str}{Colors.RESET}      "
                sys.stdout.write(msg[:120])
                sys.stdout.flush()
            time.sleep(PROGRESS_MONITOR_SLEEP)
    
    monitor_thread = threading.Thread(target=progress_monitor, daemon=True)
    if not args.quiet:
        monitor_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {}
            future_start = {}
            for ip in ip_list:
                if shutdown_flag.is_set():
                    break
                
                if rate_limit_delay > 0:
                    current_time = time.time()
                    elapsed = current_time - last_submit_time
                    if elapsed < rate_limit_delay:
                        time.sleep(rate_limit_delay - elapsed)
                    last_submit_time = time.time()
                
                scan_status.update(ip=ip, action="Scanning...")
                future = executor.submit(
                    scan_host_with_timeout,
                    ip=ip,
                    timeout=host_timeout,
                    target_share=args.share,
                    list_shares_only=args.list_shares,
                    username=args.username,
                    password=args.password,
                    domain=args.domain,
                    lm_hash=lm_hash,
                    nt_hash=nt_hash
                )
                future_to_ip[future] = ip
                future_start[future] = time.time()
            
            while future_to_ip and not shutdown_flag.is_set():
                done, not_done = wait(list(future_to_ip.keys()), timeout=0.5)
                
                for future in done:
                    ip = future_to_ip.pop(future)
                    future_start.pop(future, None)
                    try:
                        scan_result = future.result()
                    except (ConnectionError, TimeoutError, OSError) as e:
                        from jesur.utils.logger import log_debug
                        log_debug(f"Network error scanning {ip}: {e}")
                        verbose_print(f"[-] Error scanning {ip}: {e}")
                        continue
                    except Exception as e:
                        from jesur.utils.logger import log_error
                        log_error(f"Unexpected error scanning {ip}: {e}", exc_info=True)
                        verbose_print(f"[-] Error scanning {ip}: {e}")
                        continue
                    
                    if scan_result['success']:
                        if scan_result['results']:
                            with context.results_lock:
                                results.extend(scan_result['results'])
                        if scan_result['files']:
                            with context.all_files_lock:
                                all_files.extend(scan_result['files'])
                        
                        if scan_result['stats']:
                            stats = scan_result['stats']
                            scan_stats.increment(
                                hosts_with_smb=stats.get('hosts_with_smb', 0),
                                shares_found=stats.get('shares_found', 0),
                                readable_shares=stats.get('readable_shares', 0),
                                writable_shares=stats.get('writable_shares', 0),
                                files_scanned=stats.get('files_scanned', 0),
                                sensitive_files_found=stats.get('sensitive_files_found', 0),
                                sensitive_content_found=stats.get('sensitive_content_found', 0),
                                bytes_read=stats.get('bytes_read', 0),
                                files_downloaded=stats.get('files_downloaded', 0)
                            )
                    elif scan_result.get('error'):
                        verbose_print(f"[-] Error scanning {ip}: {scan_result['error']}")
                        if args.verbose and scan_result.get('traceback'):
                            verbose_print(f"[DEBUG] Traceback:\n{scan_result['traceback']}")

                    with completed_lock:
                        completed_hosts += 1
                    scan_stats.increment(hosts_scanned=1)
                
                now = time.time()
                for future in list(not_done):
                    start = future_start.get(future, start_time)
                    if now - start > host_timeout:
                        ip = future_to_ip.get(future)
                        future.cancel()
                        verbose_print(f"[-] Host timeout reached for {ip} ({host_timeout}s), cancelling.")
                        future_to_ip.pop(future, None)
                        future_start.pop(future, None)
                        with completed_lock:
                            completed_hosts += 1
                        scan_stats.increment(hosts_scanned=1)
            
            if shutdown_flag.is_set():
                for f in future_to_ip:
                    f.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
                if not args.quiet:
                    print(f"\n{Colors.YELLOW}[!] Shutdown requested, stopping...{Colors.RESET}")

    except KeyboardInterrupt:
        shutdown_flag.set()
        if not args.quiet:
            print(f"\n{Colors.RED}[!] KeyboardInterrupt - stopping scan...{Colors.RESET}")
    except Exception as e:
        from jesur.utils.logger import log_error
        log_error(f"Unexpected error during scan execution: {e}", exc_info=True)
        print(f"\n{Colors.RED}[-] Error: {e}{Colors.RESET}")
        if args.verbose:
            traceback.print_exc()


    # Force flag end time and report
    scan_stats.end_time = time.time()
    
    if not args.quiet:
        print(f"\n\n{Colors.GREEN}[*] Scan completed/interrupted.{Colors.RESET}", flush=True)
    
    # Print statistics
    if not args.no_stats and not args.quiet:
        try:
            print_statistics(scan_stats.get_stats())
        except Exception as e:
            from jesur.utils.logger import log_error
            log_error(f"Error printing statistics: {e}", exc_info=True)
            if args.verbose:
                print(f"{Colors.YELLOW}[!] Error printing stats: {e}{Colors.RESET}")
    
    # Save reports with timeout protection
    try:
        if not args.list_shares and (results or all_files):
            quiet_print(f"[*] Saving reports...")
            f_rep, s_rep = save_results(all_files, results, args.output_name, args, scan_stats.get_stats())
            if f_rep:
                quiet_print(f"{Colors.GREEN}[+] Files report:{Colors.RESET} {f_rep}")
                quiet_print(f"{Colors.GREEN}[+] Sensitive report:{Colors.RESET} {s_rep}")
            
            # Export to JSON
            if args.output_json:
                filenames = get_export_filenames(args.output_name, 'json')
                if all_files:
                    json_file = export_to_json(all_files, scan_stats.get_stats(), filenames['files'])
                    if json_file:
                        quiet_print(f"{Colors.GREEN}[+] JSON (files):{Colors.RESET} {json_file}")
                if results:
                    json_sensitive = export_to_json(results, scan_stats.get_stats(), filenames['sensitive'])
                    if json_sensitive:
                        quiet_print(f"{Colors.GREEN}[+] JSON (sensitive):{Colors.RESET} {json_sensitive}")
                
                stats_file = export_statistics(scan_stats.get_stats(), filenames['stats'])
                if stats_file:
                    quiet_print(f"{Colors.GREEN}[+] Statistics:{Colors.RESET} {stats_file}")
            
            # Export to CSV
            if args.output_csv:
                filenames = get_export_filenames(args.output_name, 'csv')
                if all_files:
                    csv_file = export_to_csv(all_files, filenames['files'], 'files')
                    if csv_file:
                        quiet_print(f"{Colors.GREEN}[+] CSV (files):{Colors.RESET} {csv_file}")
                if results:
                    csv_sensitive = export_to_csv(results, filenames['sensitive'], 'sensitive')
                    if csv_sensitive:
                        quiet_print(f"{Colors.GREEN}[+] CSV (sensitive):{Colors.RESET} {csv_sensitive}")
        else:
            quiet_print(f"{Colors.YELLOW}[*] No report generated (List shares mode or no results).{Colors.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted during report generation{Colors.RESET}")
    except (IOError, OSError) as e:
        from jesur.utils.logger import log_error
        log_error(f"IO error saving reports: {e}")
        print(f"\n{Colors.RED}[!] Error saving reports: {e}{Colors.RESET}")
    except Exception as e:
        from jesur.utils.logger import log_error
        log_error(f"Unexpected error saving reports: {e}", exc_info=True)
        print(f"\n{Colors.RED}[!] Error saving reports: {e}{Colors.RESET}")
        if args.verbose:
            traceback.print_exc()


if __name__ == "__main__":
    main()
