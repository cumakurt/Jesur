"""
JESUR - Enhanced SMB Share Scanner
Common utilities module - Colors, formatting, and helper functions

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
from typing import Optional

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'

def colored_print(text: str, color: str) -> None:
    """Print colored text."""
    print(f"{color}{text}{Colors.RESET}")

def verbose_print(text: str, force: bool = False) -> None:
    """Print only in verbose mode."""
    from jesur.core.context import verbose_mode, quiet_mode
    if force or (verbose_mode and not quiet_mode):
        print(text)

def quiet_print(text: str) -> None:
    """Print only if not in quiet mode."""
    from jesur.core.context import quiet_mode
    if not quiet_mode:
        print(text)

def print_header(text: str) -> None:
    """Print a formatted header."""
    from jesur.core.context import quiet_mode
    if not quiet_mode:
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{text.center(80)}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.RESET}\n")

def print_section(text: str) -> None:
    """Print a section header."""
    from jesur.core.context import quiet_mode
    if not quiet_mode:
        print(f"\n{Colors.BLUE}{Colors.BOLD}▶ {text}{Colors.RESET}")
        print(f"{Colors.DIM}{'─'*80}{Colors.RESET}")

def print_finding(category: str, value: str, file_path: str = "") -> None:
    """Print a finding in a professional format."""
    category_colors = {
        'INTERNAL_IP': Colors.YELLOW,
        'PASSWORD': Colors.RED,
        'API_KEY': Colors.MAGENTA,
        'TOKEN': Colors.MAGENTA,
        'USERNAME': Colors.YELLOW,
        'DATABASE': Colors.CYAN,
        'AWS': Colors.YELLOW,
        'AZURE': Colors.BLUE,
        'GCP': Colors.GREEN,
    }
    color = category_colors.get(category.upper(), Colors.RED)
    
    # Truncate long values for display
    display_value = value[:60] + "..." if len(value) > 60 else value
    
    if file_path:
        print(f"  {Colors.DIM}📄{Colors.RESET} {Colors.WHITE}{file_path}{Colors.RESET}")
    
    print(f"  {color}{Colors.BOLD}⚠{Colors.RESET} {Colors.BOLD}{category.upper():<15}{Colors.RESET} {Colors.DIM}│{Colors.RESET} {display_value}")

def normalize_smb_path(path: Optional[str]) -> Optional[str]:
    """Normalize SMB path to Windows format (backslashes, no leading slash)."""
    if not path:
        return path
    
    # Replace forward slashes with backslashes
    normalized = path.replace('/', '\\')
    
    # Remove leading backslash if present (except for root)
    if normalized.startswith('\\') and len(normalized) > 1:
        normalized = normalized.lstrip('\\')
    
    # Remove duplicate backslashes
    while '\\\\' in normalized:
        normalized = normalized.replace('\\\\', '\\')
    
    return normalized

def format_bytes(bytes_count: int) -> str:
    """Format bytes to human readable format."""
    count = float(bytes_count)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if count < 1024.0:
            return f"{count:.2f} {unit}"
        count /= 1024.0
    return f"{count:.2f} PB"

def format_duration(seconds: float) -> str:
    """Format seconds to human readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"

