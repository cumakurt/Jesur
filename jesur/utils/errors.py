"""
JESUR - Enhanced SMB Share Scanner
Error messages module - Standardized error messages

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""

class ErrorMessages:
    """Centralized error message constants."""
    
    # Configuration errors
    CONFIG_INVALID_THREADS = "threads must be an integer between {min} and {max}, got: {value}"
    CONFIG_INVALID_RATE_LIMIT = "rate_limit must be a non-negative integer, got: {value}"
    CONFIG_INVALID_TIMEOUT = "host_timeout must be a positive integer (seconds), got: {value}"
    CONFIG_INVALID_FILE_SIZE = "{param} must be a positive integer (bytes), got: {value}"
    CONFIG_INVALID_REGEX = "Invalid regex pattern in {param}: {error}"
    CONFIG_INVALID_HASH_FORMAT = "hashes must be in format LMHASH:NTHASH (exactly 2 parts)"
    CONFIG_INVALID_HASH_LENGTH = "Each hash must be exactly 32 hexadecimal characters"
    CONFIG_INVALID_HEX = "{param} must be a valid hexadecimal string"
    CONFIG_SIZE_MISMATCH = "min_size ({min}) cannot be greater than max_size ({max})"
    
    # Network errors
    NETWORK_CONNECTION_FAILED = "Failed to connect to {ip}: {error}"
    NETWORK_TIMEOUT = "Connection timeout to {ip} after {timeout}s"
    NETWORK_PORT_CLOSED = "No SMB ports open on {ip}"
    NETWORK_AUTH_FAILED = "Authentication failed for {ip} as {user}@{domain}"
    
    # File errors
    FILE_READ_ERROR = "Error reading file {path}: {error}"
    FILE_WRITE_ERROR = "Error writing file {path}: {error}"
    FILE_DOWNLOAD_ERROR = "Error downloading file {path}: {error}"
    FILE_PATH_INVALID = "Invalid path detected: {path}"
    FILE_PATH_TRAVERSAL = "Path traversal attempt detected: {path}"
    FILE_TOO_LARGE = "File {path} is too large ({size} bytes)"
    
    # Share errors
    SHARE_ACCESS_DENIED = "Access denied to share {share} on {ip}"
    SHARE_NOT_FOUND = "Share {share} not found on {ip}"
    SHARE_LIST_ERROR = "Error listing shares on {ip}: {error}"
    
    # Pattern errors
    PATTERNS_LOAD_FAILED = "Failed to load patterns.json: {error}"
    PATTERNS_INVALID_JSON = "Invalid JSON in patterns file: {error}"
    
    # Export errors
    EXPORT_JSON_ERROR = "Error exporting to JSON: {error}"
    EXPORT_CSV_ERROR = "Error exporting to CSV: {error}"
    EXPORT_STATS_ERROR = "Error exporting statistics: {error}"
    EXPORT_IO_ERROR = "IO error exporting {format}: {error}"
    
    # Template errors
    TEMPLATE_NOT_FOUND = "Template file not found: {path}"
    
    # Scan errors
    SCAN_TIMEOUT = "Scan timeout after {timeout} seconds for {ip}"
    SCAN_INTERRUPTED = "Scan interrupted by user"
    SCAN_UNKNOWN_ERROR = "Unknown error occurred during scan"
    
    @staticmethod
    def format(message: str, **kwargs) -> str:
        """Format error message with provided arguments."""
        try:
            return message.format(**kwargs)
        except KeyError as e:
            return f"{message} (formatting error: missing {e})"
