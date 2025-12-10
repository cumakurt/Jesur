"""
JESUR - Enhanced SMB Share Scanner
Constants module - Centralizes all magic numbers and configuration constants

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""

# Threading constants
MAX_THREADS = 100
MIN_THREADS = 10
DEFAULT_THREADS_SMALL_NETWORK = 10
DEFAULT_THREADS_MEDIUM_NETWORK = 50
SMALL_NETWORK_THRESHOLD = 10
MEDIUM_NETWORK_THRESHOLD = 50

# Timeout constants (in seconds)
TIMEOUT_PORT_SCAN = 3
TIMEOUT_CONNECTION = 3
TIMEOUT_SHARE_LIST = 3
TIMEOUT_FILE_READ = 5
TIMEOUT_FILE_WRITE = 3
TIMEOUT_DIR_LIST = 5
TIMEOUT_AUTH = 2
TIMEOUT_OPERATION = 5
TIMEOUT_HOST_DEFAULT = 180
TIMEOUT_FILE_MINIMUM = 10
TIMEOUT_LARGE_FILE = 30
TIMEOUT_CHUNK_MAX = 3

# File size constants (in bytes)
MAX_FILE_SIZE_DEFAULT = 10 * 1024 * 1024  # 10MB
MAX_READ_BYTES_DEFAULT = 1024 * 1024  # 1MB
CHUNK_SIZE_DEFAULT = 512 * 1024  # 512KB
MAX_CACHE_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file
LARGE_FILE_THRESHOLD = 10 * 1024 * 1024  # 10MB

# Cache constants
MAX_FILE_CACHE_SIZE = 1000
MAX_SHARE_CACHE_SIZE = 500
MAX_MEMORY_MB = 500
CACHE_CLEANUP_THRESHOLD = 0.7  # Cleanup when 70% full
CACHE_CLEANUP_TARGET = 0.8  # Cleanup to 80%

# Pattern matching constants
MAX_MATCHES_PER_CATEGORY = 20

# Retry configuration
RETRY_MAX_ATTEMPTS = 3
RETRY_BASE_DELAY = 1
RETRY_MAX_DELAY = 10
RETRY_EXPONENTIAL_BASE = 2

# Connection pool constants
MAX_CONNECTIONS_DEFAULT = 50

# SMB ports
SMB_PORT_DIRECT = 445
SMB_PORT_NETBIOS = 139

# Rate limiting
RATE_LIMIT_UNLIMITED = 0

# Network constants
CIDR_DEFAULT_MASK = 32

# Configuration validation limits
MAX_FILE_SIZE_LIMIT_MULTIPLIER = 10  # Allow up to 10x default max file size
MAX_READ_BYTES_LIMIT_MULTIPLIER = 10  # Allow up to 10x default max read bytes
MAX_FILE_SIZE_LIMIT = MAX_FILE_SIZE_DEFAULT * MAX_FILE_SIZE_LIMIT_MULTIPLIER  # 100MB
MAX_READ_BYTES_LIMIT = MAX_READ_BYTES_DEFAULT * MAX_READ_BYTES_LIMIT_MULTIPLIER  # 10MB

# Progress display constants
PROGRESS_UPDATE_INTERVAL = 0.5  # Update progress every 0.5 seconds
PROGRESS_MONITOR_SLEEP = 0.1  # Sleep interval for progress monitor thread
