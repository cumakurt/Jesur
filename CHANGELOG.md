# Changelog

## [2.1.0]

### Added
- Interactive packaged HTML report template with local filtering, pagination, charts, and evidence links.
- High-value file discovery for cloud credentials, Windows/Active Directory artifacts, offensive tool output, backup/export archives, package-manager credentials, and deployment secrets.
- Built-in content signatures for cloud keys, CI/CD tokens, JWTs, basic-auth URLs, database connection strings, and PuTTY/private key material.
- Severity labels for sensitive file and content findings in reports and CSV exports.
- Regression tests for report immutability, CSV hardening, path sanitization, and IPv4 /31 host counting.

### Changed
- Reworked scan scheduling to keep only a bounded number of pending host futures in memory.
- Reset runtime scan state before each CLI run to avoid stale results or shutdown flags in reused processes.
- Scoped file-content cache keys by host and share to avoid cross-host cache collisions.
- Made sensitive filename matching case-insensitive for SMB-style filesystem behavior.
- Added path-aware matching for credential locations such as `.aws/credentials`, `.ssh/id_*`, `.kube/config`, Docker config, Windows registry hives, and AD database files.
- Kept directory traversal active when filename filters are used, so matching files below non-matching directories are still found.
- Aligned package metadata and documentation with Python 3.9+ and version 2.1.0.

### Fixed
- Removed unresolved merge conflict markers from documentation.
- Prevented duplicate sensitive-file and downloaded-file statistics for the same file.
- Fixed a cache cleanup self-deadlock risk under memory pressure.
- Released stale SMB pooled connections when connection health checks fail.
- Escaped fallback HTML report values and avoided mutating report input data.
- Hardened CSV exports against spreadsheet formula injection.

### Security
- Improved SMB download path validation while allowing normal filenames with spaces and punctuation.
- Avoided exposing stale or cross-target cached content in report and evidence workflows.

## [2.0.0]

### Added
- Modern Docker multi-stage build architecture
- Python 3.12 support
- Optimized build process with better caching
- Test infrastructure with pytest
- Type hints for all public API functions
- Comprehensive exception handling improvements
- ErrorMessages class usage throughout codebase
- pytest.ini configuration file
- Test files for common utilities, constants, and scanner functions
- Health check support in Docker
- Non-root user support (optional)

### Changed
- Upgraded base image to Python 3.12-slim
- Improved Docker build performance and reliability
- Enhanced exception handling: replaced bare `except:` with specific exception types
- Enhanced logging consistency: standardized logging across all modules
- Moved magic numbers to constants.py
- Added type hints to all public functions
- Improved docstrings with proper formatting
- Fixed HTML report file download paths (relative path correction)

### Fixed
- Docker build DNS resolution issues
- Silent exception swallowing issues
- Inconsistent error handling patterns
- Missing type information in function signatures
- HTML report download link paths

### Security
- Improved error logging without exposing sensitive information
- Enhanced path traversal protection documentation
- Optional non-root user execution in Docker
