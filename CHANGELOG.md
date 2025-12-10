# Changelog

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


