"""
Logging utility module for JESUR.
Provides centralized logging configuration and helper functions.
"""

import logging
import sys
from jesur.core.context import verbose_mode, quiet_mode

# Configure root logger
_logger = None

def get_logger():
    """Get or create logger instance."""
    global _logger
    if _logger is None:
        _logger = logging.getLogger('jesur')
        _logger.setLevel(logging.DEBUG)
        
        # Create console handler
        handler = logging.StreamHandler(sys.stdout)
        
        # Set format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        
        # Set level based on verbose/quiet mode
        if quiet_mode:
            handler.setLevel(logging.WARNING)
        elif verbose_mode:
            handler.setLevel(logging.DEBUG)
        else:
            handler.setLevel(logging.INFO)
        
        _logger.addHandler(handler)
        _logger.propagate = False
    
    return _logger

def log_error(message, exc_info=None, logger=None):
    """Log error with optional exception info."""
    if logger is None:
        logger = get_logger()
    logger.error(message, exc_info=exc_info)

def log_warning(message, logger=None):
    """Log warning message."""
    if logger is None:
        logger = get_logger()
    logger.warning(message)

def log_info(message, logger=None):
    """Log info message."""
    if logger is None:
        logger = get_logger()
    logger.info(message)

def log_debug(message, logger=None):
    """Log debug message."""
    if logger is None:
        logger = get_logger()
    logger.debug(message)
