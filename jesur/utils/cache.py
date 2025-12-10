"""
JESUR - Enhanced SMB Share Scanner
Cache management module - File, share, and pattern caching

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
import hashlib
import json
import os
import re
from functools import lru_cache
from threading import Lock

class CacheManager:
    """Manages caching for files, shares, and compiled patterns with memory limits."""
    
    def __init__(self, max_file_cache_size=None, max_share_cache_size=None, max_memory_mb=None):
        from jesur.core.constants import MAX_FILE_CACHE_SIZE, MAX_SHARE_CACHE_SIZE, MAX_MEMORY_MB
        if max_file_cache_size is None:
            max_file_cache_size = MAX_FILE_CACHE_SIZE
        if max_share_cache_size is None:
            max_share_cache_size = MAX_SHARE_CACHE_SIZE
        if max_memory_mb is None:
            max_memory_mb = MAX_MEMORY_MB
        self.file_cache = {}
        self.share_cache = {}
        self.pattern_cache = {}
        self.lock = Lock()
        self.max_file_cache_size = max_file_cache_size
        self.max_share_cache_size = max_share_cache_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.current_memory = 0
        self.geo_ip_cache_file = "geo_ip_cache.json"
        
    @lru_cache(maxsize=1000)
    def get_file_hash(self, file_path, size, mtime):
        """Generate hash for file cache key."""
        return hashlib.md5(f"{file_path}:{size}:{mtime}".encode()).hexdigest()
    
    def _estimate_memory(self, content):
        """Estimate memory usage of content."""
        if isinstance(content, bytes):
            return len(content)
        elif isinstance(content, str):
            return len(content.encode('utf-8'))
        elif isinstance(content, (list, dict)):
            return sum(self._estimate_memory(item) for item in (content if isinstance(content, list) else content.values()))
        return 0
    
    def _cleanup_cache_if_needed(self):
        """Remove oldest entries if cache exceeds memory limit."""
        if self.current_memory <= self.max_memory_bytes:
            return
        
        # Remove oldest file cache entries (simple FIFO)
        from jesur.core.constants import CACHE_CLEANUP_TARGET
        with self.lock:
            while self.current_memory > self.max_memory_bytes * CACHE_CLEANUP_TARGET and self.file_cache:
                # Remove first entry (oldest)
                key = next(iter(self.file_cache))
                content = self.file_cache.pop(key)
                self.current_memory -= self._estimate_memory(content)
    
    def get_cached_file(self, file_path, size, mtime):
        """Get cached file content if available."""
        file_hash = self.get_file_hash(file_path, size, mtime)
        with self.lock:
            return self.file_cache.get(file_hash)
    
    def cache_file(self, file_path, size, mtime, content):
        """Cache file content with optimized memory management."""
        from jesur.core.constants import MAX_CACHE_FILE_SIZE, MAX_FILE_CACHE_SIZE, MAX_MEMORY_MB, CACHE_CLEANUP_THRESHOLD, CACHE_CLEANUP_TARGET
        file_hash = self.get_file_hash(file_path, size, mtime)
        content_size = self._estimate_memory(content)
        
        # Early exit for very large files
        if content_size > MAX_CACHE_FILE_SIZE:
            return
        
        with self.lock:
            # Check if already cached (avoid duplicate caching)
            if file_hash in self.file_cache:
                return
            
            # Pre-emptive cleanup if memory is getting high
            from jesur.core.constants import CACHE_CLEANUP_THRESHOLD
            if self.current_memory > self.max_memory_bytes * CACHE_CLEANUP_THRESHOLD:
                self._cleanup_cache_if_needed()
            
            # Check cache size limit
            if len(self.file_cache) >= self.max_file_cache_size:
                # Remove oldest entry (FIFO)
                if self.file_cache:
                    old_key = next(iter(self.file_cache))
                    old_content = self.file_cache.pop(old_key)
                    self.current_memory -= self._estimate_memory(old_content)
            
            # Add to cache
            self.file_cache[file_hash] = content
            self.current_memory += content_size
            
        # Post-add cleanup check
        if self.current_memory > self.max_memory_bytes:
            self._cleanup_cache_if_needed()
    
    def get_cached_share(self, ip, share):
        """Get cached share listing with optimized lookup."""
        key = f"{ip}:{share}"
        with self.lock:
            return self.share_cache.get(key)
    
    def cache_share(self, ip, share, content):
        """Cache share listing with optimized size management."""
        key = f"{ip}:{share}"
        with self.lock:
            # Check if already cached
            if key in self.share_cache:
                return
            
            # Remove oldest entry if cache is full
            if len(self.share_cache) >= self.max_share_cache_size:
                if self.share_cache:
                    # Remove oldest entry (FIFO)
                    oldest_key = next(iter(self.share_cache))
                    self.share_cache.pop(oldest_key)
            
            self.share_cache[key] = content
    
    @lru_cache(maxsize=100)
    def get_compiled_pattern(self, pattern):
        """Get compiled regex pattern from cache."""
        return re.compile(pattern)
    
    def load_geo_ip_cache(self):
        """Load geo IP cache from file."""
        try:
            if os.path.exists(self.geo_ip_cache_file):
                with open(self.geo_ip_cache_file, 'r') as f:
                    return json.load(f)
        except (IOError, OSError) as e:
            from jesur.utils.logger import log_debug
            log_debug(f"Failed to load geo IP cache: {e}")
        except json.JSONDecodeError as e:
            from jesur.utils.logger import log_debug
            log_debug(f"Invalid JSON in geo IP cache: {e}")
        except Exception as e:
            from jesur.utils.logger import log_debug
            log_debug(f"Unexpected error loading geo IP cache: {e}")
        return {}

    def save_geo_ip_cache(self, cache_data):
        """Save geo IP cache to file."""
        try:
            with open(self.geo_ip_cache_file, 'w') as f:
                json.dump(cache_data, f)
        except (IOError, OSError) as e:
            from jesur.utils.logger import log_debug
            log_debug(f"Failed to save geo IP cache: {e}")
        except Exception as e:
            from jesur.utils.logger import log_debug
            log_debug(f"Unexpected error saving geo IP cache: {e}")
            
    def clear_cache(self):
        """Clear all caches."""
        with self.lock:
            self.file_cache.clear()
            self.share_cache.clear()
            self.current_memory = 0

# Global instance
cache_manager = CacheManager()
