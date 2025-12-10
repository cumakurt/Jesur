"""
JESUR - Enhanced SMB Share Scanner
Context management module - Thread-safe shared state

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
import threading
import time
from threading import Lock

class ScanStatus:
    """Tracks scanning progress and status."""
    
    def __init__(self):
        self.current_ip = ""
        self.current_share = ""
        self.current_path = ""
        self.current_action = ""
        self.last_update = time.time()
        self.last_display_update = 0
        self.start_time = None
        self.lock = Lock()

    def update(self, ip=None, share=None, action=None, path=None):
        with self.lock:
            if ip is not None:
                self.current_ip = ip
            if share is not None:
                self.current_share = share
            if path is not None:
                self.current_path = path
            if action is not None:
                self.current_action = action
            self.last_update = time.time()

    def get_status(self):
        with self.lock:
            return {
                'ip': self.current_ip,
                'share': self.current_share,
                'path': self.current_path,
                'action': self.current_action,
                'last_update': self.last_update
            }

class ScanStats:
    """Tracks detailed scan statistics."""
    
    def __init__(self):
        self.lock = Lock()
        self.hosts_scanned = 0
        self.hosts_with_smb = 0
        self.shares_found = 0
        self.readable_shares = 0
        self.writable_shares = 0
        self.files_scanned = 0
        self.sensitive_files_found = 0
        self.sensitive_content_found = 0
        self.bytes_read = 0
        self.files_downloaded = 0
        self.start_time = None
        self.end_time = None
        
    def increment(self, **kwargs):
        """Increment one or more statistics."""
        with self.lock:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, getattr(self, key) + value)
    
    def get_stats(self):
        """Get all statistics as a dictionary."""
        with self.lock:
            return {
                'hosts_scanned': self.hosts_scanned,
                'hosts_with_smb': self.hosts_with_smb,
                'shares_found': self.shares_found,
                'readable_shares': self.readable_shares,
                'writable_shares': self.writable_shares,
                'files_scanned': self.files_scanned,
                'sensitive_files_found': self.sensitive_files_found,
                'sensitive_content_found': self.sensitive_content_found,
                'bytes_read': self.bytes_read,
                'files_downloaded': self.files_downloaded,
                'start_time': self.start_time,
                'end_time': self.end_time
            }
    
    def get_duration(self):
        """Get scan duration in seconds."""
        if self.start_time:
            end = self.end_time or time.time()
            return end - self.start_time
        return 0

# Global Status Objects
scan_status = ScanStatus()
scan_stats = ScanStats()
shutdown_flag = threading.Event()

# Thread-safe collections for results
from queue import Queue
results_queue = Queue()
all_files_queue = Queue()

# Backward compatibility: Keep lists but use locks for thread safety
results = []
all_files = []
results_lock = Lock()
all_files_lock = Lock()

# Global configuration
verbose_mode = False
quiet_mode = False
