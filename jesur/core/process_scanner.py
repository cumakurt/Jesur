"""
JESUR - Enhanced SMB Share Scanner
Process scanner module - Thread-safe scan wrapper with timeout support

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""

import threading
import time
from typing import Dict, Any, Optional
from jesur.core.scanner import scan_host as _scan_host_thread
from jesur.core.context import scan_stats, shutdown_flag


def scan_host_with_timeout(ip: str, timeout: int = 120, **kwargs: Any) -> Dict[str, Any]:
    """
    Scan a host with timeout support using threading.Event.
    
    Args:
        ip: IP address to scan
        timeout: Maximum time in seconds
        **kwargs: Other scan parameters (username, password, domain, etc.)
        
    Returns:
        Dictionary with 'success', 'error', 'results', 'files', 'stats' keys
    """
    result = {
        'success': False,
        'results': [],
        'files': [],
        'stats': {},
        'error': None
    }
    
    # Thread-local timeout flag
    timeout_flag = threading.Event()
    scan_result = {'data': None, 'exception': None}
    
    def scan_wrapper():
        """Wrapper function to run scan in a separate thread."""
        try:
            scan_result['data'] = _scan_host_thread(
                ip=ip,
                target_share=kwargs.get('target_share'),
                list_shares_only=kwargs.get('list_shares_only', False),
                username=kwargs.get('username', 'guest'),
                password=kwargs.get('password', ''),
                domain=kwargs.get('domain', 'WORKGROUP'),
                lm_hash=kwargs.get('lm_hash'),
                nt_hash=kwargs.get('nt_hash')
            )
        except (ConnectionError, TimeoutError, OSError) as e:
            import traceback
            scan_result['exception'] = (str(e), traceback.format_exc())
        except Exception as e:
            import traceback
            scan_result['exception'] = (str(e), traceback.format_exc())
        finally:
            timeout_flag.set()
    
    # Start scan in a thread
    scan_thread = threading.Thread(target=scan_wrapper, daemon=True)
    scan_thread.start()
    
    # Wait for completion or timeout
    timeout_occurred = not timeout_flag.wait(timeout=timeout)
    
    # Check if scan completed or timed out
    # Note: Even if timeout occurred, check if scan completed (race condition)
    if scan_result['data'] is not None:
        # Scan completed successfully (even if timeout occurred)
        result['success'] = True
        result['stats'] = scan_result['data'].get('stats', {})
        result['results'] = scan_result['data'].get('results', [])
        result['files'] = scan_result['data'].get('files', [])
    elif scan_result['exception'] is not None:
        # Scan failed with exception
        result['error'] = scan_result['exception'][0]
        result['traceback'] = scan_result['exception'][1]
        result['success'] = False
    elif timeout_occurred:
        # Timeout occurred and scan didn't complete
        result['error'] = f"Scan timeout after {timeout} seconds"
        result['success'] = False
        # Don't set global shutdown_flag as it affects other threads
        # The scan_thread will continue running but results won't be collected
    else:
        # Should not reach here, but handle it
        result['error'] = "Unknown error occurred"
        result['success'] = False
    
    # Force cleanup connections for this specific IP only if timeout occurred
    if timeout_occurred:
        try:
            from jesur.core.connection import connection_pool
            # Only cleanup connections related to this IP
            with connection_pool.lock:
                keys_to_remove = [k for k in list(connection_pool.connections.keys()) if k.startswith(f"{ip}:")]
                for key in keys_to_remove:
                    try:
                        conn = connection_pool.connections.get(key)
                        if conn:
                            conn.close()
                    except (ConnectionError, OSError):
                        # Expected - connection may already be closed
                        pass
                    except Exception as e:
                        from jesur.utils.logger import log_debug
                        log_debug(f"Error closing connection during timeout cleanup: {e}")
                    finally:
                        if key in connection_pool.connections:
                            del connection_pool.connections[key]
                            # Release semaphore if connection was removed
                            try:
                                connection_pool.connection_semaphore.release()
                            except ValueError:
                                # Semaphore already at max, ignore
                                pass
        except Exception as e:
            from jesur.utils.logger import log_debug
            log_debug(f"Error during connection cleanup: {e}")
    
    # Ensure thread cleanup even if scan completed
    if scan_thread.is_alive() and timeout_occurred:
        # Thread may still be running, but we've already collected results or timed out
        # The daemon thread will be cleaned up automatically when main thread exits
        pass
    
    return result
