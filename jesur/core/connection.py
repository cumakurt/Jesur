"""
JESUR - Enhanced SMB Share Scanner
SMB connection management module

Developer: cumakurt
GitHub: https://github.com/cumakurt/Jesur
LinkedIn: https://www.linkedin.com/in/cuma-kurt-34414917/
Version: 2.0.0
"""
import socket
import threading
from threading import Lock
from time import sleep
from functools import wraps
from typing import Optional, Callable, Any
from smb.SMBConnection import SMBConnection
from jesur.core.context import shutdown_flag
import smb.ntlm
import hashlib
import hmac
import random
import struct

# Monkey-patch pysmb to support hash authentication
# pysmb doesn't natively support pass-the-hash, so we patch generateChallengeResponseV2
# Use closure to safely store original function and avoid recursion
def _create_patched_function():
    """Create patched function with closure to store original safely."""
    # Store original BEFORE any patching
    original_func = smb.ntlm.generateChallengeResponseV2
    
    def _is_hash_format(password):
        """Check if password is in LM:NT hash format (both 32 hex chars)."""
        if not isinstance(password, str) or ':' not in password:
            return False, None, None
        parts = password.split(':')
        # Must be exactly 2 parts, each exactly 32 hex characters
        if len(parts) == 2 and len(parts[0]) == 32 and len(parts[1]) == 32:
            try:
                # Validate both are valid hex
                int(parts[0], 16)
                int(parts[1], 16)
                return True, bytes.fromhex(parts[0]), bytes.fromhex(parts[1])
            except ValueError:
                pass
        return False, None, None
    
    def patched_function(password, user, server_challenge, server_info, domain='', client_challenge=None):
        """
        Patched version that supports hash authentication for NTLMv2.
        If password is in format "LMHASH:NTHASH" (both 32 hex chars), use NT hash directly.
        Otherwise, use original function for normal password authentication.
        """
        # Check if this is a hash format password
        is_hash, lm_hash_bytes, nt_hash_bytes = _is_hash_format(password)
        
        if is_hash and nt_hash_bytes:
            # This is a hash format - use NT hash directly
            try:
                client_timestamp = b'\0' * 8
                if not client_challenge:
                    client_challenge = bytes([random.getrandbits(8) for i in range(0, 8)])
                
                assert len(client_challenge) == 8
                
                # Calculate response key using NT hash directly (not MD4 of password)
                # For NTLMv2: response_key = HMAC_MD5(nt_hash, (user.upper() + domain).encode('UTF-16LE'))
                response_key = hmac.new(nt_hash_bytes, (user.upper() + domain).encode('UTF-16LE'), hashlib.md5).digest()
                temp = b'\x01\x01' + b'\0'*6 + client_timestamp + client_challenge + b'\0'*4 + server_info
                ntproofstr = hmac.new(response_key, server_challenge + temp, hashlib.md5).digest()
                
                nt_challenge_response = ntproofstr + temp
                lm_challenge_response = hmac.new(response_key, server_challenge + client_challenge, hashlib.md5).digest() + client_challenge
                session_key = hmac.new(response_key, ntproofstr, hashlib.md5).digest()
                
                return nt_challenge_response, lm_challenge_response, session_key
            except Exception as e:
                # If hash processing fails, fall through to original (shouldn't happen)
                from jesur.utils.logger import log_debug
                log_debug(f"Hash processing failed, using original function: {e}")
                pass
        
        # Not a hash format - use original function for normal password authentication
        # Use closure variable to avoid recursion
        return original_func(password, user, server_challenge, server_info, domain, client_challenge)
    
    return patched_function

# Apply monkey-patch (only once - the closure-based version is more robust)
smb.ntlm.generateChallengeResponseV2 = _create_patched_function()

# Retry configuration
from jesur.core.constants import (
    RETRY_MAX_ATTEMPTS, RETRY_BASE_DELAY,
    RETRY_MAX_DELAY, RETRY_EXPONENTIAL_BASE
)
RETRY_CONFIG = {
    'max_attempts': RETRY_MAX_ATTEMPTS,
    'base_delay': RETRY_BASE_DELAY,
    'max_delay': RETRY_MAX_DELAY,
    'exponential_base': RETRY_EXPONENTIAL_BASE
}

def retry_on_failure(
    max_attempts: int = RETRY_CONFIG['max_attempts'],
    base_delay: float = RETRY_CONFIG['base_delay'],
    max_delay: float = RETRY_CONFIG['max_delay'],
    exponential_base: float = RETRY_CONFIG['exponential_base']
) -> Callable:
    """Decorator for retrying failed operations with exponential backoff."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except (socket.timeout, ConnectionError, OSError) as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        delay = min(base_delay * (exponential_base ** attempt), max_delay)
                        sleep(delay)
                    else:
                        raise
                except Exception as e:
                    # Don't retry on non-network errors
                    raise
            if last_exception:
                raise last_exception
        return wrapper
    return decorator

@retry_on_failure(max_attempts=RETRY_MAX_ATTEMPTS, base_delay=RETRY_BASE_DELAY)
def check_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if a port is open on a host with retry mechanism.
    
    Args:
        ip: IP address to check
        port: Port number to check
        timeout: Connection timeout in seconds
        
    Returns:
        True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except (socket.timeout, ConnectionError, OSError):
        return False
    except Exception as e:
        from jesur.utils.logger import log_debug
        log_debug(f"Unexpected error checking port {port} on {ip}: {e}")
        return False

class SMBConnectionPool:
    """Thread-safe connection pool for SMB connections with automatic cleanup."""
    
    def __init__(self, max_connections=None):
        from jesur.core.constants import MAX_CONNECTIONS_DEFAULT
        if max_connections is None:
            max_connections = MAX_CONNECTIONS_DEFAULT
        self.max_connections = max_connections
        self.connections = {}
        self.lock = Lock()
        self.connection_semaphore = threading.BoundedSemaphore(max_connections)
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup all connections."""
        self.cleanup_all()
    
    def cleanup_all(self):
        """Cleanup all connections in the pool."""
        with self.lock:
            for key, conn in list(self.connections.items()):
                try:
                    conn.close()
                except (ConnectionError, OSError):
                    # Expected - connection may already be closed
                    pass
                except Exception as e:
                    from jesur.utils.logger import log_debug
                    log_debug(f"Error closing connection during cleanup: {e}")
            self.connections.clear()
            # Reset semaphore by releasing all acquired permits
            while True:
                try:
                    self.connection_semaphore.release()
                except ValueError:
                    break
    
    def _create_connection_key(self, ip, username, password, domain, lm_hash=None, nt_hash=None):
        """Create a connection key without exposing sensitive data."""
        # Use hash of password instead of password itself for security
        if password:
            password_hash = hashlib.sha256(password.encode()).hexdigest()[:16]
        else:
            password_hash = 'none'
        
        # For hash auth, use hash values directly (already hashed)
        if lm_hash and nt_hash:
            return f"{ip}:{username}:{domain}:hash:{lm_hash[:8]}:{nt_hash[:8]}"
        else:
            return f"{ip}:{username}:{domain}:pass:{password_hash}"
    
    def get_connection(
        self,
        ip: str,
        username: str,
        password: str,
        domain: str,
        is_direct_tcp: bool,
        timeout: float = 3.0,
        lm_hash: Optional[str] = None,
        nt_hash: Optional[str] = None
    ) -> Optional[Any]:
        # Check shutdown flag before connection attempt
        if shutdown_flag.is_set():
            return None
            
        # Include auth material in the key to avoid reusing a session with different creds
        # Use secure key generation that doesn't expose passwords
        key = self._create_connection_key(ip, username, password, domain, lm_hash, nt_hash)
        
        with self.lock:
            if key in self.connections:
                conn = self.connections[key]
                if shutdown_flag.is_set():
                    return None
                if self._test_connection(conn, timeout=1):
                    return conn
                else:
                    del self.connections[key]
        
        if shutdown_flag.is_set():
            return None
            
        self.connection_semaphore.acquire()
        connected = False  # Initialize before try block
        try:
            if shutdown_flag.is_set():
                return None
                
            # Detect hash-based authentication (LM:NT format).
            # pysmb (1.2.10) does NOT natively support hash auth.
            # We monkey-patched generateChallengeResponseV2 to handle "LM:NT" format.
            # For NTLMv1 (use_ntlm_v2=False), we need to use the patched function.
            use_ntlm_v2 = True
            using_hashes = (lm_hash and len(lm_hash) == 32) and (nt_hash and len(nt_hash) == 32)
            effective_password = password or ""
            if using_hashes:
                # Try NTLMv2 first (more compatible), fall back to v1 if needed
                # Our monkey-patch handles "LM:NT" format in password field
                use_ntlm_v2 = True  # Try v2 first with hash patch
                effective_password = f"{lm_hash}:{nt_hash}"
                # If v2 fails, we'll try v1 in retry logic

            conn = SMBConnection(
                username,
                effective_password,
                "scanner",
                "remote_server",
                domain=domain,
                use_ntlm_v2=use_ntlm_v2,
                is_direct_tcp=is_direct_tcp
            )
            
            conn.sock_timeout = timeout
            
            # Extra visibility in verbose mode (without exposing credentials)
            from jesur.core import context
            from jesur.utils.logger import log_debug
            if hasattr(context, 'verbose_mode') and context.verbose_mode:
                if using_hashes:
                    log_debug(f"Hash auth detected for {ip}: NTLMv2 enabled (timeout={timeout}s)")
                else:
                    log_debug(f"Password auth for {ip}: NTLMv2 enabled (timeout={timeout}s)")
            
            if shutdown_flag.is_set():
                return None
            
            # Connection attempt with timer
            timer = threading.Timer(timeout, lambda: None)
            timer.start()
            
            from jesur.core.constants import SMB_PORT_DIRECT, SMB_PORT_NETBIOS
            try:
                port = SMB_PORT_DIRECT if is_direct_tcp else SMB_PORT_NETBIOS
                if conn.connect(ip, port, timeout=timeout):
                    connected = True
            finally:
                timer.cancel()
            
            if shutdown_flag.is_set():
                try:
                    conn.close()
                except (ConnectionError, OSError):
                    # Expected - connection may already be closed
                    pass
                except Exception as e:
                    from jesur.utils.logger import log_debug
                    log_debug(f"Error closing connection on shutdown: {e}")
                return None
                
            if connected:
                with self.lock:
                    self.connections[key] = conn
                return conn
            
        except (ConnectionError, TimeoutError, OSError) as e:
            # Log network errors in verbose mode
            from jesur.core import context
            from jesur.utils.logger import log_debug, log_error
            if hasattr(context, 'verbose_mode') and context.verbose_mode:
                log_debug(f"Network error connecting to {ip}: {type(e).__name__}: {str(e)}")
            else:
                log_error(f"Network error connecting to {ip}: {type(e).__name__}")
        except Exception as e:
            # Log other errors
            from jesur.core import context
            from jesur.utils.logger import log_error
            log_error(f"Unexpected connection error for {ip}: {type(e).__name__}: {str(e)}", exc_info=True)
        finally:
            if not connected:
                self.connection_semaphore.release()
        
        return None
    
    def _test_connection(self, conn: Any, timeout: float = 1.0) -> bool:
        """
        Test if connection is still alive.
        
        Args:
            conn: SMB connection object to test
            timeout: Test timeout in seconds
            
        Returns:
            True if connection is alive, False otherwise
        """
        try:
            conn.sock_timeout = timeout
            conn.listShares(timeout=timeout)
            return True
        except (ConnectionError, TimeoutError, OSError):
            return False
        except Exception as e:
            from jesur.utils.logger import log_debug
            log_debug(f"Unexpected error testing connection: {e}")
            return False
    
    def release_connection(
        self,
        ip: str,
        username: str,
        domain: str,
        password: Optional[str] = None,
        lm_hash: Optional[str] = None,
        nt_hash: Optional[str] = None
    ) -> None:
        """
        Release a connection and clean up resources.
        
        Args:
            ip: IP address of the connection
            username: Username used for connection
            domain: Domain used for connection
            password: Password used for connection (optional)
            lm_hash: LM hash used for connection (optional)
            nt_hash: NT hash used for connection (optional)
        """
        # Use same key generation method for consistency
        if password is not None or lm_hash is not None:
            key = self._create_connection_key(ip, username, password or "", domain, lm_hash, nt_hash)
        else:
            # Fallback: try to find connection by partial key match
            key = None
            with self.lock:
                for k in list(self.connections.keys()):
                    if k.startswith(f"{ip}:{username}:{domain}:"):
                        key = k
                        break
        
        with self.lock:
            if key and key in self.connections:
                try:
                    self.connections[key].close()
                except (ConnectionError, OSError):
                    # Expected - connection may already be closed
                    pass
                except Exception as e:
                    from jesur.utils.logger import log_debug
                    log_debug(f"Error closing connection during release: {e}")
                finally:
                    if key in self.connections:
                        del self.connections[key]
                    self.connection_semaphore.release()

# Global connection pool
from jesur.core.constants import MAX_CONNECTIONS_DEFAULT
connection_pool = SMBConnectionPool(max_connections=MAX_CONNECTIONS_DEFAULT)
