"""Rate limiting functionality for scans."""

import time
import threading
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class RateLimiter:
    """Simple rate limiter for controlling task speed."""
    
    def __init__(self, max_rate: float):
        self.max_rate = max_rate
        self._min_interval = 1.0 / max_rate if max_rate > 0 else 0
        self.last_call = 0.0
        self.lock = threading.Lock()
        
    def acquire(self):
        """Acquire permission to proceed (blocking if necessary)."""
        if self.max_rate <= 0:
            return

        with self.lock:
            current_time = time.monotonic()
            elapsed = current_time - self.last_call
            
            if elapsed < self._min_interval:
                sleep_time = self._min_interval - elapsed
                time.sleep(sleep_time)
            
            self.last_call = time.monotonic()
    
    def set_rate(self, max_rate: float):
        """Update the rate limit."""
        with self.lock:
            self.max_rate = max_rate
            self._min_interval = 1.0 / max_rate if max_rate > 0 else 0
            logger.debug(f"Rate limiter updated to {max_rate} ops/sec.")
    
    def get_rate(self) -> float:
        """Get current rate limit."""
        return self.max_rate