"""Rate limiting functionality for scans."""

import time
import threading
from typing import Optional
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class RateLimiter:
    """Simple rate limiter for controlling scan speed."""
    
    def __init__(self, max_rate: int = 100):
        """
        Initialize rate limiter.
        
        Args:
            max_rate: Maximum operations per second
        """
        self.max_rate = max_rate
        self.min_interval = 1.0 / max_rate if max_rate > 0 else 0
        self.last_call = 0.0
        self.lock = threading.Lock()
        
    def acquire(self):
        """Acquire permission to proceed (blocking if necessary)."""
        if self.max_rate <= 0:
            return  # No rate limiting
        
        with self.lock:
            current_time = time.time()
            elapsed = current_time - self.last_call
            
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
                self.last_call = time.time()
            else:
                self.last_call = current_time
    
    def set_rate(self, max_rate: int):
        """Update the rate limit."""
        with self.lock:
            self.max_rate = max_rate
            self.min_interval = 1.0 / max_rate if max_rate > 0 else 0
    
    def get_rate(self) -> int:
        """Get current rate limit."""
        return self.max_rate

class AdaptiveRateLimiter(RateLimiter):
    """Rate limiter that can adapt based on network conditions."""
    
    def __init__(self, initial_rate: int = 100, min_rate: int = 10, max_rate: int = 1000):
        super().__init__(initial_rate)
        self.min_rate = min_rate
        self.max_rate_limit = max_rate
        self.error_count = 0
        self.success_count = 0
        self.adjustment_threshold = 10
        
    def report_success(self):
        """Report a successful operation."""
        with self.lock:
            self.success_count += 1
            self.error_count = max(0, self.error_count - 1)  # Gradually reduce error count
            
            # Increase rate if we have enough successes
            if self.success_count >= self.adjustment_threshold:
                old_rate = self.max_rate
                self.max_rate = min(self.max_rate_limit, int(self.max_rate * 1.1))
                self.min_interval = 1.0 / self.max_rate if self.max_rate > 0 else 0
                self.success_count = 0
                
                if old_rate != self.max_rate:
                    logger.debug(f"Rate increased from {old_rate} to {self.max_rate}")
    
    def report_error(self):
        """Report a failed operation."""
        with self.lock:
            self.error_count += 1
            self.success_count = 0  # Reset success count
            
            # Decrease rate if we have too many errors
            if self.error_count >= 3:
                old_rate = self.max_rate
                self.max_rate = max(self.min_rate, int(self.max_rate * 0.8))
                self.min_interval = 1.0 / self.max_rate if self.max_rate > 0 else 0
                self.error_count = 0
                
                if old_rate != self.max_rate:
                    logger.warning(f"Rate decreased from {old_rate} to {self.max_rate} due to errors")