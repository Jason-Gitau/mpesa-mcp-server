import time
import logging
from functools import wraps
from typing import Dict, Tuple
from flask import request, jsonify, g

from models.organization import OrganizationModel

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiting utility class"""
    
    def __init__(self):
        # In-memory storage for rate limiting
        # In production, you'd want to use Redis or similar
        self.request_counts = {}
        self.cleanup_interval = 3600  # 1 hour
        self.last_cleanup = time.time()
    
    def _cleanup_old_entries(self):
        """Clean up old rate limit entries"""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            # Remove entries older than 1 hour
            cutoff_time = current_time - 3600
            keys_to_remove = []
            
            for key, (timestamp, count) in self.request_counts.items():
                if timestamp < cutoff_time:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.request_counts[key]
            
            self.last_cleanup = current_time
    
    def _get_rate_limit_key(self, identifier: str, window: str) -> str:
        """Generate rate limit key"""
        current_window = int(time.time()) // self._get_window_seconds(window)
        return f"{identifier}:{window}:{current_window}"
    
    def _get_window_seconds(self, window: str) -> int:
        """Convert window string to seconds"""
        if window == 'minute':
            return 60
        elif window == 'hour':
            return 3600
        elif window == 'day':
            return 86400
        else:
            return 3600  # default to hour
    
    def check_rate_limit(self, identifier: str, limit: int, window: str = 'hour') -> Tuple[bool, int, int]:
        """
        Check if request is within rate limit
        
        Returns:
            - is_allowed: bool
            - current_count: int
            - limit: int
        """
        self._cleanup_old_entries()
        
        key = self._get_rate_limit_key(identifier, window)
        current_time = time.time()
        
        if key in self.request_counts:
            timestamp, count = self.request_counts[key]
            # If within the same window, increment count
            if current_time - timestamp < self._get_window_seconds(window):
                self.request_counts[key] = (timestamp, count + 1)
                return count + 1 <= limit, count + 1, limit
            else:
                # New window, reset count
                self.request_counts[key] = (current_time, 1)
                return True, 1, limit
        else:
            # First request
            self.request_counts[key] = (current_time, 1)
            return True, 1, limit
    
    def get_remaining_requests(self, identifier: str, limit: int, window: str = 'hour') -> int:
        """Get number of remaining requests"""
        key = self._get_rate_limit_key(identifier, window)
        
        if key in self.request_counts:
            timestamp, count = self.request_counts[key]
            if time.time() - timestamp < self._get_window_seconds(window):
                return max(0, limit - count)
        
        return limit
    
    def reset_rate_limit(self, identifier: str, window: str = 'hour'):
        """Reset rate limit for identifier"""
        key = self._get_rate_limit_key(identifier, window)
        if key in self.request_counts:
            del self.request_counts[key]

# Global rate limiter instance
rate_limiter = RateLimiter()

def rate_limit(limit: int, window: str = 'hour', per: str = 'ip'):
    """
    Rate limiting decorator
    
    Args:
        limit: Maximum number of requests allowed
        window: Time window ('minute', 'hour', 'day')
        per: What to limit by ('ip', 'user', 'org')
    """
    def decorator(f):
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            # Determine identifier based on 'per' parameter
            if per == 'ip':
                identifier = request.environ.get('REMOTE_ADDR', 'unknown')
            elif per == 'user':
                identifier = getattr(g, 'current_user_id', 'anonymous')
                if identifier == 'anonymous':
                    # Fall back to IP for anonymous users
                    identifier = request.environ.get('REMOTE_ADDR', 'unknown')
            elif per == 'org':
                identifier = getattr(g, 'current_org_id', 'unknown')
                if identifier == 'unknown':
                    # Fall back to user or IP
                    identifier = getattr(g, 'current_user_id', 
                                       request.environ.get('REMOTE_ADDR', 'unknown'))
            else:
                identifier = request.environ.get('REMOTE_ADDR', 'unknown')
            
            # Check rate limit
            is_allowed, current_count, max_limit = rate_limiter.check_rate_limit(
                identifier, limit, window
            )
            
            if not is_allowed:
                logger.warning(f"Rate limit exceeded for {identifier}: "
                             f"{current_count}/{max_limit} per {window}")
                
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'limit': max_limit,
                    'window': window,
                    'current_count': current_count
                }), 429
            
            # Add rate limit headers to response
            response = await f(*args, **kwargs)
            
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(max_limit)
                response.headers['X-RateLimit-Remaining'] = str(max_limit - current_count)
                response.headers['X-RateLimit-Window'] = window
            
            return response
            
        return decorated_function
    return decorator

async def check_organization_rate_limit(org_id: str) -> bool:
    """Check organization-specific rate limits from database"""
    try:
        return await OrganizationModel.check_rate_limit(org_id)
    except Exception as e:
        logger.error(f"Failed to check organization rate limit: {e}")
        return False

def org_rate_limit(f):
    """Organization-specific rate limiting middleware"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        org_id = getattr(g, 'current_org_id', None)
        
        if not org_id:
            return jsonify({'error': 'Organization context required'}), 400
        
        # Check organization rate limit
        is_allowed = await check_organization_rate_limit(org_id)
        
        if not is_allowed:
            logger.warning(f"Organization rate limit exceeded for org {org_id}")
            return jsonify({
                'error': 'Organization rate limit exceeded',
                'message': 'Your organization has exceeded its API rate limit'
            }), 429
        
        return await f(*args, **kwargs)
    return decorated_function

def adaptive_rate_limit(base_limit: int, window: str = 'hour'):
    """
    Adaptive rate limiting that adjusts based on system load
    """
    def decorator(f):
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            # TODO: Implement adaptive rate limiting logic
            # This could factor in:
            # - Current system load
            # - User/organization tier
            # - Time of day
            # - Historical usage patterns
            
            # For now, just use base rate limiting
            identifier = getattr(g, 'current_user_id', 
                               request.environ.get('REMOTE_ADDR', 'unknown'))
            
            is_allowed, current_count, max_limit = rate_limiter.check_rate_limit(
                identifier, base_limit, window
            )
            
            if not is_allowed:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'limit': max_limit,
                    'window': window
                }), 429
            
            return await f(*args, **kwargs)
            
        return decorated_function
    return decorator

def burst_rate_limit(burst_limit: int, sustained_limit: int, 
                    burst_window: str = 'minute', sustained_window: str = 'hour'):
    """
    Burst rate limiting - allows short bursts but enforces sustained limits
    """
    def decorator(f):
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            identifier = getattr(g, 'current_user_id', 
                               request.environ.get('REMOTE_ADDR', 'unknown'))
            
            # Check burst limit
            burst_allowed, burst_count, burst_max = rate_limiter.check_rate_limit(
                f"{identifier}:burst", burst_limit, burst_window
            )
            
            # Check sustained limit
            sustained_allowed, sustained_count, sustained_max = rate_limiter.check_rate_limit(
                f"{identifier}:sustained", sustained_limit, sustained_window
            )
            
            if not burst_allowed:
                return jsonify({
                    'error': 'Burst rate limit exceeded',
                    'burst_limit': burst_max,
                    'burst_window': burst_window,
                    'current_burst_count': burst_count
                }), 429
            
            if not sustained_allowed:
                return jsonify({
                    'error': 'Sustained rate limit exceeded',
                    'sustained_limit': sustained_max,
                    'sustained_window': sustained_window,
                    'current_sustained_count': sustained_count
                }), 429
            
            response = await f(*args, **kwargs)
            
            # Add headers for both limits
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Burst-Limit'] = str(burst_max)
                response.headers['X-RateLimit-Burst-Remaining'] = str(burst_max - burst_count)
                response.headers['X-RateLimit-Sustained-Limit'] = str(sustained_max)
                response.headers['X-RateLimit-Sustained-Remaining'] = str(sustained_max - sustained_count)
            
            return response
            
        return decorated_function
    return decorator

def whitelist_rate_limit(whitelist: list, default_limit: int, window: str = 'hour'):
    """Rate limiting with whitelist support"""
    def decorator(f):
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            identifier = getattr(g, 'current_user_id', 
                               request.environ.get('REMOTE_ADDR', 'unknown'))
            
            # Check if identifier is whitelisted
            if identifier in whitelist:
                # No rate limiting for whitelisted users/IPs
                return await f(*args, **kwargs)
            
            # Apply normal rate limiting
            is_allowed, current_count, max_limit = rate_limiter.check_rate_limit(
                identifier, default_limit, window
            )
            
            if not is_allowed:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'limit': max_limit,
                    'window': window
                }), 429
            
            return await f(*args, **kwargs)
            
        return decorated_function
    return decorator
