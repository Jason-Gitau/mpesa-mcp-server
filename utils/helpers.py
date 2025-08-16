import re
import hashlib
import secrets
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from decimal import Decimal, InvalidOperation

logger = logging.getLogger(__name__)

def generate_batch_id(org_slug: str) -> str:
    """Generate a unique batch ID for bulk payments"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_suffix = secrets.token_hex(4)
    return f"BATCH_{org_slug.upper()}_{timestamp}_{random_suffix}"

def format_phone_number(phone: str, country_code: str = '254') -> str:
    """Format phone number to international format"""
    if not phone:
        return phone
    
    # Remove all non-digit characters
    phone = re.sub(r'\D', '', phone)
    
    # Handle Kenyan numbers
    if country_code == '254':
        # If starts with 0, replace with 254
        if phone.startswith('0'):
            phone = '254' + phone[1:]
        # If starts with 7, prepend 254
        elif phone.startswith('7') and len(phone) == 9:
            phone = '254' + phone
        # If doesn't start with 254, prepend it
        elif not phone.startswith('254'):
            phone = '254' + phone
    
    return phone

def validate_phone_number(phone: str, country_code: str = '254') -> bool:
    """Validate phone number format"""
    if not phone:
        return False
    
    formatted_phone = format_phone_number(phone, country_code)
    
    # Kenyan phone number validation
    if country_code == '254':
        # Should be 254XXXXXXXXX (12 digits total)
        if len(formatted_phone) != 12:
            return False
        if not formatted_phone.startswith('254'):
            return False
        # Second part should start with 7
        if not formatted_phone[3:4] == '7':
            return False
        # All characters should be digits
        if not formatted_phone.isdigit():
            return False
        return True
    
    return True  # Default to valid for other countries

def validate_amount(amount: Any) -> tuple[bool, Optional[Decimal]]:
    """Validate and convert amount to Decimal"""
    try:
        if isinstance(amount, str):
            amount = amount.strip()
        
        decimal_amount = Decimal(str(amount))
        
        # Check if amount is positive
        if decimal_amount <= 0:
            return False, None
        
        # Check for reasonable limits (1 cent to 1 million)
        if decimal_amount < Decimal('0.01') or decimal_amount > Decimal('1000000'):
            return False, None
        
        # Round to 2 decimal places
        decimal_amount = decimal_amount.quantize(Decimal('0.01'))
        
        return True, decimal_amount
        
    except (InvalidOperation, ValueError, TypeError):
        return False, None

def generate_reference_number(prefix: str = 'REF') -> str:
    """Generate a unique reference number"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_part = secrets.token_hex(4).upper()
    return f"{prefix}_{timestamp}_{random_part}"

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Hash password with salt"""
    if salt is None:
        salt = secrets.token_hex(32)
    
    # Use PBKDF2 with SHA256
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    
    hashed = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000)
    return hashed.hex(), salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify password against hash"""
    expected_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(expected_hash, hashed)

def sanitize_input(input_str: str, max_length: int = 255) -> str:
    """Sanitize user input"""
    if not isinstance(input_str, str):
        return str(input_str)
    
    # Strip whitespace and limit length
    sanitized = input_str.strip()[:max_length]
    
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    return sanitized

def validate_email(email: str) -> bool:
    """Validate email format"""
    if not email:
        return False
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def mask_sensitive_data(data: str, mask_char: str = '*', visible_chars: int = 4) -> str:
    """Mask sensitive data for logging"""
    if not data or len(data) <= visible_chars:
        return mask_char * len(data) if data else ''
    
    return data[:visible_chars] + mask_char * (len(data) - visible_chars)

def format_currency(amount: Decimal, currency: str = 'KES') -> str:
    """Format amount as currency"""
    return f"{currency} {amount:,.2f}"

def parse_date_range(date_str: str) -> tuple[Optional[datetime], Optional[datetime]]:
    """Parse date range string"""
    try:
        if '|' in date_str:
            start_str, end_str = date_str.split('|', 1)
            start_date = datetime.fromisoformat(start_str.strip())
            end_date = datetime.fromisoformat(end_str.strip())
            return start_date, end_date
        else:
            # Single date - treat as start of day to end of day
            date = datetime.fromisoformat(date_str.strip())
            start_date = date.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = date.replace(hour=23, minute=59, second=59, microsecond=999999)
            return start_date, end_date
    except ValueError:
        return None, None

def chunk_list(items: List, chunk_size: int) -> List[List]:
    """Split list into chunks"""
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]

def calculate_pagination(total: int, page: int, per_page: int) -> Dict[str, Any]:
    """Calculate pagination metadata"""
    total_pages = (total + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return {
        'total': total,
        'per_page': per_page,
        'page': page,
        'total_pages': total_pages,
        'has_prev': has_prev,
        'has_next': has_next,
        'prev_page': page - 1 if has_prev else None,
        'next_page': page + 1 if has_next else None
    }

def generate_api_key(length: int = 32) -> str:
    """Generate API key"""
    return secrets.token_urlsafe(length)

def validate_json(json_str: str) -> tuple[bool, Optional[Dict]]:
    """Validate JSON string"""
    try:
        import json
        data = json.loads(json_str)
        return True, data
    except (ValueError, TypeError):
        return False, None

def clean_dict(data: Dict) -> Dict:
    """Remove None values from dictionary"""
    return {k: v for k, v in data.items() if v is not None}

def merge_dicts(*dicts: Dict) -> Dict:
    """Merge multiple dictionaries"""
    result = {}
    for d in dicts:
        if d:
            result.update(d)
    return result

def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to integer"""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float"""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default

def truncate_string(text: str, length: int, suffix: str = '...') -> str:
    """Truncate string to specified length"""
    if not text or len(text) <= length:
        return text
    
    return text[:length - len(suffix)] + suffix

def normalize_whitespace(text: str) -> str:
    """Normalize whitespace in text"""
    return ' '.join(text.split())

def is_valid_uuid(uuid_str: str) -> bool:
    """Check if string is valid UUID"""
    try:
        import uuid
        uuid.UUID(uuid_str)
        return True
    except (ValueError, TypeError):
        return False

def generate_slug(text: str, max_length: int = 50) -> str:
    """Generate URL-friendly slug from text"""
    # Convert to lowercase
    slug = text.lower()
    
    # Replace spaces and special chars with hyphens
    slug = re.sub(r'[^\w\s-]', '', slug)
    slug = re.sub(r'[\s_-]+', '-', slug)
    
    # Remove leading/trailing hyphens
    slug = slug.strip('-')
    
    # Truncate if too long
    if len(slug) > max_length:
        slug = slug[:max_length].rstrip('-')
    
    return slug

def validate_slug(slug: str) -> bool:
    """Validate slug format"""
    if not slug:
        return False
    
    # Should only contain lowercase letters, numbers, and hyphens
    pattern = r'^[a-z0-9-]+$'
    if not re.match(pattern, slug):
        return False
    
    # Should not start or end with hyphen
    if slug.startswith('-') or slug.endswith('-'):
        return False
    
    # Should not have consecutive hyphens
    if '--' in slug:
        return False
    
    return True

def time_ago(dt: datetime) -> str:
    """Get human-readable time difference"""
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    diff = now - dt
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif seconds < 2592000:  # 30 days
        days = int(seconds / 86400)
        return f"{days} day{'s' if days != 1 else ''} ago"
    else:
        return dt.strftime("%Y-%m-%d")

def retry_operation(func, max_retries: int = 3, delay: float = 1.0):
    """Decorator for retrying operations"""
    import time
    from functools import wraps
    
    def decorator(f):
        @wraps(f)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return await f(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s...")
                        time.sleep(delay)
                    else:
                        logger.error(f"All {max_retries + 1} attempts failed")
                        raise last_exception
            
        return wrapper
    return decorator

class Timer:
    """Context manager for timing operations"""
    
    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        logger.info(f"{self.name} took {duration:.3f} seconds")
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
