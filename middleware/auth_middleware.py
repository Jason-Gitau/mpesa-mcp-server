import logging
from functools import wraps
from flask import request, jsonify, g

from services.auth_service import AuthService

logger = logging.getLogger(__name__)

def require_auth(f):
    """Authentication middleware decorator"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'No authorization token provided'}), 401
        
        try:
            # Verify JWT token
            payload = AuthService.verify_jwt_token(auth_header)
            
            # Extract user context
            user_context = AuthService.extract_user_context(payload)
            
            # Validate required claims
            if not AuthService.validate_token_claims(payload):
                return jsonify({'error': 'Invalid token claims'}), 401
            
            # Set user context in Flask g
            g.current_user_id = user_context['user_id']
            g.current_user_role = user_context['role']
            g.current_org_id = user_context['organization_id']
            g.current_username = user_context['username']
            g.current_org_slug = user_context['organization_slug']
            
            # Get organization ID if not in token (fallback)
            if not g.current_org_id:
                g.current_org_id = await AuthService.get_user_organization_id(g.current_user_id)
            
            # Validate session is still active
            is_valid = await AuthService.validate_user_session(
                g.current_user_id, g.current_org_id
            )
            
            if not is_valid:
                return jsonify({'error': 'Session invalid or expired'}), 401
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return jsonify({'error': str(e)}), 401
        
        return await f(*args, **kwargs)
    return decorated_function

def require_org_admin(f):
    """Organization admin authorization middleware decorator"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user_role'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Check if user has admin role
        if g.current_user_role not in ['super_admin', 'org_admin']:
            return jsonify({'error': 'Organization admin access required'}), 403
        
        return await f(*args, **kwargs)
    return decorated_function

def require_super_admin(f):
    """Super admin authorization middleware decorator"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user_role'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Check if user has super admin role
        if g.current_user_role != 'super_admin':
            return jsonify({'error': 'Super admin access required'}), 403
        
        return await f(*args, **kwargs)
    return decorated_function

def require_permission(permission):
    """Permission-based authorization middleware decorator"""
    def decorator(f):
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user_id'):
                return jsonify({'error': 'Authentication required'}), 401
            
            # Check if user has required permission
            has_permission = await AuthService.check_user_permission(
                g.current_user_id, permission
            )
            
            if not has_permission:
                return jsonify({'error': f'Permission required: {permission}'}), 403
            
            return await f(*args, **kwargs)
        return decorated_function
    return decorator

def require_organization_access(f):
    """Middleware to ensure user can only access their own organization data"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user_role'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Extract org_id from route parameters
        org_id = kwargs.get('org_id') or request.view_args.get('org_id')
        
        if org_id:
            # Check if user can access this organization
            can_access = AuthService.check_organization_access(
                g.current_org_id, org_id, g.current_user_role
            )
            
            if not can_access:
                return jsonify({'error': 'Access denied to this organization'}), 403
        
        return await f(*args, **kwargs)
    return decorated_function

def optional_auth(f):
    """Optional authentication middleware - sets user context if token is provided"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                # Verify JWT token
                payload = AuthService.verify_jwt_token(auth_header)
                user_context = AuthService.extract_user_context(payload)
                
                # Set user context in Flask g
                g.current_user_id = user_context['user_id']
                g.current_user_role = user_context['role']
                g.current_org_id = user_context['organization_id']
                g.current_username = user_context['username']
                g.current_org_slug = user_context['organization_slug']
                
            except Exception as e:
                logger.warning(f"Optional auth failed: {e}")
                # Continue without authentication
                pass
        
        return await f(*args, **kwargs)
    return decorated_function

def api_key_auth(f):
    """API key authentication middleware (alternative to JWT)"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        try:
            # TODO: Implement API key validation
            # This would involve looking up the API key in the database
            # and setting appropriate user context
            
            # For now, just reject all API key requests
            return jsonify({'error': 'API key authentication not implemented'}), 501
            
        except Exception as e:
            logger.error(f"API key authentication failed: {e}")
            return jsonify({'error': 'Invalid API key'}), 401
        
        return await f(*args, **kwargs)
    return decorated_function

def csrf_protect(f):
    """CSRF protection middleware"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        # Skip CSRF for GET requests
        if request.method == 'GET':
            return await f(*args, **kwargs)
        
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token:
            return jsonify({'error': 'CSRF token required'}), 403
        
        try:
            # TODO: Implement CSRF token validation
            # This would involve validating the token against the user session
            
            # For now, just check if token is present
            if len(csrf_token) < 10:
                return jsonify({'error': 'Invalid CSRF token'}), 403
            
        except Exception as e:
            logger.error(f"CSRF validation failed: {e}")
            return jsonify({'error': 'CSRF validation failed'}), 403
        
        return await f(*args, **kwargs)
    return decorated_function

def log_request(f):
    """Request logging middleware"""
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        # Log request details
        user_id = getattr(g, 'current_user_id', 'anonymous')
        org_id = getattr(g, 'current_org_id', None)
        ip_address = request.environ.get('REMOTE_ADDR')
        user_agent = request.headers.get('User-Agent')
        
        logger.info(f"Request: {request.method} {request.path} - "
                   f"User: {user_id}, Org: {org_id}, IP: {ip_address}")
        
        try:
            result = await f(*args, **kwargs)
            logger.info(f"Response: {request.method} {request.path} - Success")
            return result
        except Exception as e:
            logger.error(f"Response: {request.method} {request.path} - Error: {e}")
            raise
        
    return decorated_function
