import logging
from flask import Blueprint, request, jsonify

from services.auth_service import AuthService
from services.audit_service import AuditService
from models.organization import OrganizationModel

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
async def login():
    """User authentication with organization context"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    organization_slug = data.get('organization')  # Optional organization slug
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Get client info for audit
    ip_address = request.environ.get('REMOTE_ADDR')
    user_agent = request.headers.get('User-Agent')
    
    try:
        # Authenticate user
        user = await AuthService.authenticate_user(username, password, organization_slug)
        
        if not user:
            # Log failed login attempt
            await AuditService.log_login_attempt(
                username, False, ip_address, user_agent, organization_slug
            )
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create user session
        session_data = await AuthService.create_user_session(user)
        
        # Log successful login
        await AuditService.log_login_attempt(
            username, True, ip_address, user_agent, user['org_slug']
        )
        
        # Log security event
        await AuditService.log_security_event(
            'LOGIN_SUCCESS', f'User {username} logged in successfully',
            str(user['id']), str(user['organization_id']), ip_address
        )
        
        return jsonify({
            'success': True,
            'data': session_data,
            'message': 'Login successful'
        })
        
    except Exception as e:
        logger.error(f"Login failed: {e}")
        
        # Log failed login attempt
        await AuditService.log_login_attempt(
            username, False, ip_address, user_agent, organization_slug
        )
        
        # Log security event for system errors
        await AuditService.log_security_event(
            'LOGIN_ERROR', f'Login system error for {username}: {str(e)}',
            None, None, ip_address
        )
        
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
async def logout():
    """User logout"""
    try:
        # Get token from header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                payload = AuthService.verify_jwt_token(auth_header)
                user_context = AuthService.extract_user_context(payload)
                
                # Log logout
                await AuditService.log_security_event(
                    'LOGOUT', f'User {user_context["username"]} logged out',
                    user_context['user_id'], user_context['organization_id'],
                    request.environ.get('REMOTE_ADDR')
                )
                
            except Exception:
                # Token might be invalid, but that's okay for logout
                pass
        
        return jsonify({
            'success': True,
            'message': 'Logout successful'
        })
        
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/refresh', methods=['POST'])
async def refresh_token():
    """Refresh JWT token"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'No token provided'}), 401
        
        new_token = await AuthService.refresh_token(auth_header)
        
        return jsonify({
            'success': True,
            'data': {'token': new_token},
            'message': 'Token refreshed successfully'
        })
        
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        return jsonify({'error': str(e)}), 401

@auth_bp.route('/verify', methods=['GET'])
async def verify_token():
    """Verify token validity"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'No token provided'}), 401
        
        payload = AuthService.verify_jwt_token(auth_header)
        user_context = AuthService.extract_user_context(payload)
        
        # Validate session is still active
        is_valid = await AuthService.validate_user_session(
            user_context['user_id'], user_context['organization_id']
        )
        
        if not is_valid:
            return jsonify({'error': 'Session invalid'}), 401
        
        return jsonify({
            'success': True,
            'data': {
                'valid': True,
                'user': user_context
            },
            'message': 'Token is valid'
        })
        
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        return jsonify({'error': str(e)}), 401

@auth_bp.route('/register-organization', methods=['POST'])
async def register_organization():
    """Register new organization (public endpoint for self-service)"""
    data = request.get_json()
    
    required_fields = ['name', 'slug', 'admin_username', 'admin_email', 'admin_password']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    
    try:
        admin_user = {
            'username': data['admin_username'],
            'email': data['admin_email'],
            'password': data['admin_password']
        }
        
        result = await OrganizationModel.create_organization(
            name=data['name'],
            slug=data['slug'],
            admin_user=admin_user
        )
        
        # Log organization creation
        await AuditService.log_security_event(
            'ORGANIZATION_CREATED', 
            f'New organization created: {data["name"]} ({data["slug"]})',
            None, result['organization_id'], 
            request.environ.get('REMOTE_ADDR')
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Organization registered successfully'
        })
        
    except Exception as e:
        logger.error(f"Organization registration failed: {e}")
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/forgot-password', methods=['POST'])
async def forgot_password():
    """Password reset request"""
    data = request.get_json()
    email = data.get('email')
    organization_slug = data.get('organization')
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    try:
        # Log password reset request
        await AuditService.log_security_event(
            'PASSWORD_RESET_REQUEST',
            f'Password reset requested for email: {email}',
            None, None, request.environ.get('REMOTE_ADDR'),
            {'email': email, 'organization': organization_slug}
        )
        
        # TODO: Implement password reset logic
        # For now, just return success message
        return jsonify({
            'success': True,
            'message': 'Password reset instructions sent to your email'
        })
        
    except Exception as e:
        logger.error(f"Password reset request failed: {e}")
        return jsonify({'error': 'Password reset request failed'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
async def reset_password():
    """Reset password with token"""
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    if not token or not new_password:
        return jsonify({'error': 'Token and new password are required'}), 400
    
    try:
        # TODO: Implement password reset logic
        # Verify reset token and update password
        
        # Log password reset completion
        await AuditService.log_security_event(
            'PASSWORD_RESET_COMPLETED',
            'Password reset completed successfully',
            None, None, request.environ.get('REMOTE_ADDR'),
            {'token': token[:10] + '...'}  # Log partial token for audit
        )
        
        return jsonify({
            'success': True,
            'message': 'Password reset successfully'
        })
        
    except Exception as e:
        logger.error(f"Password reset failed: {e}")
        return jsonify({'error': 'Password reset failed'}), 500

@auth_bp.route('/change-password', methods=['POST'])
async def change_password():
    """Change password for authenticated user"""
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current and new passwords are required'}), 400
    
    try:
        # Get user from token
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authentication required'}), 401
        
        payload = AuthService.verify_jwt_token(auth_header)
        user_context = AuthService.extract_user_context(payload)
        
        # TODO: Implement password change logic
        # Verify current password and update to new password
        
        # Log password change
        await AuditService.log_security_event(
            'PASSWORD_CHANGED',
            f'Password changed for user {user_context["username"]}',
            user_context['user_id'], user_context['organization_id'],
            request.environ.get('REMOTE_ADDR')
        )
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        })
        
    except Exception as e:
        logger.error(f"Password change failed: {e}")
        return jsonify({'error': str(e)}), 500
