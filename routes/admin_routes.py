import logging
from flask import Blueprint, request, jsonify, g

from models.organization import OrganizationModel
from models.user import UserModel
from services.audit_service import AuditService
from middleware.auth_middleware import require_auth, require_org_admin

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/health', methods=['GET'])
async def health_check():
    """Health check endpoint"""
    try:
        from utils.database import get_db_pool
        from datetime import datetime
        
        # Check database connection
        pool = get_db_pool()
        async with pool.acquire() as conn:
            await conn.fetchval('SELECT 1')
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'services': {
                'database': 'connected'
            }
        })
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@admin_bp.route('/organizations', methods=['GET'])
@require_auth
async def list_organizations():
    """List all organizations (super admin only)"""
    if g.current_user_role != 'super_admin':
        return jsonify({'error': 'Super admin access required'}), 403
    
    try:
        orgs = await OrganizationModel.list_organizations()
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'ORGANIZATIONS_LISTED', 'list_organizations',
            {}, {'count': len(orgs)}, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': orgs
        })
        
    except Exception as e:
        logger.error(f"Failed to list organizations: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/organizations', methods=['POST'])
@require_auth
async def create_organization():
    """Create new organization (super admin only)"""
    if g.current_user_role != 'super_admin':
        return jsonify({'error': 'Super admin access required'}), 403
    
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
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'ORGANIZATION_CREATED', 'create_organization',
            {'name': data['name'], 'slug': data['slug']}, result, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Organization created successfully'
        })
        
    except Exception as e:
        logger.error(f"Organization creation failed: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/organizations/<org_id>/credentials', methods=['PUT'])
@require_auth
@require_org_admin
async def update_credentials(org_id):
    """Update organization M-Pesa credentials"""
    if g.current_org_id != org_id and g.current_user_role != 'super_admin':
        return jsonify({'error': 'Access denied to this organization'}), 403
    
    data = request.get_json()
    
    try:
        result = await OrganizationModel.update_org_credentials(
            org_id=org_id,
            credentials=data,
            user_id=g.current_user_id
        )
        
        await AuditService.log_audit(
            g.current_user_id, org_id, 'CREDENTIALS_UPDATE', 'update_org_credentials',
            list(data.keys()), {'updated': True}, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Credentials updated successfully'
        })
        
    except Exception as e:
        logger.error(f"Credentials update failed: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/users', methods=['GET'])
@require_auth
@require_org_admin
async def list_users():
    """List users in organization"""
    try:
        org_filter = g.current_org_id if g.current_user_role != 'super_admin' else None
        
        users = await UserModel.list_users(org_filter)
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'USERS_LISTED', 'list_users',
            {'org_filter': org_filter}, {'count': len(users)}, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': users
        })
        
    except Exception as e:
        logger.error(f"Failed to list users: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/users', methods=['POST'])
@require_auth
@require_org_admin
async def create_user():
    """Create new user in organization"""
    data = request.get_json()
    
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    
    try:
        from werkzeug.security import generate_password_hash
        
        # Check if username/email already exists
        username_exists = await UserModel.check_username_exists(
            data['username'], g.current_org_id
        )
        if username_exists:
            return jsonify({'error': 'Username already exists'}), 400
        
        email_exists = await UserModel.check_email_exists(
            data['email'], g.current_org_id
        )
        if email_exists:
            return jsonify({'error': 'Email already exists'}), 400
        
        # Create user
        password_hash = generate_password_hash(data['password'])
        user_id = await UserModel.create_user(
            organization_id=g.current_org_id,
            username=data['username'],
            email=data['email'],
            password_hash=password_hash,
            role=data.get('role', 'user'),
            permissions=data.get('permissions', {})
        )
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'USER_CREATED', 'create_user',
            {'username': data['username'], 'role': data.get('role', 'user')}, 
            {'user_id': user_id}, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': {'user_id': user_id},
            'message': 'User created successfully'
        })
        
    except Exception as e:
        logger.error(f"User creation failed: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/users/<user_id>', methods=['PUT'])
@require_auth
@require_org_admin
async def update_user(user_id):
    """Update user information"""
    data = request.get_json()
    
    try:
        # Verify user belongs to current organization (unless super admin)
        if g.current_user_role != 'super_admin':
            user = await UserModel.get_user_by_id(user_id)
            if not user or str(user['organization_id']) != g.current_org_id:
                return jsonify({'error': 'User not found or access denied'}), 404
        
        success = await UserModel.update_user(user_id, data)
        
        if not success:
            return jsonify({'error': 'User not found or no changes made'}), 404
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'USER_UPDATED', 'update_user',
            {'user_id': user_id, 'updates': list(data.keys())}, 
            {'success': True}, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'message': 'User updated successfully'
        })
        
    except Exception as e:
        logger.error(f"User update failed: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/users/<user_id>', methods=['DELETE'])
@require_auth
@require_org_admin
async def delete_user(user_id):
    """Delete user (soft delete)"""
    try:
        # Verify user belongs to current organization (unless super admin)
        if g.current_user_role != 'super_admin':
            user = await UserModel.get_user_by_id(user_id)
            if not user or str(user['organization_id']) != g.current_org_id:
                return jsonify({'error': 'User not found or access denied'}), 404
        
        # Don't allow self-deletion
        if user_id == g.current_user_id:
            return jsonify({'error': 'Cannot delete your own account'}), 400
        
        success = await UserModel.delete_user(user_id)
        
        if not success:
            return jsonify({'error': 'User not found'}), 404
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'USER_DELETED', 'delete_user',
            {'user_id': user_id}, {'success': True}, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"User deletion failed: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/audit-logs', methods=['GET'])
@require_auth
@require_org_admin
async def audit_logs():
    """View audit logs (scoped to organization for org admins)"""
    try:
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        org_filter = g.current_org_id if g.current_user_role != 'super_admin' else None
        
        logs = await AuditService.get_audit_logs(org_filter, limit, offset)
        
        return jsonify({
            'success': True,
            'data': logs
        })
        
    except Exception as e:
        logger.error(f"Failed to get audit logs: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/usage-stats', methods=['GET'])
@require_auth
@require_org_admin
async def usage_stats():
    """Get organization usage statistics"""
    try:
        org_filter = g.current_org_id if g.current_user_role != 'super_admin' else request.args.get('org_id')
        
        if not org_filter:
            return jsonify({'error': 'Organization ID required'}), 400
        
        stats = await OrganizationModel.get_usage_stats(org_filter)
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'USAGE_STATS_VIEWED', 'usage_stats',
            {'org_id': org_filter}, stats, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': stats
        })
        
    except Exception as e:
        logger.error(f"Failed to get usage stats: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/activity-summary', methods=['GET'])
@require_auth
@require_org_admin
async def activity_summary():
    """Get organization activity summary"""
    try:
        days = int(request.args.get('days', 30))
        org_filter = g.current_org_id if g.current_user_role != 'super_admin' else request.args.get('org_id')
        
        if not org_filter:
            return jsonify({'error': 'Organization ID required'}), 400
        
        summary = await AuditService.get_organization_activity_summary(org_filter, days)
        
        return jsonify({
            'success': True,
            'data': summary
        })
        
    except Exception as e:
        logger.error(f"Failed to get activity summary: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/security-events', methods=['GET'])
@require_auth
@require_org_admin
async def security_events():
    """Get security events"""
    try:
        days = int(request.args.get('days', 30))
        org_filter = g.current_org_id if g.current_user_role != 'super_admin' else request.args.get('org_id')
        
        events = await AuditService.get_security_events(org_filter, days)
        
        return jsonify({
            'success': True,
            'data': events
        })
        
    except Exception as e:
        logger.error(f"Failed to get security events: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/failed-logins', methods=['GET'])
@require_auth
@require_org_admin
async def failed_logins():
    """Get failed login attempts"""
    try:
        hours = int(request.args.get('hours', 24))
        
        attempts = await AuditService.get_failed_login_attempts(hours)
        
        return jsonify({
            'success': True,
            'data': attempts
        })
        
    except Exception as e:
        logger.error(f"Failed to get failed login attempts: {e}")
        return jsonify({'error': str(e)}), 500
