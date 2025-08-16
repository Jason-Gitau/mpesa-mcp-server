import logging
from typing import Dict, List, Optional
from werkzeug.security import check_password_hash

from utils.database import get_db_pool

logger = logging.getLogger(__name__)

class UserModel:
    """User-related database operations"""

    @staticmethod
    async def get_user_by_credentials(username: str, password: str, organization_slug: str = None) -> Optional[Dict]:
        """Authenticate user and return user data with organization info"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                query = """
                    SELECT u.id, u.username, u.email, u.password_hash, u.role, u.permissions, 
                           u.is_active, u.organization_id, o.name as org_name, o.slug as org_slug,
                           o.subscription_status, o.subscription_plan
                    FROM users u
                    JOIN organizations o ON u.organization_id = o.id
                    WHERE u.username = $1 AND u.is_active = true AND o.is_active = true
                """
                params = [username]
                
                if organization_slug:
                    query += " AND o.slug = $2"
                    params.append(organization_slug)
                
                user = await conn.fetchrow(query, *params)
                
                if not user or not check_password_hash(user['password_hash'], password):
                    return None
                
                if user['subscription_status'] not in ['trial', 'active']:
                    raise Exception('Organization subscription is inactive')
                
                return dict(user)
                
        except Exception as e:
            logger.error(f"User authentication failed: {e}")
            raise

    @staticmethod
    async def get_user_organization(user_id: str) -> str:
        """Get organization ID for a user"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                user = await conn.fetchrow("""
                    SELECT organization_id FROM users WHERE id = $1 AND is_active = true
                """, user_id)
                
                if not user:
                    raise Exception(f"User {user_id} not found or inactive")
                
                return str(user['organization_id'])
                
        except Exception as e:
            logger.error(f"Failed to get user organization: {e}")
            raise

    @staticmethod
    async def list_users(org_filter: str = None) -> List[Dict]:
        """List users with optional organization filter"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                query = """
                    SELECT u.id, u.username, u.email, u.role, u.permissions, u.is_active, 
                           u.created_at, o.name as organization_name, o.slug as organization_slug
                    FROM users u
                    JOIN organizations o ON u.organization_id = o.id
                """
                params = []
                
                if org_filter:
                    query += " WHERE u.organization_id = $1"
                    params.append(org_filter)
                
                query += " ORDER BY u.created_at DESC"
                
                users = await conn.fetch(query, *params)
                return [dict(user) for user in users]
                
        except Exception as e:
            logger.error(f"Failed to list users: {e}")
            raise

    @staticmethod
    async def create_user(organization_id: str, username: str, email: str, 
                         password_hash: str, role: str = 'user', permissions: Dict = None) -> str:
        """Create a new user"""
        try:
            import json
            pool = get_db_pool()
            async with pool.acquire() as conn:
                user_id = await conn.fetchval("""
                    INSERT INTO users (organization_id, username, email, password_hash, role, permissions)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    RETURNING id
                """, organization_id, username, email, password_hash, role, 
                     json.dumps(permissions or {}))
                
                return str(user_id)
                
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise

    @staticmethod
    async def update_user(user_id: str, updates: Dict) -> bool:
        """Update user information"""
        try:
            if not updates:
                return False
                
            update_fields = []
            params = []
            param_count = 0
            
            allowed_updates = ['username', 'email', 'role', 'permissions', 'is_active']
            
            for field, value in updates.items():
                if field in allowed_updates:
                    param_count += 1
                    if field == 'permissions':
                        import json
                        update_fields.append(f"{field} = ${param_count}")
                        params.append(json.dumps(value))
                    else:
                        update_fields.append(f"{field} = ${param_count}")
                        params.append(value)
            
            if not update_fields:
                return False
            
            # Add updated_at
            from datetime import datetime
            param_count += 1
            update_fields.append(f"updated_at = ${param_count}")
            params.append(datetime.now())
            
            # Add user_id for WHERE clause
            param_count += 1
            params.append(user_id)
            
            query = f"""
                UPDATE users 
                SET {', '.join(update_fields)}
                WHERE id = ${param_count}
            """
            
            pool = get_db_pool()
            async with pool.acquire() as conn:
                result = await conn.execute(query, *params)
                return result == "UPDATE 1"
                
        except Exception as e:
            logger.error(f"Failed to update user: {e}")
            raise

    @staticmethod
    async def delete_user(user_id: str) -> bool:
        """Soft delete user (set is_active = false)"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                result = await conn.execute("""
                    UPDATE users SET is_active = false, updated_at = NOW()
                    WHERE id = $1
                """, user_id)
                return result == "UPDATE 1"
                
        except Exception as e:
            logger.error(f"Failed to delete user: {e}")
            raise

    @staticmethod
    async def check_user_permission(user_id: str, permission: str) -> bool:
        """Check if user has specific permission"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                user = await conn.fetchrow("""
                    SELECT role, permissions FROM users WHERE id = $1 AND is_active = true
                """, user_id)
                
                if not user:
                    return False
                
                # Super admin and org admin have all permissions
                if user['role'] in ['super_admin', 'org_admin']:
                    return True
                
                # Check specific permissions
                import json
                permissions = json.loads(user['permissions'] or '{}')
                return permissions.get(permission, False) or permissions.get('all', False)
                
        except Exception as e:
            logger.error(f"Failed to check user permission: {e}")
            return False

    @staticmethod
    async def get_user_by_id(user_id: str) -> Optional[Dict]:
        """Get user by ID"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                user = await conn.fetchrow("""
                    SELECT u.*, o.name as organization_name, o.slug as organization_slug
                    FROM users u
                    JOIN organizations o ON u.organization_id = o.id
                    WHERE u.id = $1 AND u.is_active = true
                """, user_id)
                
                return dict(user) if user else None
                
        except Exception as e:
            logger.error(f"Failed to get user by ID: {e}")
            raise

    @staticmethod
    async def update_last_login(user_id: str):
        """Update user's last login timestamp"""
        try:
            from datetime import datetime
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    UPDATE users SET last_login = $1 WHERE id = $2
                """, datetime.now(), user_id)
                
        except Exception as e:
            logger.error(f"Failed to update last login: {e}")
            # Don't raise exception as this is not critical
            pass

    @staticmethod
    async def check_username_exists(username: str, org_id: str = None) -> bool:
        """Check if username already exists in organization"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                if org_id:
                    result = await conn.fetchval("""
                        SELECT id FROM users WHERE username = $1 AND organization_id = $2
                    """, username, org_id)
                else:
                    result = await conn.fetchval("""
                        SELECT id FROM users WHERE username = $1
                    """, username)
                
                return result is not None
                
        except Exception as e:
            logger.error(f"Failed to check username exists: {e}")
            raise

    @staticmethod
    async def check_email_exists(email: str, org_id: str = None) -> bool:
        """Check if email already exists in organization"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                if org_id:
                    result = await conn.fetchval("""
                        SELECT id FROM users WHERE email = $1 AND organization_id = $2
                    """, email, org_id)
                else:
                    result = await conn.fetchval("""
                        SELECT id FROM users WHERE email = $1
                    """, email)
                
                return result is not None
                
        except Exception as e:
            logger.error(f"Failed to check email exists: {e}")
            raise
