import jwt
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional

from config import Config
from models.user import UserModel

logger = logging.getLogger(__name__)

class AuthService:
    """Authentication and authorization service"""

    @staticmethod
    async def authenticate_user(username: str, password: str, organization_slug: str = None) -> Optional[Dict]:
        """Authenticate user and return user data"""
        try:
            user = await UserModel.get_user_by_credentials(username, password, organization_slug)
            
            if user:
                # Update last login
                await UserModel.update_last_login(str(user['id']))
            
            return user
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise

    @staticmethod
    def generate_jwt_token(user: Dict) -> str:
        """Generate JWT token for authenticated user"""
        try:
            token_payload = {
                'user_id': str(user['id']),
                'username': user['username'],
                'role': user['role'],
                'organization_id': str(user['organization_id']),
                'organization_slug': user['org_slug'],
                'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRY_HOURS)
            }
            
            token = jwt.encode(token_payload, Config.SECRET_KEY, algorithm='HS256')
            return token
            
        except Exception as e:
            logger.error(f"JWT token generation failed: {e}")
            raise

    @staticmethod
    def verify_jwt_token(token: str) -> Dict:
        """Verify and decode JWT token"""
        try:
            if not token:
                raise Exception('No token provided')
            
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token.split(' ')[1]
            
            payload = jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
            return payload
            
        except jwt.ExpiredSignatureError:
            raise Exception('Token has expired')
        except jwt.InvalidTokenError:
            raise Exception('Invalid token')
        except Exception as e:
            logger.error(f"JWT token verification failed: {e}")
            raise

    @staticmethod
    async def get_user_organization_id(user_id: str) -> str:
        """Get organization ID for user if not in token"""
        try:
            return await UserModel.get_user_organization(user_id)
        except Exception as e:
            logger.error(f"Failed to get user organization: {e}")
            raise

    @staticmethod
    async def check_user_permission(user_id: str, permission: str) -> bool:
        """Check if user has specific permission"""
        try:
            return await UserModel.check_user_permission(user_id, permission)
        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            return False

    @staticmethod
    def check_role_permission(role: str, required_roles: list) -> bool:
        """Check if user role has required permission"""
        return role in required_roles

    @staticmethod
    def check_organization_access(user_org_id: str, requested_org_id: str, user_role: str) -> bool:
        """Check if user can access requested organization"""
        # Super admin can access any organization
        if user_role == 'super_admin':
            return True
        
        # Other users can only access their own organization
        return user_org_id == requested_org_id

    @staticmethod
    async def create_user_session(user: Dict) -> Dict:
        """Create user session data"""
        try:
            token = AuthService.generate_jwt_token(user)
            
            session_data = {
                'token': token,
                'user': {
                    'id': str(user['id']),
                    'username': user['username'],
                    'email': user['email'],
                    'role': user['role'],
                    'permissions': user['permissions'],
                    'organization': {
                        'id': str(user['organization_id']),
                        'name': user['org_name'],
                        'slug': user['org_slug'],
                        'subscription_status': user['subscription_status'],
                        'subscription_plan': user['subscription_plan']
                    }
                }
            }
            
            return session_data
            
        except Exception as e:
            logger.error(f"Session creation failed: {e}")
            raise

    @staticmethod
    def validate_token_claims(payload: Dict, required_claims: list = None) -> bool:
        """Validate JWT token claims"""
        try:
            required_claims = required_claims or ['user_id', 'role', 'organization_id']
            
            for claim in required_claims:
                if claim not in payload:
                    return False
            
            # Check if token is expired (additional check)
            exp = payload.get('exp')
            if exp and datetime.utcnow().timestamp() > exp:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Token claim validation failed: {e}")
            return False

    @staticmethod
    async def refresh_token(current_token: str) -> str:
        """Refresh JWT token if it's still valid but approaching expiry"""
        try:
            payload = AuthService.verify_jwt_token(current_token)
            
            # Check if token is within refresh window (e.g., 2 hours before expiry)
            exp = payload.get('exp')
            if exp:
                exp_datetime = datetime.fromtimestamp(exp)
                time_to_expiry = exp_datetime - datetime.utcnow()
                
                # Refresh if token expires within 2 hours
                if time_to_expiry.total_seconds() < 7200:
                    # Get fresh user data
                    user = await UserModel.get_user_by_id(payload['user_id'])
                    if user:
                        return AuthService.generate_jwt_token(user)
            
            # Return original token if no refresh needed
            return current_token
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise

    @staticmethod
    async def validate_user_session(user_id: str, org_id: str) -> bool:
        """Validate that user session is still valid"""
        try:
            user = await UserModel.get_user_by_id(user_id)
            
            if not user:
                return False
            
            # Check if user is still active
            if not user['is_active']:
                return False
            
            # Check if organization matches
            if str(user['organization_id']) != org_id:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Session validation failed: {e}")
            return False

    @staticmethod
    def extract_user_context(payload: Dict) -> Dict:
        """Extract user context from JWT payload"""
        return {
            'user_id': payload.get('user_id'),
            'username': payload.get('username'),
            'role': payload.get('role'),
            'organization_id': payload.get('organization_id'),
            'organization_slug': payload.get('organization_slug')
        }
