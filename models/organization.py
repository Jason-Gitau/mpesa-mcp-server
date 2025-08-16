import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from werkzeug.security import generate_password_hash

from utils.database import get_db_pool

logger = logging.getLogger(__name__)

class OrganizationModel:
    """Organization-related database operations"""
    
    @staticmethod
    async def get_org_config(org_id: str) -> Dict:
        """Get organization-specific M-Pesa configuration"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                org = await conn.fetchrow("""
                    SELECT * FROM organizations WHERE id = $1 AND is_active = true
                """, org_id)
                
                if not org:
                    raise Exception(f"Organization {org_id} not found or inactive")
                
                # Check subscription status
                if org['subscription_status'] not in ['trial', 'active']:
                    raise Exception(f"Organization subscription is {org['subscription_status']}")
                
                config = {
                    'consumer_key': org['mpesa_consumer_key'],
                    'consumer_secret': org['mpesa_consumer_secret'],
                    'business_short_code': org['mpesa_business_short_code'],
                    'lipa_na_mpesa_passkey': org['mpesa_lipa_na_mpesa_passkey'],
                    'base_url': org['mpesa_base_url'] or 'https://sandbox.safaricom.co.ke',
                    'initiator_name': org['mpesa_initiator_name'],
                    'security_credential': org['mpesa_security_credential'],
                    'callback_base_url': org['callback_base_url'],
                    'api_rate_limit': org['api_rate_limit'],
                    'subscription_plan': org['subscription_plan'],
                    'organization_name': org['name'],
                    'organization_slug': org['slug']
                }
                
                # Validate required M-Pesa credentials
                required_fields = ['consumer_key', 'consumer_secret', 'business_short_code', 
                                 'lipa_na_mpesa_passkey']
                missing_fields = [field for field in required_fields if not config.get(field)]
                if missing_fields:
                    raise Exception(f"Missing M-Pesa credentials for organization: {missing_fields}")
                
                return config
                
        except Exception as e:
            logger.error(f"Failed to get org config: {e}")
            raise

    @staticmethod
    async def create_organization(name: str, slug: str, admin_user: Dict) -> Dict:
        """Create new organization with admin user"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                # Check if slug already exists
                existing = await conn.fetchval("SELECT id FROM organizations WHERE slug = $1", slug)
                if existing:
                    raise Exception(f"Organization slug '{slug}' already exists")
                
                # Create organization
                org_id = await conn.fetchval("""
                    INSERT INTO organizations (name, slug, subscription_status, subscription_plan)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id
                """, name, slug, 'trial', 'basic')
                
                # Create admin user
                password_hash = generate_password_hash(admin_user['password'])
                user_id = await conn.fetchval("""
                    INSERT INTO users (organization_id, username, email, password_hash, role, permissions)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    RETURNING id
                """, org_id, admin_user['username'], admin_user['email'], 
                     password_hash, 'org_admin', json.dumps({"all": True}))
                
                return {
                    'organization_id': str(org_id),
                    'user_id': str(user_id),
                    'message': 'Organization created successfully'
                }
                
        except Exception as e:
            logger.error(f"Organization creation failed: {e}")
            raise

    @staticmethod
    async def update_org_credentials(org_id: str, credentials: Dict, user_id: str) -> Dict:
        """Update organization M-Pesa credentials"""
        try:
            update_fields = []
            params = []
            param_count = 0
            
            credential_mapping = {
                'consumer_key': 'mpesa_consumer_key',
                'consumer_secret': 'mpesa_consumer_secret',
                'business_short_code': 'mpesa_business_short_code',
                'lipa_na_mpesa_passkey': 'mpesa_lipa_na_mpesa_passkey',
                'initiator_name': 'mpesa_initiator_name',
                'security_credential': 'mpesa_security_credential',
                'base_url': 'mpesa_base_url',
                'callback_base_url': 'callback_base_url'
            }
            
            for field, db_field in credential_mapping.items():
                if credentials.get(field):
                    param_count += 1
                    update_fields.append(f"{db_field} = ${param_count}")
                    params.append(credentials[field])
            
            if not update_fields:
                raise Exception("No valid credentials provided")
            
            # Add updated_at
            param_count += 1
            update_fields.append(f"updated_at = ${param_count}")
            params.append(datetime.now())
            
            # Add organization_id for WHERE clause
            param_count += 1
            params.append(org_id)
            
            query = f"""
                UPDATE organizations 
                SET {', '.join(update_fields)}
                WHERE id = ${param_count}
            """
            
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute(query, *params)
            
            return {'message': 'Credentials updated successfully'}
            
        except Exception as e:
            logger.error(f"Credentials update failed: {e}")
            raise

    @staticmethod
    async def check_rate_limit(org_id: str) -> bool:
        """Check if organization has exceeded rate limits"""
        try:
            config = await OrganizationModel.get_org_config(org_id)
            rate_limit = config['api_rate_limit']
            
            # Count API calls in the last hour
            pool = get_db_pool()
            async with pool.acquire() as conn:
                count = await conn.fetchval("""
                    SELECT COUNT(*) FROM audit_logs 
                    WHERE organization_id = $1 
                    AND created_at > NOW() - INTERVAL '1 hour'
                """, org_id)
                
                return count < rate_limit
                
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return False

    @staticmethod
    async def list_organizations():
        """List all organizations with stats"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                orgs = await conn.fetch("""
                    SELECT o.*, 
                           COUNT(u.id) as user_count,
                           COUNT(t.id) as transaction_count,
                           SUM(CASE WHEN t.status = 'SUCCESS' THEN t.amount ELSE 0 END) as total_volume
                    FROM organizations o
                    LEFT JOIN users u ON o.id = u.organization_id
                    LEFT JOIN transactions t ON o.id = t.organization_id
                    GROUP BY o.id
                    ORDER BY o.created_at DESC
                """)
                
                return [dict(org) for org in orgs]
                
        except Exception as e:
            logger.error(f"Failed to list organizations: {e}")
            raise

    @staticmethod
    async def get_usage_stats(org_id: str) -> Dict:
        """Get organization usage statistics"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                # Get current month usage
                current_month_start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                
                usage_stats = await conn.fetchrow("""
                    SELECT 
                        COUNT(CASE WHEN a.created_at >= $2 THEN 1 END) as api_calls_this_month,
                        COUNT(CASE WHEN t.created_at >= $2 THEN 1 END) as transactions_this_month,
                        SUM(CASE WHEN t.created_at >= $2 AND t.status = 'SUCCESS' THEN t.amount ELSE 0 END) as volume_this_month,
                        COUNT(CASE WHEN bp.created_at >= $2 THEN 1 END) as bulk_payments_this_month
                    FROM organizations o
                    LEFT JOIN audit_logs a ON o.id = a.organization_id
                    LEFT JOIN transactions t ON o.id = t.organization_id
                    LEFT JOIN bulk_payments bp ON o.id = bp.organization_id
                    WHERE o.id = $1
                    GROUP BY o.id
                """, org_id, current_month_start)
                
                # Get rate limit info
                rate_limit_info = await conn.fetchrow("""
                    SELECT api_rate_limit, subscription_plan, subscription_status
                    FROM organizations WHERE id = $1
                """, org_id)
                
                return {
                    'usage': dict(usage_stats) if usage_stats else {},
                    'limits': dict(rate_limit_info) if rate_limit_info else {},
                    'period': current_month_start.isoformat()
                }
                
        except Exception as e:
            logger.error(f"Failed to get usage stats: {e}")
            raise

    @staticmethod
    async def store_api_token(org_id: str, access_token: str, expires_at):
        """Store API token in database"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO api_tokens (organization_id, access_token, expires_at) 
                    VALUES ($1, $2, $3)
                """, org_id, access_token, expires_at)
        except Exception as e:
            logger.error(f"Failed to store API token: {e}")
            raise
