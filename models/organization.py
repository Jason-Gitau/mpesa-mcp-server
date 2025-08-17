import logging
from datetime import datetime
from typing import Dict, Any, Optional
from utils.secure_database import get_secure_db

logger = logging.getLogger(__name__)

class SecureOrganizationModel:
    """Secure organization model with encrypted credentials and RLS"""
    
    @staticmethod
    async def get_org_config(org_id: str) -> Dict:
        """Get organization-specific M-Pesa configuration with decrypted credentials"""
        try:
            secure_db = get_secure_db()
            
            # ✅ CRITICAL: Connection automatically sets org context via RLS
            async with secure_db.get_connection(org_id) as conn:
                
                # Query will only return data for the specified org due to RLS
                org = await conn.fetchrow("""
                    SELECT id, name, slug,
                           mpesa_consumer_key_encrypted,
                           mpesa_consumer_secret_encrypted,
                           mpesa_business_short_code_encrypted,
                           mpesa_lipa_na_mpesa_passkey_encrypted,
                           mpesa_initiator_name_encrypted,
                           mpesa_security_credential_encrypted,
                           mpesa_base_url,
                           callback_base_url,
                           api_rate_limit,
                           subscription_plan,
                           subscription_status,
                           is_active
                    FROM organizations 
                    WHERE id = $1 AND is_active = true
                """, org_id)
                
                if not org:
                    raise Exception(f"Organization {org_id} not found or inactive")
                
                # Check subscription status
                if org['subscription_status'] not in ['trial', 'active']:
                    raise Exception(f"Organization subscription is {org['subscription_status']}")
                
                # ✅ DECRYPT credentials securely
                config = {
                    'consumer_key': await secure_db.decrypt_credential(
                        org['mpesa_consumer_key_encrypted']
                    ) if org['mpesa_consumer_key_encrypted'] else None,
                    
                    'consumer_secret': await secure_db.decrypt_credential(
                        org['mpesa_consumer_secret_encrypted']
                    ) if org['mpesa_consumer_secret_encrypted'] else None,
                    
                    'business_short_code': await secure_db.decrypt_credential(
                        org['mpesa_business_short_code_encrypted']
                    ) if org['mpesa_business_short_code_encrypted'] else None,
                    
                    'lipa_na_mpesa_passkey': await secure_db.decrypt_credential(
                        org['mpesa_lipa_na_mpesa_passkey_encrypted']
                    ) if org['mpesa_lipa_na_mpesa_passkey_encrypted'] else None,
                    
                    'initiator_name': await secure_db.decrypt_credential(
                        org['mpesa_initiator_name_encrypted']
                    ) if org['mpesa_initiator_name_encrypted'] else None,
                    
                    'security_credential': await secure_db.decrypt_credential(
                        org['mpesa_security_credential_encrypted']  
                    ) if org['mpesa_security_credential_encrypted'] else None,
                    
                    # Non-encrypted fields
                    'base_url': org['mpesa_base_url'] or 'https://sandbox.safaricom.co.ke',
                    'callback_base_url': org['callback_base_url'],
                    'api_rate_limit': org['api_rate_limit'],
                    'subscription_plan': org['subscription_plan'],
                    'organization_name': org['name'],
                    'organization_slug': org['slug']
                }
                
                # ✅ Validate required M-Pesa credentials
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
    async def create_organization(name: str, slug: str, admin_user: Dict, 
                                mpesa_credentials: Dict) -> Dict:
        """Create new organization with encrypted M-Pesa credentials"""
        try:
            secure_db = get_secure_db()
            
            # Use a temporary connection without org context for creation
            async with secure_db.pool.acquire() as conn:
                
                # Check if slug already exists
                existing = await conn.fetchval(
                    "SELECT id FROM organizations WHERE slug = $1", slug
                )
                if existing:
                    raise Exception(f"Organization slug '{slug}' already exists")
                
                # ✅ ENCRYPT M-Pesa credentials before storage
                encrypted_credentials = {}
                credential_fields = [
                    'consumer_key', 'consumer_secret', 'business_short_code',
                    'lipa_na_mpesa_passkey', 'initiator_name', 'security_credential'
                ]
                
                for field in credential_fields:
                    if mpesa_credentials.get(field):
                        encrypted_credentials[f"{field}_encrypted"] = await secure_db.encrypt_credential(
                            mpesa_credentials[field]
                        )
                
                # Create organization with encrypted credentials
                org_id = await conn.fetchval("""
                    INSERT INTO organizations (
                        name, slug, subscription_status, subscription_plan,
                        mpesa_consumer_key_encrypted,
                        mpesa_consumer_secret_encrypted,
                        mpesa_business_short_code_encrypted,
                        mpesa_lipa_na_mpesa_passkey_encrypted,
                        mpesa_initiator_name_encrypted,
                        mpesa_security_credential_encrypted,
                        mpesa_base_url,
                        callback_base_url
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    RETURNING id
                """, 
                    name, slug, 'trial', 'basic',
                    encrypted_credentials.get('consumer_key_encrypted'),
                    encrypted_credentials.get('consumer_secret_encrypted'),
                    encrypted_credentials.get('business_short_code_encrypted'),
                    encrypted_credentials.get('lipa_na_mpesa_passkey_encrypted'),
                    encrypted_credentials.get('initiator_name_encrypted'),
                    encrypted_credentials.get('security_credential_encrypted'),
                    mpesa_credentials.get('base_url', 'https://sandbox.safaricom.co.ke'),
                    mpesa_credentials.get('callback_base_url')
                )
                
                # ✅ Now create admin user with secure password hashing
                from werkzeug.security import generate_password_hash
                import secrets
                
                password_salt = secrets.token_hex(16)
                password_hash = generate_password_hash(
                    admin_user['password'] + password_salt, 
                    method='pbkdf2:sha256:100000'
                )
                
                user_id = await conn.fetchval("""
                    INSERT INTO users (
                        organization_id, username, email, 
                        password_hash, password_salt, password_iterations,
                        role, permissions
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    RETURNING id
                """, 
                    org_id, admin_user['username'], admin_user['email'], 
                    password_hash, password_salt, 100000,
                    'org_admin', {"all": True}
                )
                
                return {
                    'organization_id': str(org_id),
                    'user_id': str(user_id),
                    'message': 'Organization created successfully with encrypted credentials'
                }
                
        except Exception as e:
            logger.error(f"Organization creation failed: {e}")
            raise

    @staticmethod
    async def update_org_credentials(org_id: str, credentials: Dict, user_id: str) -> Dict:
        """Update organization M-Pesa credentials with encryption"""
        try:
            secure_db = get_secure_db()
            
            # ✅ Use organization context for security
            async with secure_db.get_connection(org_id, user_id) as conn:
                
                update_fields = []
                params = []
                param_count = 0
                
                # Mapping of API fields to encrypted database columns
                credential_mapping = {
                    'consumer_key': 'mpesa_consumer_key_encrypted',
                    'consumer_secret': 'mpesa_consumer_secret_encrypted', 
                    'business_short_code': 'mpesa_business_short_code_encrypted',
                    'lipa_na_mpesa_passkey': 'mpesa_lipa_na_mpesa_passkey_encrypted',
                    'initiator_name': 'mpesa_initiator_name_encrypted',
                    'security_credential': 'mpesa_security_credential_encrypted'
                }
                
                # Non-encrypted fields
                non_encrypted_mapping = {
                    'base_url': 'mpesa_base_url',
                    'callback_base_url': 'callback_base_url'
                }
                
                # ✅ Encrypt sensitive credentials
                for field, db_field in credential_mapping.items():
                    if credentials.get(field):
                        param_count += 1
                        encrypted_value = await secure_db.encrypt_credential(credentials[field])
                        update_fields.append(f"{db_field} = ${param_count}")
                        params.append(encrypted_value)
                
                # Handle non-encrypted fields
                for field, db_field in non_encrypted_mapping.items():
                    if credentials.get(field):
                        param_count += 1
                        update_fields.append(f"{db_field} = ${param_count}")
                        params.append(credentials[field])
                
                if not update_fields:
                    raise Exception("No valid credentials provided")
                
                # Add updated_at timestamp
                param_count += 1
                update_fields.append(f"updated_at = ${param_count}")
                params.append(datetime.now())
                
                # Add organization_id for WHERE clause (RLS will also enforce this)
                param_count += 1
                params.append(org_id)
                
                query = f"""
                    UPDATE organizations 
                    SET {', '.join(update_fields)}
                    WHERE id = ${param_count}
                """
                
                await conn.execute(query, *params)
                
                # ✅ Audit the credential update
                await secure_db.store_audit_log(
                    org_id, user_id, 'CREDENTIALS_UPDATED', 'update_org_credentials',
                    {'fields_updated': list(credentials.keys())},
                    {'message': 'Credentials updated successfully'},
                    'SUCCESS', '127.0.0.1', 'System'
                )
                
                return {'message': 'Encrypted credentials updated successfully'}
                
        except Exception as e:
            logger.error(f"Credentials update failed: {e}")
            raise

    @staticmethod
    async def check_rate_limit(org_id: str) -> bool:
        """Check if organization has exceeded rate limits with RLS protection"""
        try:
            secure_db = get_secure_db()
            
            async with secure_db.get_connection(org_id) as conn:
                
                # Get rate limit for this organization (RLS ensures org isolation)
                rate_limit = await conn.fetchval("""
                    SELECT api_rate_limit FROM organizations WHERE id = $1
                """, org_id)
                
                if not rate_limit:
                    return False
                
                # Count API calls in the last hour (RLS ensures org isolation)
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
    async def list_organizations(requesting_user_id: str, requesting_user_role: str):
        """List organizations (super admin sees all, org admin sees own only)"""
        try:
            secure_db = get_secure_db()
            
            if requesting_user_role == 'super_admin':
                # Super admin can see all organizations
                async with secure_db.pool.acquire() as conn:
                    # Temporarily override RLS for super admin
                    await conn.execute("SET row_security = off")
                    
                    orgs = await conn.fetch("""
                        SELECT o.id, o.name, o.slug, o.subscription_status, 
                               o.subscription_plan, o.is_active, o.created_at,
                               COUNT(u.id) as user_count,
                               COUNT(t.id) as transaction_count
                        FROM organizations o
                        LEFT JOIN users u ON o.id = u.organization_id
                        LEFT JOIN transactions t ON o.id = t.organization_id 
                        GROUP BY o.id
                        ORDER BY o.created_at DESC
                    """)
                    
                    await conn.execute("SET row_security = on")
                    return [dict(org) for org in orgs]
                    
            else:
                # Regular users see only their organization
                # Get user's organization first
                user_org_id = await SecureOrganizationModel._get_user_org_id(requesting_user_id)
                
                async with secure_db.get_connection(user_org_id, requesting_user_id) as conn:
                    org = await conn.fetchrow("""
                        SELECT o.id, o.name, o.slug, o.subscription_status,
                               o.subscription_plan, o.is_active, o.created_at,
                               COUNT(u.id) as user_count,
                               COUNT(t.id) as transaction_count
                        FROM organizations o
                        LEFT JOIN users u ON o.id = u.organization_id
                        LEFT JOIN transactions t ON o.id = t.organization_id
                        WHERE o.id = $1
                        GROUP BY o.id
                    """, user_org_id)
                    
                    return [dict(org)] if org else []
                    
        except Exception as e:
            logger.error(f"Failed to list organizations: {e}")
            raise

    @staticmethod
    async def get_usage_stats(org_id: str, requesting_user_id: str) -> Dict:
        """Get organization usage statistics with RLS protection"""
        try:
            secure_db = get_secure_db()
            
            async with secure_db.get_connection(org_id, requesting_user_id) as conn:
                
                # Get current month usage (RLS ensures org isolation)
                current_month_start = datetime.now().replace(
                    day=1, hour=0, minute=0, second=0, microsecond=0
                )
                
                usage_stats = await conn.fetchrow("""
                    SELECT 
                        COUNT(CASE WHEN a.created_at >= $2 THEN 1 END) as api_calls_this_month,
                        COUNT(CASE WHEN t.created_at >= $2 THEN 1 END) as transactions_this_month,
                        SUM(CASE WHEN t.created_at >= $2 AND t.status = 'SUCCESS' 
                            THEN t.amount ELSE 0 END) as volume_this_month,
                        COUNT(CASE WHEN bp.created_at >= $2 THEN 1 END) as bulk_payments_this_month
                    FROM organizations o
                    LEFT JOIN audit_logs a ON o.id = a.organization_id
                    LEFT JOIN transactions t ON o.id = t.organization_id
                    LEFT JOIN bulk_payments bp ON o.id = bp.organization_id
                    WHERE o.id = $1
                    GROUP BY o.id
                """, org_id, current_month_start)
                
                # Get rate limit info (RLS ensures org isolation)
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
        """Store API token with hashing (not plain text)"""
        try:
            secure_db = get_secure_db()
            
            # ✅ Hash the token instead of storing in plain text
            import hashlib
            token_hash = hashlib.sha256(access_token.encode()).hexdigest()
            token_prefix = access_token[:10]  # For identification
            
            async with secure_db.get_connection(org_id) as conn:
                await conn.execute("""
                    INSERT INTO api_tokens (
                        organization_id, access_token_hash, token_prefix, 
                        expires_at, last_used
                    ) VALUES ($1, $2, $3, $4, NOW())
                """, org_id, token_hash, token_prefix, expires_at)
                
        except Exception as e:
            logger.error(f"Failed to store API token: {e}")
            raise

    @staticmethod
    async def _get_user_org_id(user_id: str) -> str:
        """Helper to get user's organization ID"""
        secure_db = get_secure_db()
        
        async with secure_db.pool.acquire() as conn:
            org_id = await conn.fetchval("""
                SELECT organization_id FROM users WHERE id = $1 AND is_active = true
            """, user_id)
            
            if not org_id:
                raise Exception(f"User {user_id} not found or inactive")
                
            return str(org_id)
