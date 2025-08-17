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
                    'lipa_na_mpesa_passkey',
