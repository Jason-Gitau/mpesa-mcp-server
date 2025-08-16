import os
import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from decimal import Decimal
import hashlib
import hmac
import base64
from functools import wraps

import asyncpg
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import httpx
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MPesaDarajaMCPServer:
    def __init__(self, supabase_url: str = None, supabase_key: str = None):
        self.supabase_url = supabase_url
        self.supabase_key = supabase_key
        self.db_pool = None
        
        # Cache for organization configs and tokens
        self.org_configs = {}
        self.org_tokens = {}
        
    async def init_db(self):
        """Initialize database connection pool"""
        try:
            self.db_pool = await asyncpg.create_pool(
                host=os.getenv('DB_HOST'),
                port=os.getenv('DB_PORT', 5432),
                database=os.getenv('DB_NAME'),
                user=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD'),
                min_size=1,
                max_size=10
            )
            logger.info("Database connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    async def get_org_config(self, org_id: str) -> Dict:
        """Get organization-specific M-Pesa configuration"""
        if org_id in self.org_configs:
            return self.org_configs[org_id]
            
        try:
            async with self.db_pool.acquire() as conn:
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
                
                self.org_configs[org_id] = config
                return config
                
        except Exception as e:
            logger.error(f"Failed to get org config: {e}")
            raise

    async def get_user_organization(self, user_id: str) -> str:
        """Get organization ID for a user"""
        try:
            async with self.db_pool.acquire() as conn:
                user = await conn.fetchrow("""
                    SELECT organization_id FROM users WHERE id = $1 AND is_active = true
                """, user_id)
                
                if not user:
                    raise Exception(f"User {user_id} not found or inactive")
                
                return str(user['organization_id'])
                
        except Exception as e:
            logger.error(f"Failed to get user organization: {e}")
            raise

    async def check_rate_limit(self, org_id: str) -> bool:
        """Check if organization has exceeded rate limits"""
        try:
            config = await self.get_org_config(org_id)
            rate_limit = config['api_rate_limit']
            
            # Count API calls in the last hour
            async with self.db_pool.acquire() as conn:
                count = await conn.fetchval("""
                    SELECT COUNT(*) FROM audit_logs 
                    WHERE organization_id = $1 
                    AND created_at > NOW() - INTERVAL '1 hour'
                """, org_id)
                
                return count < rate_limit
                
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return False

    async def get_access_token(self, org_id: str) -> str:
        """Get or refresh Daraja API access token for specific organization"""
        token_key = f"{org_id}_token"
        expires_key = f"{org_id}_expires"
        
        if (token_key in self.org_tokens and expires_key in self.org_tokens and 
            datetime.now() < self.org_tokens[expires_key]):
            return self.org_tokens[token_key]
            
        try:
            config = await self.get_org_config(org_id)
            
            url = f"{config['base_url']}/oauth/v1/generate?grant_type=client_credentials"
            credentials = f"{config['consumer_key']}:{config['consumer_secret']}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {encoded_credentials}',
                'Content-Type': 'application/json'
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                
                data = response.json()
                access_token = data['access_token']
                expires_in = int(data['expires_in'])
                expires_at = datetime.now() + timedelta(seconds=expires_in - 60)
                
                # Cache token
                self.org_tokens[token_key] = access_token
                self.org_tokens[expires_key] = expires_at
                
                # Store token in database
                async with self.db_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO api_tokens (organization_id, access_token, expires_at) 
                        VALUES ($1, $2, $3)
                    """, org_id, access_token, expires_at)
                
                return access_token
                
        except Exception as e:
            logger.error(f"Failed to get access token for org {org_id}: {e}")
            raise

    async def log_audit(self, user_id: str, org_id: str, action: str, tool_name: str, 
                       request_data: Dict, response_data: Dict, status: str,
                       ip_address: str = None, user_agent: str = None):
        """Log audit trail with organization context"""
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO audit_logs (organization_id, user_id, action, tool_name, request_data, 
                                          response_data, status, ip_address, user_agent)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """, org_id, user_id, action, tool_name, json.dumps(request_data), 
                     json.dumps(response_data), status, ip_address, user_agent)
        except Exception as e:
            logger.error(f"Failed to log audit: {e}")

    async def stk_push_payment(self, phone_number: str, amount: float, 
                              account_reference: str, transaction_desc: str,
                              user_id: str, org_id: str) -> Dict:
        """Tool: STK Push Payment Initiator"""
        try:
            # Check rate limits
            if not await self.check_rate_limit(org_id):
                raise Exception("Rate limit exceeded for organization")
            
            config = await self.get_org_config(org_id)
            access_token = await self.get_access_token(org_id)
            
            # Generate timestamp and password
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            password_string = f"{config['business_short_code']}{config['lipa_na_mpesa_passkey']}{timestamp}"
            password = base64.b64encode(password_string.encode()).decode()
            
            url = f"{config['base_url']}/mpesa/stkpush/v1/processrequest"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Generate organization-specific callback URL
            callback_url = f"{config['callback_base_url']}/mpesa/callback/{org_id}"
            
            payload = {
                'BusinessShortCode': config['business_short_code'],
                'Password': password,
                'Timestamp': timestamp,
                'TransactionType': 'CustomerPayBillOnline',
                'Amount': int(amount),
                'PartyA': phone_number,
                'PartyB': config['business_short_code'],
                'PhoneNumber': phone_number,
                'CallBackURL': callback_url,
                'AccountReference': account_reference,
                'TransactionDesc': transaction_desc
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers)
                result = response.json()
                
                # Store transaction in database with organization context
                async with self.db_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO transactions (organization_id, merchant_request_id, checkout_request_id,
                                                transaction_type, amount, phone_number,
                                                account_reference, transaction_desc, initiated_by, status)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    """, org_id, result.get('MerchantRequestID'), result.get('CheckoutRequestID'),
                         'STK_PUSH', Decimal(str(amount)), phone_number, 
                         account_reference, transaction_desc, user_id, 'PENDING')
                
                await self.log_audit(user_id, org_id, 'STK_PUSH_INITIATED', 'stk_push_payment',
                                   payload, result, 'SUCCESS',
                                   request.environ.get('REMOTE_ADDR'),
                                   request.headers.get('User-Agent'))
                
                return result
                
        except Exception as e:
            logger.error(f"STK Push failed: {e}")
            await self.log_audit(user_id, org_id, 'STK_PUSH_INITIATED', 'stk_push_payment',
                               payload if 'payload' in locals() else {}, {'error': str(e)}, 'FAILED',
                               request.environ.get('REMOTE_ADDR'),
                               request.headers.get('User-Agent'))
            raise

    async def check_transaction_status(self, checkout_request_id: str, user_id: str, org_id: str) -> Dict:
        """Tool: Transaction Status Tracker"""
        try:
            config = await self.get_org_config(org_id)
            access_token = await self.get_access_token(org_id)
            
            # Generate timestamp and password
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            password_string = f"{config['business_short_code']}{config['lipa_na_mpesa_passkey']}{timestamp}"
            password = base64.b64encode(password_string.encode()).decode()
            
            url = f"{config['base_url']}/mpesa/stkpushquery/v1/query"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'BusinessShortCode': config['business_short_code'],
                'Password': password,
                'Timestamp': timestamp,
                'CheckoutRequestID': checkout_request_id
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers)
                result = response.json()
                
                # Update transaction status in database (organization-scoped)
                async with self.db_pool.acquire() as conn:
                    await conn.execute("""
                        UPDATE transactions SET status = $1, result_code = $2, 
                                              result_desc = $3, updated_at = NOW()
                        WHERE checkout_request_id = $4 AND organization_id = $5
                    """, result.get('ResultDesc', 'PENDING'), 
                         result.get('ResultCode'), result.get('ResultDesc'), 
                         checkout_request_id, org_id)
                
                await self.log_audit(user_id, org_id, 'TRANSACTION_STATUS_CHECK', 'check_transaction_status',
                                   payload, result, 'SUCCESS',
                                   request.environ.get('REMOTE_ADDR'),
                                   request.headers.get('User-Agent'))
                
                return result
                
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            await self.log_audit(user_id, org_id, 'TRANSACTION_STATUS_CHECK', 'check_transaction_status',
                               payload if 'payload' in locals() else {}, {'error': str(e)}, 'FAILED',
                               request.environ.get('REMOTE_ADDR'),
                               request.headers.get('User-Agent'))
            raise

    async def get_account_balance(self, user_id: str, org_id: str, account_type: str = 'PAYBILL') -> Dict:
        """Tool: Account Balance Checker"""
        try:
            config = await self.get_org_config(org_id)
            access_token = await self.get_access_token(org_id)
            
            url = f"{config['base_url']}/mpesa/accountbalance/v1/query"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Organization-specific callback URLs
            result_url = f"{config['callback_base_url']}/mpesa/balance/result/{org_id}"
            timeout_url = f"{config['callback_base_url']}/mpesa/balance/timeout/{org_id}"
            
            payload = {
                'Initiator': config['initiator_name'],
                'SecurityCredential': config['security_credential'],
                'CommandID': 'AccountBalance',
                'PartyA': config['business_short_code'],
                'IdentifierType': '4',
                'ResultURL': result_url,
                'QueueTimeOutURL': timeout_url,
                'Remarks': f'Account balance check for {config["organization_name"]}'
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers)
                result = response.json()
                
                await self.log_audit(user_id, org_id, 'BALANCE_CHECK', 'get_account_balance',
                                   payload, result, 'SUCCESS',
                                   request.environ.get('REMOTE_ADDR'),
                                   request.headers.get('User-Agent'))
                
                return result
                
        except Exception as e:
            logger.error(f"Balance check failed: {e}")
            await self.log_audit(user_id, org_id, 'BALANCE_CHECK', 'get_account_balance',
                               payload if 'payload' in locals() else {}, {'error': str(e)}, 'FAILED',
                               request.environ.get('REMOTE_ADDR'),
                               request.headers.get('User-Agent'))
            raise

    async def bulk_payment(self, payments: List[Dict], batch_name: str, user_id: str, org_id: str) -> Dict:
        """Tool: Bulk Payment Processor"""
        try:
            # Check rate limits for bulk operations
            if not await self.check_rate_limit(org_id):
                raise Exception("Rate limit exceeded for organization")
            
            config = await self.get_org_config(org_id)
            access_token = await self.get_access_token(org_id)
            batch_id = f"BATCH_{config['organization_slug']}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            total_amount = sum(payment['amount'] for payment in payments)
            
            # Store bulk payment record with organization context
            async with self.db_pool.acquire() as conn:
                bulk_payment_id = await conn.fetchval("""
                    INSERT INTO bulk_payments (organization_id, batch_id, batch_name, total_amount, 
                                             total_recipients, initiated_by, status)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING id
                """, org_id, batch_id, batch_name, Decimal(str(total_amount)), 
                     len(payments), user_id, 'PROCESSING')
            
            results = []
            success_count = 0
            
            # Organization-specific callback URLs
            result_url = f"{config['callback_base_url']}/mpesa/b2c/result/{org_id}"
            timeout_url = f"{config['callback_base_url']}/mpesa/b2c/timeout/{org_id}"
            
            for payment in payments:
                try:
                    url = f"{config['base_url']}/mpesa/b2c/v1/paymentrequest"
                    headers = {
                        'Authorization': f'Bearer {access_token}',
                        'Content-Type': 'application/json'
                    }
                    
                    payload = {
                        'InitiatorName': config['initiator_name'],
                        'SecurityCredential': config['security_credential'],
                        'CommandID': 'BusinessPayment',
                        'Amount': int(payment['amount']),
                        'PartyA': config['business_short_code'],
                        'PartyB': payment['phone_number'],
                        'Remarks': payment.get('remarks', 'Bulk payment'),
                        'QueueTimeOutURL': timeout_url,
                        'ResultURL': result_url,
                        'Occasion': payment.get('occasion', batch_name)
                    }
                    
                    async with httpx.AsyncClient() as client:
                        response = await client.post(url, json=payload, headers=headers)
                        result = response.json()
                        
                        # Store individual payment with organization context
                        async with self.db_pool.acquire() as conn:
                            await conn.execute("""
                                INSERT INTO bulk_payment_items (bulk_payment_id, phone_number, 
                                                               amount, account_reference, remarks, status)
                                VALUES ($1, $2, $3, $4, $5, $6)
                            """, bulk_payment_id, payment['phone_number'], 
                                 Decimal(str(payment['amount'])), 
                                 payment.get('account_reference'), payment.get('remarks'), 'PENDING')
                        
                        if result.get('ResponseCode') == '0':
                            success_count += 1
                        
                        results.append({
                            'phone_number': payment['phone_number'],
                            'amount': payment['amount'],
                            'result': result
                        })
                        
                except Exception as e:
                    logger.error(f"Individual payment failed: {e}")
                    results.append({
                        'phone_number': payment['phone_number'],
                        'amount': payment['amount'],
                        'error': str(e)
                    })
            
            # Update bulk payment status
            status = 'COMPLETED' if success_count == len(payments) else 'FAILED'
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE bulk_payments SET status = $1, completed_at = NOW()
                    WHERE id = $2 AND organization_id = $3
                """, status, bulk_payment_id, org_id)
            
            final_result = {
                'batch_id': batch_id,
                'organization_id': org_id,
                'total_payments': len(payments),
                'successful_payments': success_count,
                'total_amount': total_amount,
                'results': results
            }
            
            await self.log_audit(user_id, org_id, 'BULK_PAYMENT', 'bulk_payment',
                               {'batch_name': batch_name, 'payments': payments}, 
                               final_result, 'SUCCESS',
                               request.environ.get('REMOTE_ADDR'),
                               request.headers.get('User-Agent'))
            
            return final_result
            
        except Exception as e:
            logger.error(f"Bulk payment failed: {e}")
            await self.log_audit(user_id, org_id, 'BULK_PAYMENT', 'bulk_payment',
                               {'batch_name': batch_name} if 'batch_name' in locals() else {}, 
                               {'error': str(e)}, 'FAILED',
                               request.environ.get('REMOTE_ADDR'),
                               request.headers.get('User-Agent'))
            raise

    async def reverse_transaction(self, transaction_id: str, amount: float, 
                                reason: str, user_id: str, org_id: str) -> Dict:
        """Tool: Transaction Reversal"""
        try:
            config = await self.get_org_config(org_id)
            access_token = await self.get_access_token(org_id)
            
            url = f"{config['base_url']}/mpesa/reversal/v1/request"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Organization-specific callback URLs
            result_url = f"{config['callback_base_url']}/mpesa/reversal/result/{org_id}"
            timeout_url = f"{config['callback_base_url']}/mpesa/reversal/timeout/{org_id}"
            
            payload = {
                'Initiator': config['initiator_name'],
                'SecurityCredential': config['security_credential'],
                'CommandID': 'TransactionReversal',
                'TransactionID': transaction_id,
                'Amount': int(amount),
                'ReceiverParty': config['business_short_code'],
                'RecieverIdentifierType': '11',
                'ResultURL': result_url,
                'QueueTimeOutURL': timeout_url,
                'Remarks': reason,
                'Occasion': 'Transaction reversal'
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers)
                result = response.json()
                
                # Store reversal record with organization context
                async with self.db_pool.acquire() as conn:
                    original_transaction = await conn.fetchrow("""
                        SELECT id FROM transactions WHERE transaction_id = $1 AND organization_id = $2
                    """, transaction_id, org_id)
                    
                    if original_transaction:
                        await conn.execute("""
                            INSERT INTO reversals (original_transaction_id, amount, 
                                                 reason, initiated_by, status)
                            VALUES ($1, $2, $3, $4, $5)
                        """, original_transaction['id'], Decimal(str(amount)), 
                             reason, user_id, 'PENDING')
                
                await self.log_audit(user_id, org_id, 'TRANSACTION_REVERSAL', 'reverse_transaction',
                                   payload, result, 'SUCCESS',
                                   request.environ.get('REMOTE_ADDR'),
                                   request.headers.get('User-Agent'))
                
                return result
                
        except Exception as e:
            logger.error(f"Transaction reversal failed: {e}")
            await self.log_audit(user_id, org_id, 'TRANSACTION_REVERSAL', 'reverse_transaction',
                               payload if 'payload' in locals() else {}, {'error': str(e)}, 'FAILED',
                               request.environ.get('REMOTE_ADDR'),
                               request.headers.get('User-Agent'))
            raise

    async def get_transaction_history(self, filters: Dict, user_id: str, org_id: str) -> List[Dict]:
        """Tool: Payment Reconciliation Dashboard with organization isolation"""
        try:
            query = """
                SELECT t.*, u.username as initiated_by_username
                FROM transactions t
                LEFT JOIN users u ON t.initiated_by = u.id
                WHERE t.organization_id = $1
            """
            params = [org_id]
            param_count = 1
            
            if filters.get('start_date'):
                param_count += 1
                query += f" AND t.created_at >= ${param_count}"
                params.append(filters['start_date'])
            
            if filters.get('end_date'):
                param_count += 1
                query += f" AND t.created_at <= ${param_count}"
                params.append(filters['end_date'])
            
            if filters.get('status'):
                param_count += 1
                query += f" AND t.status = ${param_count}"
                params.append(filters['status'])
            
            if filters.get('transaction_type'):
                param_count += 1
                query += f" AND t.transaction_type = ${param_count}"
                params.append(filters['transaction_type'])
            
            if filters.get('phone_number'):
                param_count += 1
                query += f" AND t.phone_number = ${param_count}"
                params.append(filters['phone_number'])
            
            query += " ORDER BY t.created_at DESC"
            
            if filters.get('limit'):
                param_count += 1
                query += f" LIMIT ${param_count}"
                params.append(filters['limit'])
            
            async with self.db_pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                
                result = [dict(row) for row in rows]
                
                await self.log_audit(user_id, org_id, 'TRANSACTION_HISTORY_QUERY', 'get_transaction_history',
                                   filters, {'count': len(result)}, 'SUCCESS',
                                   request.environ.get('REMOTE_ADDR'),
                                   request.headers.get('User-Agent'))
                
                return result
                
        except Exception as e:
            logger.error(f"Transaction history query failed: {e}")
            await self.log_audit(user_id, org_id, 'TRANSACTION_HISTORY_QUERY', 'get_transaction_history',
                               filters, {'error': str(e)}, 'FAILED',
                               request.environ.get('REMOTE_ADDR'),
                               request.headers.get('User-Agent'))
            raise

    async def create_organization(self, name: str, slug: str, admin_user: Dict) -> Dict:
        """Create new organization with admin user"""
        try:
            async with self.db_pool.acquire() as conn:
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

    async def update_org_credentials(self, org_id: str, credentials: Dict, user_id: str) -> Dict:
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
            
            async with self.db_pool.acquire() as conn:
                await conn.execute(query, *params)
            
            # Clear cached config
            if org_id in self.org_configs:
                del self.org_configs[org_id]
            
            await self.log_audit(user_id, org_id, 'CREDENTIALS_UPDATE', 'update_org_credentials',
                               list(credentials.keys()), {'updated': True}, 'SUCCESS')
            
            return {'message': 'Credentials updated successfully'}
            
        except Exception as e:
            logger.error(f"Credentials update failed: {e}")
            raise

# Initialize Flask app
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Initialize MCP server
mcp_server = MPesaDarajaMCPServer(
    supabase_url=os.getenv('SUPABASE_URL'),
    supabase_key=os.getenv('SUPABASE_KEY')
)

def require_auth(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'No authorization token provided'}), 401
        
        try:
            token = token.split(' ')[1]
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user_id = payload['user_id']
            g.current_user_role = payload.get('role', 'user')
            g.current_org_id = payload.get('organization_id')
            
            # Get organization ID if not in token
            if not g.current_org_id:
                g.current_org_id = await mcp_server.get_user_organization(g.current_user_id)
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return await f(*args, **kwargs)
    return decorated_function

def require_org_admin(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        if g.current_user_role not in ['super_admin', 'org_admin']:
            return jsonify({'error': 'Organization admin access required'}), 403
        return await f(*args, **kwargs)
    return decorated_function

@app.before_first_request
async def init_app():
    """Initialize the application"""
    await mcp_server.init_db()

# Authentication endpoints
@app.route('/auth/login', methods=['POST'])
async def login():
    """User authentication with organization context"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    organization_slug = data.get('organization')  # Optional organization slug
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    try:
        async with mcp_server.db_pool.acquire() as conn:
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
                return jsonify({'error': 'Invalid credentials'}), 401
            
            if user['subscription_status'] not in ['trial', 'active']:
                return jsonify({'error': 'Organization subscription is inactive'}), 403
            
            # Generate JWT token with organization context
            token_payload = {
                'user_id': str(user['id']),
                'username': user['username'],
                'role': user['role'],
                'organization_id': str(user['organization_id']),
                'organization_slug': user['org_slug'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }
            
            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
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
            })
            
    except Exception as e:
        logger.error(f"Login failed: {e}")
        return jsonify({'error': 'Login failed'}), 500

# Organization Management Endpoints
@app.route('/organizations', methods=['POST'])
async def create_organization():
    """Create new organization (super admin only)"""
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
        
        result = await mcp_server.create_organization(
            name=data['name'],
            slug=data['slug'],
            admin_user=admin_user
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Organization created successfully'
        })
        
    except Exception as e:
        logger.error(f"Organization creation failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/organizations/<org_id>/credentials', methods=['PUT'])
@require_auth
@require_org_admin
async def update_credentials(org_id):
    """Update organization M-Pesa credentials"""
    if g.current_org_id != org_id and g.current_user_role != 'super_admin':
        return jsonify({'error': 'Access denied to this organization'}), 403
    
    data = request.get_json()
    
    try:
        result = await mcp_server.update_org_credentials(
            org_id=org_id,
            credentials=data,
            user_id=g.current_user_id
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Credentials updated successfully'
        })
        
    except Exception as e:
        logger.error(f"Credentials update failed: {e}")
        return jsonify({'error': str(e)}), 500

# MCP Server Tool Endpoints with Multi-Tenant Support

@app.route('/tools/stk-push', methods=['POST'])
@require_auth
async def stk_push():
    """STK Push Payment Initiator Tool"""
    try:
        data = request.get_json()
        required_fields = ['phone_number', 'amount', 'account_reference', 'transaction_desc']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        result = await mcp_server.stk_push_payment(
            phone_number=data['phone_number'],
            amount=float(data['amount']),
            account_reference=data['account_reference'],
            transaction_desc=data['transaction_desc'],
            user_id=g.current_user_id,
            org_id=g.current_org_id
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'STK Push initiated successfully'
        })
        
    except Exception as e:
        logger.error(f"STK Push endpoint failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/tools/transaction-status/<checkout_request_id>', methods=['GET'])
@require_auth
async def check_status(checkout_request_id):
    """Transaction Status Tracker Tool"""
    try:
        result = await mcp_server.check_transaction_status(
            checkout_request_id=checkout_request_id,
            user_id=g.current_user_id,
            org_id=g.current_org_id
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Transaction status retrieved successfully'
        })
        
    except Exception as e:
        logger.error(f"Transaction status check failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/tools/account-balance', methods=['GET'])
@require_auth
async def check_balance():
    """Account Balance Checker Tool"""
    try:
        account_type = request.args.get('account_type', 'PAYBILL')
        
        result = await mcp_server.get_account_balance(
            user_id=g.current_user_id,
            org_id=g.current_org_id,
            account_type=account_type
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Balance check initiated successfully'
        })
        
    except Exception as e:
        logger.error(f"Balance check failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/tools/bulk-payment', methods=['POST'])
@require_auth
async def bulk_payment():
    """Bulk Payment Processor Tool"""
    try:
        data = request.get_json()
        
        if not data.get('payments') or not isinstance(data['payments'], list):
            return jsonify({'error': 'payments list is required'}), 400
        
        if not data.get('batch_name'):
            return jsonify({'error': 'batch_name is required'}), 400
        
        # Validate each payment
        for i, payment in enumerate(data['payments']):
            required_fields = ['phone_number', 'amount']
            for field in required_fields:
                if not payment.get(field):
                    return jsonify({'error': f'Payment {i+1}: {field} is required'}), 400
        
        result = await mcp_server.bulk_payment(
            payments=data['payments'],
            batch_name=data['batch_name'],
            user_id=g.current_user_id,
            org_id=g.current_org_id
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Bulk payment processed successfully'
        })
        
    except Exception as e:
        logger.error(f"Bulk payment failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/tools/reverse-transaction', methods=['POST'])
@require_auth
async def reverse_transaction():
    """Transaction Reversal Tool"""
    try:
        data = request.get_json()
        required_fields = ['transaction_id', 'amount', 'reason']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        result = await mcp_server.reverse_transaction(
            transaction_id=data['transaction_id'],
            amount=float(data['amount']),
            reason=data['reason'],
            user_id=g.current_user_id,
            org_id=g.current_org_id
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Transaction reversal initiated successfully'
        })
        
    except Exception as e:
        logger.error(f"Transaction reversal failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/tools/transaction-history', methods=['GET'])
@require_auth
async def transaction_history():
    """Payment Reconciliation Dashboard Tool"""
    try:
        # Get query parameters for filtering
        filters = {
            'start_date': request.args.get('start_date'),
            'end_date': request.args.get('end_date'),
            'status': request.args.get('status'),
            'transaction_type': request.args.get('transaction_type'),
            'phone_number': request.args.get('phone_number'),
            'limit': int(request.args.get('limit', 100))
        }
        
        # Remove None values
        filters = {k: v for k, v in filters.items() if v is not None}
        
        result = await mcp_server.get_transaction_history(
            filters=filters,
            user_id=g.current_user_id,
            org_id=g.current_org_id
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'count': len(result),
            'message': 'Transaction history retrieved successfully'
        })
        
    except Exception as e:
        logger.error(f"Transaction history query failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/tools/reports/generate', methods=['POST'])
@require_auth
async def generate_report():
    """Automated Reports Tool with Organization Isolation"""
    try:
        data = request.get_json()
        report_type = data.get('report_type', 'DAILY')
        date_from = data.get('date_from')
        date_to = data.get('date_to')
        
        if not date_from or not date_to:
            return jsonify({'error': 'date_from and date_to are required'}), 400
        
        # Generate organization-specific report data
        async with mcp_server.db_pool.acquire() as conn:
            # Transaction summary for this organization
            transaction_summary = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_transactions,
                    SUM(CASE WHEN status = 'SUCCESS' THEN amount ELSE 0 END) as successful_amount,
                    SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as successful_count,
                    SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
                    SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) as pending_count
                FROM transactions 
                WHERE organization_id = $1 AND created_at BETWEEN $2 AND $3
            """, g.current_org_id, date_from, date_to)
            
            # Transaction by type for this organization
            transactions_by_type = await conn.fetch("""
                SELECT transaction_type, COUNT(*) as count, SUM(amount) as total_amount
                FROM transactions 
                WHERE organization_id = $1 AND created_at BETWEEN $2 AND $3 AND status = 'SUCCESS'
                GROUP BY transaction_type
            """, g.current_org_id, date_from, date_to)
            
            # Daily breakdown for this organization
            daily_breakdown = await conn.fetch("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as transaction_count,
                    SUM(CASE WHEN status = 'SUCCESS' THEN amount ELSE 0 END) as daily_amount
                FROM transactions 
                WHERE organization_id = $1 AND created_at BETWEEN $2 AND $3
                GROUP BY DATE(created_at)
                ORDER BY date
            """, g.current_org_id, date_from, date_to)
            
            # Bulk payment summary for this organization
            bulk_summary = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_batches,
                    SUM(total_amount) as total_bulk_amount,
                    SUM(total_recipients) as total_recipients
                FROM bulk_payments
                WHERE organization_id = $1 AND created_at BETWEEN $2 AND $3
            """, g.current_org_id, date_from, date_to)
        
        report_data = {
            'organization_id': g.current_org_id,
            'summary': dict(transaction_summary),
            'by_type': [dict(row) for row in transactions_by_type],
            'daily_breakdown': [dict(row) for row in daily_breakdown],
            'bulk_payments': dict(bulk_summary),
            'generated_at': datetime.now().isoformat(),
            'period': f"{date_from} to {date_to}",
            'report_type': report_type
        }
        
        # Store report with organization context
        async with mcp_server.db_pool.acquire() as conn:
            report_id = await conn.fetchval("""
                INSERT INTO reports (organization_id, report_type, report_name, date_from, date_to, 
                                   report_data, generated_by, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id
            """, g.current_org_id, report_type, f"{report_type} Report", date_from, date_to,
                json.dumps(report_data), g.current_user_id, 
                datetime.now() + timedelta(days=30))
        
        await mcp_server.log_audit(g.current_user_id, g.current_org_id, 'REPORT_GENERATED', 'generate_report',
                                 data, {'report_id': str(report_id)}, 'SUCCESS',
                                 request.environ.get('REMOTE_ADDR'),
                                 request.headers.get('User-Agent'))
        
        return jsonify({
            'success': True,
            'data': report_data,
            'report_id': str(report_id),
            'message': 'Report generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return jsonify({'error': str(e)}), 500

# Organization-Specific Callback Endpoints
@app.route('/mpesa/callback/<org_id>', methods=['POST'])
async def mpesa_callback(org_id):
    """Handle M-Pesa STK Push callbacks for specific organization"""
    try:
        data = request.get_json()
        
        # Extract callback data
        callback_metadata = data.get('Body', {}).get('stkCallback', {})
        merchant_request_id = callback_metadata.get('MerchantRequestID')
        checkout_request_id = callback_metadata.get('CheckoutRequestID')
        result_code = callback_metadata.get('ResultCode')
        result_desc = callback_metadata.get('ResultDesc')
        
        # Extract metadata if transaction was successful
        mpesa_receipt_number = None
        if result_code == 0 and callback_metadata.get('CallbackMetadata'):
            for item in callback_metadata['CallbackMetadata']['Item']:
                if item['Name'] == 'MpesaReceiptNumber':
                    mpesa_receipt_number = item['Value']
                    break
        
        # Update transaction in database (organization-scoped)
        status = 'SUCCESS' if result_code == 0 else 'FAILED'
        
        async with mcp_server.db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE transactions 
                SET status = $1, result_code = $2, result_desc = $3, 
                    mpesa_receipt_number = $4, callback_data = $5, updated_at = NOW()
                WHERE checkout_request_id = $6 AND organization_id = $7
            """, status, result_code, result_desc, mpesa_receipt_number,
                json.dumps(data), checkout_request_id, org_id)
        
        logger.info(f"Callback processed for org {org_id}, CheckoutRequestID: {checkout_request_id}")
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Callback processing failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@app.route('/mpesa/balance/result/<org_id>', methods=['POST'])
async def balance_result_callback(org_id):
    """Handle balance check result callbacks for specific organization"""
    try:
        data = request.get_json()
        
        # Extract balance information
        result_data = data.get('Result', {})
        result_code = result_data.get('ResultCode')
        
        if result_code == 0:
            # Extract balance from result parameters
            balance_info = {}
            for param in result_data.get('ResultParameters', {}).get('ResultParameter', []):
                balance_info[param['Key']] = param['Value']
            
            # Store balance log with organization context
            async with mcp_server.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO balance_logs (organization_id, account_type, balance, checked_at)
                    VALUES ($1, $2, $3, NOW())
                """, org_id, 'PAYBILL', balance_info.get('AccountBalance', 0))
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Balance callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@app.route('/mpesa/b2c/result/<org_id>', methods=['POST'])
async def b2c_result_callback(org_id):
    """Handle B2C payment result callbacks for specific organization"""
    try:
        data = request.get_json()
        
        # Process B2C result
        result_data = data.get('Result', {})
        result_code = result_data.get('ResultCode')
        result_desc = result_data.get('ResultDesc')
        
        # Extract transaction details
        conversation_id = result_data.get('ConversationID')
        
        # Update bulk payment item status (organization-scoped)
        status = 'SUCCESS' if result_code == 0 else 'FAILED'
        
        async with mcp_server.db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE bulk_payment_items 
                SET status = $1, result_code = $2, result_desc = $3, updated_at = NOW()
                WHERE id IN (
                    SELECT bpi.id FROM bulk_payment_items bpi
                    JOIN bulk_payments bp ON bpi.bulk_payment_id = bp.id
                    WHERE bp.organization_id = $4 AND bpi.status = 'PENDING'
                    LIMIT 1
                )
            """, status, result_code, result_desc, org_id)
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"B2C callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

# Health check and management endpoints
@app.route('/health', methods=['GET'])
async def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        async with mcp_server.db_pool.acquire() as conn:
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

@app.route('/admin/organizations', methods=['GET'])
@require_auth
async def list_organizations():
    """List all organizations (super admin only)"""
    if g.current_user_role != 'super_admin':
        return jsonify({'error': 'Super admin access required'}), 403
    
    try:
        async with mcp_server.db_pool.acquire() as conn:
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
            
            return jsonify({
                'success': True,
                'data': [dict(org) for org in orgs]
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/users', methods=['GET'])
@require_auth
@require_org_admin
async def list_users():
    """List users in organization"""
    try:
        org_filter = g.current_org_id if g.current_user_role != 'super_admin' else None
        
        async with mcp_server.db_pool.acquire() as conn:
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
            
            return jsonify({
                'success': True,
                'data': [dict(user) for user in users]
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/audit-logs', methods=['GET'])
@require_auth
@require_org_admin
async def audit_logs():
    """View audit logs (scoped to organization for org admins)"""
    try:
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        org_filter = g.current_org_id if g.current_user_role != 'super_admin' else None
        
        async with mcp_server.db_pool.acquire() as conn:
            query = """
                SELECT a.*, u.username, o.name as organization_name
                FROM audit_logs a
                LEFT JOIN users u ON a.user_id = u.id
                LEFT JOIN organizations o ON a.organization_id = o.id
            """
            params = []
            param_count = 0
            
            if org_filter:
                param_count += 1
                query += f" WHERE a.organization_id = ${param_count}"
                params.append(org_filter)
            
            query += " ORDER BY a.created_at DESC"
            
            param_count += 1
            query += f" LIMIT ${param_count}"
            params.append(limit)
            
            param_count += 1
            query += f" OFFSET ${param_count}"
            params.append(offset)
            
            logs = await conn.fetch(query, *params)
            
            return jsonify({
                'success': True,
                'data': [dict(log) for log in logs]
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/usage-stats', methods=['GET'])
@require_auth
@require_org_admin
async def usage_stats():
    """Get organization usage statistics"""
    try:
        org_filter = g.current_org_id if g.current_user_role != 'super_admin' else request.args.get('org_id')
        
        if not org_filter:
            return jsonify({'error': 'Organization ID required'}), 400
        
        async with mcp_server.db_pool.acquire() as conn:
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
            """, org_filter, current_month_start)
            
            # Get rate limit info
            rate_limit_info = await conn.fetchrow("""
                SELECT api_rate_limit, subscription_plan, subscription_status
                FROM organizations WHERE id = $1
            """, org_filter)
            
            return jsonify({
                'success': True,
                'data': {
                    'usage': dict(usage_stats) if usage_stats else {},
                    'limits': dict(rate_limit_info) if rate_limit_info else {},
                    'period': current_month_start.isoformat()
                }
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Run the Flask app
    app.run(
        host=os.getenv('FLASK_HOST', '0.0.0.0'),
        port=int(os.getenv('FLASK_PORT', 5000)),
        debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    )
