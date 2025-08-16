async def stk_push_payment(self, phone_number: str, amount: float, 
                              account_reference: str, transaction_desc: str,
                              user_id: str, org_id: str) -> Dict:
        """Tool: STK Push Payment Initiator"""
        try:
            config = await self.get_org_config(org_id)
            access_token = await self.get_access_token(org_id)
            
            # Generate timestamp and password
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            password_string = f"{config['business_short_code']}{config['lipa_import os
import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from decimal import Decimal
import hashlib
import hmac
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
    def __init__(self, supabase_url: str, supabase_key: str):
        self.supabase_url = supabase_url
        self.supabase_key = supabase_key
        self.db_pool = None
        
        # Default/Fallback Daraja API Configuration (can be overridden per org)
        self.default_consumer_key = os.getenv('MPESA_CONSUMER_KEY')
        self.default_consumer_secret = os.getenv('MPESA_CONSUMER_SECRET')
        self.default_business_short_code = os.getenv('MPESA_BUSINESS_SHORT_CODE')
        self.default_lipa_na_mpesa_passkey = os.getenv('MPESA_LIPA_NA_MPESA_PASSKEY')
        self.default_base_url = os.getenv('MPESA_BASE_URL', 'https://sandbox.safaricom.co.ke')
        
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
                
                config = {
                    'consumer_key': org['mpesa_consumer_key'] or self.default_consumer_key,
                    'consumer_secret': org['mpesa_consumer_secret'] or self.default_consumer_secret,
                    'business_short_code': org['mpesa_business_short_code'] or self.default_business_short_code,
                    'lipa_na_mpesa_passkey': org['mpesa_lipa_na_mpesa_passkey'] or self.default_lipa_na_mpesa_passkey,
                    'base_url': org['mpesa_base_url'] or self.default_base_url,
                    'initiator_name': org['mpesa_initiator_name'],
                    'security_credential': org['mpesa_security_credential'],
                    'callback_base_url': org['callback_base_url'] or os.getenv('CALLBACK_BASE_URL')
                }
                
                self.org_configs[org_id] = config
                return config
                
        except Exception as e:
            logger.error(f"Failed to get org config: {e}")
            raise

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
            headers = {
                'Authorization': f'Basic {httpx._utils.to_bytes(credentials).decode()}',
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
        """Log audit trail"""
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
                              user_id: str) -> Dict:
        """Tool: STK Push Payment Initiator"""
        try:
            access_token = await self.get_access_token()
            
            # Generate timestamp and password
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            password_string = f"{self.business_short_code}{self.lipa_na_mpesa_passkey}{timestamp}"
            password = hashlib.sha256(password_string.encode()).hexdigest()
            
            url = f"{self.base_url}/mpesa/stkpush/v1/processrequest"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'BusinessShortCode': self.business_short_code,
                'Password': password,
                'Timestamp': timestamp,
                'TransactionType': 'CustomerPayBillOnline',
                'Amount': int(amount),
                'PartyA': phone_number,
                'PartyB': self.business_short_code,
                'PhoneNumber': phone_number,
                'CallBackURL': f"{os.getenv('CALLBACK_BASE_URL')}/mpesa/callback",
                'AccountReference': account_reference,
                'TransactionDesc': transaction_desc
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers)
                result = response.json()
                
                # Store transaction in database
                async with self.db_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO transactions (merchant_request_id, checkout_request_id,
                                                transaction_type, amount, phone_number,
                                                account_reference, transaction_desc, initiated_by)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    """, result.get('MerchantRequestID'), result.get('CheckoutRequestID'),
                         'STK_PUSH', Decimal(str(amount)), phone_number, 
                         account_reference, transaction_desc, user_id)
                
                await self.log_audit(user_id, 'STK_PUSH_INITIATED', 'stk_push_payment',
                                   payload, result, 'SUCCESS')
                
                return result
                
        except Exception as e:
            logger.error(f"STK Push failed: {e}")
            await self.log_audit(user_id, 'STK_PUSH_INITIATED', 'stk_push_payment',
                               payload if 'payload' in locals() else {}, {'error': str(e)}, 'FAILED')
            raise

    async def check_transaction_status(self, checkout_request_id: str, user_id: str) -> Dict:
        """Tool: Transaction Status Tracker"""
        try:
            access_token = await self.get_access_token()
            
            # Generate timestamp and password
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            password_string = f"{self.business_short_code}{self.lipa_na_mpesa_passkey}{timestamp}"
            password = hashlib.sha256(password_string.encode()).hexdigest()
            
            url = f"{self.base_url}/mpesa/stkpushquery/v1/query"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'BusinessShortCode': self.business_short_code,
                'Password': password,
                'Timestamp': timestamp,
                'CheckoutRequestID': checkout_request_id
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers)
                result = response.json()
                
                # Update transaction status in database
                async with self.db_pool.acquire() as conn:
                    await conn.execute("""
                        UPDATE transactions SET status = $1, result_code = $2, 
                                              result_desc = $3, updated_at = NOW()
                        WHERE checkout_request_id = $4
                    """, result.get('ResultDesc', 'PENDING'), 
                         result.get('ResultCode'), result.get('ResultDesc'), checkout_request_id)
                
                await self.log_audit(user_id, 'TRANSACTION_STATUS_CHECK', 'check_transaction_status',
                                   payload, result, 'SUCCESS')
                
                return result
                
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            await self.log_audit(user_id, 'TRANSACTION_STATUS_CHECK', 'check_transaction_status',
                               payload if 'payload' in locals() else {}, {'error': str(e)}, 'FAILED')
            raise

    async def get_account_balance(self, user_id: str) -> Dict:
        """Tool: Account Balance Checker"""
        try:
            access_token = await self.get_access_token()
            
            url = f"{self.base_url}/mpesa/accountbalance/v1/query"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'Initiator': os.getenv('MPESA_INITIATOR_NAME'),
                'SecurityCredential': os.getenv('MPESA_SECURITY_CREDENTIAL'),
                'CommandID': 'AccountBalance',
                'PartyA': self.business_short_code,
                'IdentifierType': '4',
                'ResultURL': f"{os.getenv('CALLBACK_BASE_URL')}/mpesa/balance/result",
                'QueueTimeOutURL': f"{os.getenv('CALLBACK_BASE_URL')}/mpesa/balance/timeout",
                'Remarks': 'Account balance check'
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers)
                result = response.json()
                
                await self.log_audit(user_id, 'BALANCE_CHECK', 'get_account_balance',
                                   payload, result, 'SUCCESS')
                
                return result
                
        except Exception as e:
            logger.error(f"Balance check failed: {e}")
            await self.log_audit(user_id, 'BALANCE_CHECK', 'get_account_balance',
                               payload if 'payload' in locals() else {}, {'error': str(e)}, 'FAILED')
            raise

    async def bulk_payment(self, payments: List[Dict], batch_name: str, user_id: str) -> Dict:
        """Tool: Bulk Payment Processor"""
        try:
            access_token = await self.get_access_token()
            batch_id = f"BATCH_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            total_amount = sum(payment['amount'] for payment in payments)
            
            # Store bulk payment record
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO bulk_payments (batch_id, batch_name, total_amount, 
                                             total_recipients, initiated_by, status)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """, batch_id, batch_name, Decimal(str(total_amount)), 
                     len(payments), user_id, 'PROCESSING')
                
                bulk_payment_id = await conn.fetchval("""
                    SELECT id FROM bulk_payments WHERE batch_id = $1
                """, batch_id)
            
            results = []
            
            for payment in payments:
                try:
                    url = f"{self.base_url}/mpesa/b2c/v1/paymentrequest"
                    headers = {
                        'Authorization': f'Bearer {access_token}',
                        'Content-Type': 'application/json'
                    }
                    
                    payload = {
                        'InitiatorName': os.getenv('MPESA_INITIATOR_NAME'),
                        'SecurityCredential': os.getenv('MPESA_SECURITY_CREDENTIAL'),
                        'CommandID': 'BusinessPayment',
                        'Amount': int(payment['amount']),
                        'PartyA': self.business_short_code,
                        'PartyB': payment['phone_number'],
                        'Remarks': payment.get('remarks', 'Bulk payment'),
                        'QueueTimeOutURL': f"{os.getenv('CALLBACK_BASE_URL')}/mpesa/b2c/timeout",
                        'ResultURL': f"{os.getenv('CALLBACK_BASE_URL')}/mpesa/b2c/result",
                        'Occasion': payment.get('occasion', batch_name)
                    }
                    
                    async with httpx.AsyncClient() as client:
                        response = await client.post(url, json=payload, headers=headers)
                        result = response.json()
                        
                        # Store individual payment
                        async with self.db_pool.acquire() as conn:
                            await conn.execute("""
                                INSERT INTO bulk_payment_items (bulk_payment_id, phone_number, 
                                                               amount, account_reference, remarks)
                                VALUES ($1, $2, $3, $4, $5)
                            """, bulk_payment_id, payment['phone_number'], 
                                 Decimal(str(payment['amount'])), 
                                 payment.get('account_reference'), payment.get('remarks'))
                        
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
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE bulk_payments SET status = 'COMPLETED', completed_at = NOW()
                    WHERE batch_id = $1
                """, batch_id)
            
            final_result = {
                'batch_id': batch_id,
                'total_payments': len(payments),
                'total_amount': total_amount,
                'results': results
            }
            
            await self.log_audit(user_id, 'BULK_PAYMENT', 'bulk_payment',
                               {'batch_name': batch_name, 'payments': payments}, 
                               final_result, 'SUCCESS')
            
            return final_result
            
        except Exception as e:
            logger.error(f"Bulk payment failed: {e}")
            await self.log_audit(user_id, 'BULK_PAYMENT', 'bulk_payment',
                               {'batch_name': batch_name} if 'batch_name' in locals() else {}, 
                               {'error': str(e)}, 'FAILED')
            raise

    async def reverse_transaction(self, transaction_id: str, amount: float, 
                                reason: str, user_id: str) -> Dict:
        """Tool: Transaction Reversal"""
        try:
            access_token = await self.get_access_token()
            
            url = f"{self.base_url}/mpesa/reversal/v1/request"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'Initiator': os.getenv('MPESA_INITIATOR_NAME'),
                'SecurityCredential': os.getenv('MPESA_SECURITY_CREDENTIAL'),
                'CommandID': 'TransactionReversal',
                'TransactionID': transaction_id,
                'Amount': int(amount),
                'ReceiverParty': self.business_short_code,
                'RecieverIdentifierType': '11',
                'ResultURL': f"{os.getenv('CALLBACK_BASE_URL')}/mpesa/reversal/result",
                'QueueTimeOutURL': f"{os.getenv('CALLBACK_BASE_URL')}/mpesa/reversal/timeout",
                'Remarks': reason,
                'Occasion': 'Transaction reversal'
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, headers=headers)
                result = response.json()
                
                # Store reversal record
                async with self.db_pool.acquire() as conn:
                    original_transaction = await conn.fetchrow("""
                        SELECT id FROM transactions WHERE transaction_id = $1
                    """, transaction_id)
                    
                    if original_transaction:
                        await conn.execute("""
                            INSERT INTO reversals (original_transaction_id, amount, 
                                                 reason, initiated_by, status)
                            VALUES ($1, $2, $3, $4, $5)
                        """, original_transaction['id'], Decimal(str(amount)), 
                             reason, user_id, 'PENDING')
                
                await self.log_audit(user_id, 'TRANSACTION_REVERSAL', 'reverse_transaction',
                                   payload, result, 'SUCCESS')
                
                return result
                
        except Exception as e:
            logger.error(f"Transaction reversal failed: {e}")
            await self.log_audit(user_id, 'TRANSACTION_REVERSAL', 'reverse_transaction',
                               payload if 'payload' in locals() else {}, {'error': str(e)}, 'FAILED')
            raise

    async def get_transaction_history(self, filters: Dict, user_id: str) -> List[Dict]:
        """Tool: Payment Reconciliation Dashboard"""
        try:
            query = """
                SELECT t.*, u.username as initiated_by_username
                FROM transactions t
                LEFT JOIN users u ON t.initiated_by = u.id
                WHERE 1=1
            """
            params = []
            param_count = 0
            
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
                
                await self.log_audit(user_id, 'TRANSACTION_HISTORY_QUERY', 'get_transaction_history',
                                   filters, {'count': len(result)}, 'SUCCESS')
                
                return result
                
        except Exception as e:
            logger.error(f"Transaction history query failed: {e}")
            await self.log_audit(user_id, 'TRANSACTION_HISTORY_QUERY', 'get_transaction_history',
                               filters, {'error': str(e)}, 'FAILED')
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
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'No authorization token provided'}), 401
        
        try:
            token = token.split(' ')[1]
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user_id = payload['user_id']
            g.current_user_role = payload.get('role', 'user')
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

@app.before_first_request
async def init_app():
    """Initialize the application"""
    await mcp_server.init_db()

# Authentication endpoints
@app.route('/auth/login', methods=['POST'])
async def login():
    """User authentication"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    try:
        async with mcp_server.db_pool.acquire() as conn:
            user = await conn.fetchrow("""
                SELECT id, username, email, password_hash, role, permissions, is_active
                FROM users WHERE username = $1 AND is_active = true
            """, username)
            
            if not user or not check_password_hash(user['password_hash'], password):
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Generate JWT token
            token_payload = {
                'user_id': str(user['id']),
                'username': user['username'],
                'role': user['role'],
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
                    'permissions': user['permissions']
                }
            })
            
    except Exception as e:
        logger.error(f"Login failed: {e}")
        return jsonify({'error': 'Login failed'}), 500

# MCP Server Tool Endpoints

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
            user_id=g.current_user_id
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
            user_id=g.current_user_id
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
        result = await mcp_server.get_account_balance(user_id=g.current_user_id)
        
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
            user_id=g.current_user_id
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
            user_id=g.current_user_id
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
            user_id=g.current_user_id
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
    """Automated Reports Tool"""
    try:
        data = request.get_json()
        report_type = data.get('report_type', 'DAILY')
        date_from = data.get('date_from')
        date_to = data.get('date_to')
        
        if not date_from or not date_to:
            return jsonify({'error': 'date_from and date_to are required'}), 400
        
        # Generate report data
        async with mcp_server.db_pool.acquire() as conn:
            # Transaction summary
            transaction_summary = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_transactions,
                    SUM(CASE WHEN status = 'SUCCESS' THEN amount ELSE 0 END) as successful_amount,
                    SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) as successful_count,
                    SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_count,
                    SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) as pending_count
                FROM transactions 
                WHERE created_at BETWEEN $1 AND $2
            """, date_from, date_to)
            
            # Transaction by type
            transactions_by_type = await conn.fetch("""
                SELECT transaction_type, COUNT(*) as count, SUM(amount) as total_amount
                FROM transactions 
                WHERE created_at BETWEEN $1 AND $2 AND status = 'SUCCESS'
                GROUP BY transaction_type
            """, date_from, date_to)
            
            # Daily breakdown
            daily_breakdown = await conn.fetch("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as transaction_count,
                    SUM(CASE WHEN status = 'SUCCESS' THEN amount ELSE 0 END) as daily_amount
                FROM transactions 
                WHERE created_at BETWEEN $1 AND $2
                GROUP BY DATE(created_at)
                ORDER BY date
            """, date_from, date_to)
        
        report_data = {
            'summary': dict(transaction_summary),
            'by_type': [dict(row) for row in transactions_by_type],
            'daily_breakdown': [dict(row) for row in daily_breakdown],
            'generated_at': datetime.now().isoformat(),
            'period': f"{date_from} to {date_to}"
        }
        
        # Store report
        async with mcp_server.db_pool.acquire() as conn:
            report_id = await conn.fetchval("""
                INSERT INTO reports (report_type, report_name, date_from, date_to, 
                                   report_data, generated_by, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id
            """, report_type, f"{report_type} Report", date_from, date_to,
                json.dumps(report_data), g.current_user_id, 
                datetime.now() + timedelta(days=30))
        
        await mcp_server.log_audit(g.current_user_id, 'REPORT_GENERATED', 'generate_report',
                                 data, {'report_id': str(report_id)}, 'SUCCESS')
        
        return jsonify({
            'success': True,
            'data': report_data,
            'report_id': str(report_id),
            'message': 'Report generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        return jsonify({'error': str(e)}), 500

# Callback endpoints for M-Pesa webhooks
@app.route('/mpesa/callback', methods=['POST'])
async def mpesa_callback():
    """Handle M-Pesa STK Push callbacks"""
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
        
        # Update transaction in database
        status = 'SUCCESS' if result_code == 0 else 'FAILED'
        
        async with mcp_server.db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE transactions 
                SET status = $1, result_code = $2, result_desc = $3, 
                    mpesa_receipt_number = $4, callback_data = $5, updated_at = NOW()
                WHERE checkout_request_id = $6
            """, status, result_code, result_desc, mpesa_receipt_number,
                json.dumps(data), checkout_request_id)
        
        logger.info(f"Callback processed for CheckoutRequestID: {checkout_request_id}")
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Callback processing failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@app.route('/mpesa/balance/result', methods=['POST'])
async def balance_result_callback():
    """Handle balance check result callbacks"""
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
            
            # Store balance log
            async with mcp_server.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO balance_logs (account_type, balance, checked_at)
                    VALUES ($1, $2, NOW())
                """, 'PAYBILL', balance_info.get('AccountBalance', 0))
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Balance callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@app.route('/mpesa/b2c/result', methods=['POST'])
async def b2c_result_callback():
    """Handle B2C payment result callbacks"""
    try:
        data = request.get_json()
        
        # Process B2C result
        result_data = data.get('Result', {})
        result_code = result_data.get('ResultCode')
        result_desc = result_data.get('ResultDesc')
        
        # Extract transaction details
        conversation_id = result_data.get('ConversationID')
        
        # Update bulk payment item status
        status = 'SUCCESS' if result_code == 0 else 'FAILED'
        
        async with mcp_server.db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE bulk_payment_items 
                SET status = $1, result_code = $2, result_desc = $3, updated_at = NOW()
                WHERE id = (
                    SELECT id FROM bulk_payment_items 
                    WHERE status = 'PENDING' 
                    LIMIT 1
                )
            """, status, result_code, result_desc)
        
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
        
        # Check M-Pesa API token
        await mcp_server.get_access_token()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'services': {
                'database': 'connected',
                'mpesa_api': 'authenticated'
            }
        })
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/admin/users', methods=['GET'])
@require_auth
async def list_users():
    """List all users (admin only)"""
    if g.current_user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        async with mcp_server.db_pool.acquire() as conn:
            users = await conn.fetch("""
                SELECT id, username, email, role, permissions, is_active, created_at
                FROM users ORDER BY created_at DESC
            """)
            
            return jsonify({
                'success': True,
                'data': [dict(user) for user in users]
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/audit-logs', methods=['GET'])
@require_auth
async def audit_logs():
    """View audit logs (admin only)"""
    if g.current_user_role != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        async with mcp_server.db_pool.acquire() as conn:
            logs = await conn.fetch("""
                SELECT a.*, u.username
                FROM audit_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.created_at DESC
                LIMIT $1 OFFSET $2
            """, limit, offset)
            
            return jsonify({
                'success': True,
                'data': [dict(log) for log in logs]
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
