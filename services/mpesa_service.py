import base64
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from decimal import Decimal
import httpx

from models.organization import OrganizationModel
from models.transaction import TransactionModel

logger = logging.getLogger(__name__)

class MPesaService:
    """M-Pesa API integration service"""
    
    def __init__(self):
        # Cache for organization tokens
        self.org_tokens = {}

    async def get_access_token(self, org_id: str) -> str:
        """Get or refresh Daraja API access token for specific organization"""
        token_key = f"{org_id}_token"
        expires_key = f"{org_id}_expires"
        
        if (token_key in self.org_tokens and expires_key in self.org_tokens and 
            datetime.now() < self.org_tokens[expires_key]):
            return self.org_tokens[token_key]
            
        try:
            config = await OrganizationModel.get_org_config(org_id)
            
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
                await OrganizationModel.store_api_token(org_id, access_token, expires_at)
                
                return access_token
                
        except Exception as e:
            logger.error(f"Failed to get access token for org {org_id}: {e}")
            raise

    async def stk_push_payment(self, phone_number: str, amount: float, 
                              account_reference: str, transaction_desc: str,
                              user_id: str, org_id: str) -> Dict:
        """Tool: STK Push Payment Initiator"""
        try:
            # Check rate limits
            if not await OrganizationModel.check_rate_limit(org_id):
                raise Exception("Rate limit exceeded for organization")
            
            config = await OrganizationModel.get_org_config(org_id)
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
                await TransactionModel.create_stk_transaction(
                    org_id, result.get('MerchantRequestID'), result.get('CheckoutRequestID'),
                    amount, phone_number, account_reference, transaction_desc, user_id
                )
                
                return result
                
        except Exception as e:
            logger.error(f"STK Push failed: {e}")
            raise

    async def check_transaction_status(self, checkout_request_id: str, user_id: str, org_id: str) -> Dict:
        """Tool: Transaction Status Tracker"""
        try:
            config = await OrganizationModel.get_org_config(org_id)
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
                
                # Update transaction status in database
                await TransactionModel.update_transaction_query_status(
                    checkout_request_id, org_id, result.get('ResultDesc', 'PENDING'), 
                    result.get('ResultCode')
                )
                
                return result
                
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            raise

    async def get_account_balance(self, user_id: str, org_id: str, account_type: str = 'PAYBILL') -> Dict:
        """Tool: Account Balance Checker"""
        try:
            config = await OrganizationModel.get_org_config(org_id)
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
                
                return result
                
        except Exception as e:
            logger.error(f"Balance check failed: {e}")
            raise

    async def bulk_payment(self, payments: List[Dict], batch_name: str, user_id: str, org_id: str) -> Dict:
        """Tool: Bulk Payment Processor"""
        try:
            # Check rate limits for bulk operations
            if not await OrganizationModel.check_rate_limit(org_id):
                raise Exception("Rate limit exceeded for organization")
            
            config = await OrganizationModel.get_org_config(org_id)
            access_token = await self.get_access_token(org_id)
            batch_id = f"BATCH_{config['organization_slug']}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            total_amount = sum(payment['amount'] for payment in payments)
            
            # Store bulk payment record with organization context
            bulk_payment_id = await TransactionModel.create_bulk_payment(
                org_id, batch_id, batch_name, total_amount, len(payments), user_id
            )
            
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
                        
                        # Store individual payment
                        await TransactionModel.create_bulk_payment_item(
                            bulk_payment_id, payment['phone_number'], payment['amount'],
                            payment.get('account_reference'), payment.get('remarks')
                        )
                        
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
            await TransactionModel.update_bulk_payment_status(bulk_payment_id, org_id, status)
            
            final_result = {
                'batch_id': batch_id,
                'organization_id': org_id,
                'total_payments': len(payments),
                'successful_payments': success_count,
                'total_amount': total_amount,
                'results': results
            }
            
            return final_result
            
        except Exception as e:
            logger.error(f"Bulk payment failed: {e}")
            raise

    async def reverse_transaction(self, transaction_id: str, amount: float, 
                                reason: str, user_id: str, org_id: str) -> Dict:
        """Tool: Transaction Reversal"""
        try:
            config = await OrganizationModel.get_org_config(org_id)
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
                original_transaction = await TransactionModel.get_original_transaction(transaction_id, org_id)
                if original_transaction:
                    await TransactionModel.create_reversal(
                        original_transaction['id'], amount, reason, user_id
                    )
                
                return result
                
        except Exception as e:
            logger.error(f"Transaction reversal failed: {e}")
            raise
