import json
import logging
from flask import Blueprint, request, jsonify

from models.transaction import TransactionModel

logger = logging.getLogger(__name__)

callback_bp = Blueprint('callback', __name__)

@callback_bp.route('/callback/<org_id>', methods=['POST'])
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
        
        await TransactionModel.update_transaction_status(
            checkout_request_id, org_id, status, result_code, result_desc,
            mpesa_receipt_number, data
        )
        
        logger.info(f"Callback processed for org {org_id}, CheckoutRequestID: {checkout_request_id}")
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Callback processing failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@callback_bp.route('/balance/result/<org_id>', methods=['POST'])
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
            await TransactionModel.create_balance_log(
                org_id, 'PAYBILL', balance_info.get('AccountBalance', 0)
            )
        
        logger.info(f"Balance callback processed for org {org_id}")
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Balance callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@callback_bp.route('/balance/timeout/<org_id>', methods=['POST'])
async def balance_timeout_callback(org_id):
    """Handle balance check timeout callbacks for specific organization"""
    try:
        data = request.get_json()
        logger.warning(f"Balance check timeout for org {org_id}: {data}")
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Balance timeout callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@callback_bp.route('/b2c/result/<org_id>', methods=['POST'])
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
        
        await TransactionModel.update_bulk_payment_item_status(
            org_id, status, result_code, result_desc
        )
        
        logger.info(f"B2C callback processed for org {org_id}, ConversationID: {conversation_id}")
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"B2C callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@callback_bp.route('/b2c/timeout/<org_id>', methods=['POST'])
async def b2c_timeout_callback(org_id):
    """Handle B2C payment timeout callbacks for specific organization"""
    try:
        data = request.get_json()
        logger.warning(f"B2C payment timeout for org {org_id}: {data}")
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"B2C timeout callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@callback_bp.route('/reversal/result/<org_id>', methods=['POST'])
async def reversal_result_callback(org_id):
    """Handle transaction reversal result callbacks for specific organization"""
    try:
        data = request.get_json()
        
        # Process reversal result
        result_data = data.get('Result', {})
        result_code = result_data.get('ResultCode')
        result_desc = result_data.get('ResultDesc')
        conversation_id = result_data.get('ConversationID')
        
        # TODO: Update reversal status in database based on conversation_id
        # This would require tracking conversation_id when initiating reversals
        
        logger.info(f"Reversal callback processed for org {org_id}, "
                   f"ConversationID: {conversation_id}, Result: {result_code}")
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Reversal callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@callback_bp.route('/reversal/timeout/<org_id>', methods=['POST'])
async def reversal_timeout_callback(org_id):
    """Handle transaction reversal timeout callbacks for specific organization"""
    try:
        data = request.get_json()
        logger.warning(f"Transaction reversal timeout for org {org_id}: {data}")
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Reversal timeout callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@callback_bp.route('/webhook/<org_id>', methods=['POST'])
async def generic_webhook(org_id):
    """Generic webhook handler for any M-Pesa callbacks"""
    try:
        data = request.get_json()
        
        # Log all webhook data for debugging
        logger.info(f"Generic webhook received for org {org_id}: {json.dumps(data, indent=2)}")
        
        # You can add specific processing logic here based on the callback type
        # or route to appropriate handlers based on callback content
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Generic webhook failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@callback_bp.route('/confirmation/<org_id>', methods=['POST'])
async def confirmation_callback(org_id):
    """Handle M-Pesa confirmation callbacks"""
    try:
        data = request.get_json()
        
        # Extract confirmation data
        transaction_type = data.get('TransactionType')
        trans_id = data.get('TransID')
        trans_time = data.get('TransTime')
        trans_amount = data.get('TransAmount')
        business_short_code = data.get('BusinessShortCode')
        bill_ref_number = data.get('BillRefNumber')
        invoice_number = data.get('InvoiceNumber')
        org_account_balance = data.get('OrgAccountBalance')
        third_party_trans_id = data.get('ThirdPartyTransID')
        msisdn = data.get('MSISDN')
        first_name = data.get('FirstName')
        middle_name = data.get('MiddleName')
        last_name = data.get('LastName')
        
        # Log confirmation for audit
        logger.info(f"Confirmation received for org {org_id}: TransID {trans_id}, "
                   f"Amount {trans_amount}, MSISDN {msisdn}")
        
        # TODO: Process confirmation and update relevant records
        # This could involve updating transaction status, triggering notifications, etc.
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'})
        
    except Exception as e:
        logger.error(f"Confirmation callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@callback_bp.route('/validation/<org_id>', methods=['POST'])
async def validation_callback(org_id):
    """Handle M-Pesa validation callbacks"""
    try:
        data = request.get_json()
        
        # Extract validation data
        transaction_type = data.get('TransactionType')
        trans_id = data.get('TransID')
        trans_time = data.get('TransTime')
        trans_amount = data.get('TransAmount')
        business_short_code = data.get('BusinessShortCode')
        bill_ref_number = data.get('BillRefNumber')
        invoice_number = data.get('InvoiceNumber')
        org_account_balance = data.get('OrgAccountBalance')
        third_party_trans_id = data.get('ThirdPartyTransID')
        msisdn = data.get('MSISDN')
        first_name = data.get('FirstName')
        middle_name = data.get('MiddleName')
        last_name = data.get('LastName')
        
        # Log validation request
        logger.info(f"Validation request for org {org_id}: TransID {trans_id}, "
                   f"Amount {trans_amount}, MSISDN {msisdn}")
        
        # TODO: Add validation logic here
        # You can validate the transaction based on business rules
        # Return ResultCode 0 to accept, non-zero to reject
        
        # For now, accept all transactions
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Accepted'})
        
    except Exception as e:
        logger.error(f"Validation callback failed: {e}")
        return jsonify({'ResultCode': 1, 'ResultDesc': 'Failed'})

@callback_bp.route('/status', methods=['GET'])
async def callback_status():
    """Callback service status endpoint"""
    try:
        from datetime import datetime
        
        return jsonify({
            'status': 'healthy',
            'service': 'M-Pesa Callback Handler',
            'timestamp': datetime.now().isoformat(),
            'endpoints': [
                '/callback/<org_id>',
                '/balance/result/<org_id>',
                '/balance/timeout/<org_id>',
                '/b2c/result/<org_id>',
                '/b2c/timeout/<org_id>',
                '/reversal/result/<org_id>',
                '/reversal/timeout/<org_id>',
                '/webhook/<org_id>',
                '/confirmation/<org_id>',
                '/validation/<org_id>'
            ]
        })
        
    except Exception as e:
        logger.error(f"Callback status check failed: {e}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500
