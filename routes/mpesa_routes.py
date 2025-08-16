import logging
from flask import Blueprint, request, jsonify, g

from services.mpesa_service import MPesaService
from services.audit_service import AuditService
from models.transaction import TransactionModel
from middleware.auth_middleware import require_auth

logger = logging.getLogger(__name__)

mpesa_bp = Blueprint('mpesa', __name__)
mpesa_service = MPesaService()

@mpesa_bp.route('/stk-push', methods=['POST'])
@require_auth
async def stk_push():
    """STK Push Payment Initiator Tool"""
    try:
        data = request.get_json()
        required_fields = ['phone_number', 'amount', 'account_reference', 'transaction_desc']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        result = await mpesa_service.stk_push_payment(
            phone_number=data['phone_number'],
            amount=float(data['amount']),
            account_reference=data['account_reference'],
            transaction_desc=data['transaction_desc'],
            user_id=g.current_user_id,
            org_id=g.current_org_id
        )
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'STK_PUSH_INITIATED', 'stk_push_payment',
            data, result, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'STK Push initiated successfully'
        })
        
    except Exception as e:
        logger.error(f"STK Push endpoint failed: {e}")
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'STK_PUSH_INITIATED', 'stk_push_payment',
            data if 'data' in locals() else {}, {'error': str(e)}, 'FAILED',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({'error': str(e)}), 500

@mpesa_bp.route('/transaction-status/<checkout_request_id>', methods=['GET'])
@require_auth
async def check_status(checkout_request_id):
    """Transaction Status Tracker Tool"""
    try:
        result = await mpesa_service.check_transaction_status(
            checkout_request_id=checkout_request_id,
            user_id=g.current_user_id,
            org_id=g.current_org_id
        )
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'TRANSACTION_STATUS_CHECK', 'check_transaction_status',
            {'checkout_request_id': checkout_request_id}, result, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Transaction status retrieved successfully'
        })
        
    except Exception as e:
        logger.error(f"Transaction status check failed: {e}")
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'TRANSACTION_STATUS_CHECK', 'check_transaction_status',
            {'checkout_request_id': checkout_request_id}, {'error': str(e)}, 'FAILED',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({'error': str(e)}), 500

@mpesa_bp.route('/account-balance', methods=['GET'])
@require_auth
async def check_balance():
    """Account Balance Checker Tool"""
    try:
        account_type = request.args.get('account_type', 'PAYBILL')
        
        result = await mpesa_service.get_account_balance(
            user_id=g.current_user_id,
            org_id=g.current_org_id,
            account_type=account_type
        )
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'BALANCE_CHECK', 'get_account_balance',
            {'account_type': account_type}, result, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Balance check initiated successfully'
        })
        
    except Exception as e:
        logger.error(f"Balance check failed: {e}")
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'BALANCE_CHECK', 'get_account_balance',
            {'account_type': request.args.get('account_type', 'PAYBILL')}, 
            {'error': str(e)}, 'FAILED',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({'error': str(e)}), 500

@mpesa_bp.route('/bulk-payment', methods=['POST'])
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
        
        result = await mpesa_service.bulk_payment(
            payments=data['payments'],
            batch_name=data['batch_name'],
            user_id=g.current_user_id,
            org_id=g.current_org_id
        )
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'BULK_PAYMENT', 'bulk_payment',
            {'batch_name': data['batch_name'], 'payment_count': len(data['payments'])}, 
            result, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Bulk payment processed successfully'
        })
        
    except Exception as e:
        logger.error(f"Bulk payment failed: {e}")
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'BULK_PAYMENT', 'bulk_payment',
            {'batch_name': data.get('batch_name') if 'data' in locals() else None}, 
            {'error': str(e)}, 'FAILED',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({'error': str(e)}), 500

@mpesa_bp.route('/reverse-transaction', methods=['POST'])
@require_auth
async def reverse_transaction():
    """Transaction Reversal Tool"""
    try:
        data = request.get_json()
        required_fields = ['transaction_id', 'amount', 'reason']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        result = await mpesa_service.reverse_transaction(
            transaction_id=data['transaction_id'],
            amount=float(data['amount']),
            reason=data['reason'],
            user_id=g.current_user_id,
            org_id=g.current_org_id
        )
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'TRANSACTION_REVERSAL', 'reverse_transaction',
            data, result, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'message': 'Transaction reversal initiated successfully'
        })
        
    except Exception as e:
        logger.error(f"Transaction reversal failed: {e}")
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'TRANSACTION_REVERSAL', 'reverse_transaction',
            data if 'data' in locals() else {}, {'error': str(e)}, 'FAILED',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({'error': str(e)}), 500

@mpesa_bp.route('/transaction-history', methods=['GET'])
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
        
        result = await TransactionModel.get_transaction_history(
            org_id=g.current_org_id,
            filters=filters
        )
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'TRANSACTION_HISTORY_QUERY', 'get_transaction_history',
            filters, {'count': len(result)}, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': result,
            'count': len(result),
            'message': 'Transaction history retrieved successfully'
        })
        
    except Exception as e:
        logger.error(f"Transaction history query failed: {e}")
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'TRANSACTION_HISTORY_QUERY', 'get_transaction_history',
            request.args.to_dict(), {'error': str(e)}, 'FAILED',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({'error': str(e)}), 500

@mpesa_bp.route('/reports/generate', methods=['POST'])
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
        report_data = await TransactionModel.generate_report_data(
            g.current_org_id, date_from, date_to
        )
        
        # Add metadata
        report_data.update({
            'organization_id': g.current_org_id,
            'generated_at': datetime.now().isoformat(),
            'period': f"{date_from} to {date_to}",
            'report_type': report_type
        })
        
        # Store report
        report_id = await TransactionModel.store_report(
            g.current_org_id, report_type, f"{report_type} Report", 
            date_from, date_to, report_data, g.current_user_id
        )
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'REPORT_GENERATED', 'generate_report',
            data, {'report_id': str(report_id)}, 'SUCCESS',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({
            'success': True,
            'data': report_data,
            'report_id': str(report_id),
            'message': 'Report generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        
        await AuditService.log_audit(
            g.current_user_id, g.current_org_id, 'REPORT_GENERATED', 'generate_report',
            data if 'data' in locals() else {}, {'error': str(e)}, 'FAILED',
            request.environ.get('REMOTE_ADDR'),
            request.headers.get('User-Agent')
        )
        
        return jsonify({'error': str(e)}), 500
