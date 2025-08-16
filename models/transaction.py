import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from decimal import Decimal

from utils.database import get_db_pool

logger = logging.getLogger(__name__)

class TransactionModel:
    """Transaction-related database operations"""

    @staticmethod
    async def create_stk_transaction(org_id: str, merchant_request_id: str, checkout_request_id: str,
                                   amount: float, phone_number: str, account_reference: str,
                                   transaction_desc: str, user_id: str):
        """Store STK Push transaction"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO transactions (organization_id, merchant_request_id, checkout_request_id,
                                            transaction_type, amount, phone_number,
                                            account_reference, transaction_desc, initiated_by, status)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                """, org_id, merchant_request_id, checkout_request_id,
                     'STK_PUSH', Decimal(str(amount)), phone_number, 
                     account_reference, transaction_desc, user_id, 'PENDING')
        except Exception as e:
            logger.error(f"Failed to create STK transaction: {e}")
            raise

    @staticmethod
    async def update_transaction_status(checkout_request_id: str, org_id: str, status: str,
                                      result_code: int = None, result_desc: str = None,
                                      mpesa_receipt_number: str = None, callback_data: Dict = None):
        """Update transaction status from callback"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    UPDATE transactions 
                    SET status = $1, result_code = $2, result_desc = $3, 
                        mpesa_receipt_number = $4, callback_data = $5, updated_at = NOW()
                    WHERE checkout_request_id = $6 AND organization_id = $7
                """, status, result_code, result_desc, mpesa_receipt_number,
                    json.dumps(callback_data) if callback_data else None, 
                    checkout_request_id, org_id)
        except Exception as e:
            logger.error(f"Failed to update transaction status: {e}")
            raise

    @staticmethod
    async def update_transaction_query_status(checkout_request_id: str, org_id: str, 
                                            result_desc: str, result_code: int = None):
        """Update transaction from status query"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    UPDATE transactions SET status = $1, result_code = $2, 
                                          result_desc = $3, updated_at = NOW()
                    WHERE checkout_request_id = $4 AND organization_id = $5
                """, result_desc, result_code, result_desc, checkout_request_id, org_id)
        except Exception as e:
            logger.error(f"Failed to update transaction query status: {e}")
            raise

    @staticmethod
    async def get_transaction_history(org_id: str, filters: Dict) -> List[Dict]:
        """Get transaction history with filters"""
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
            
            pool = get_db_pool()
            async with pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Transaction history query failed: {e}")
            raise

    @staticmethod
    async def create_bulk_payment(org_id: str, batch_id: str, batch_name: str, 
                                total_amount: float, total_recipients: int, user_id: str):
        """Create bulk payment record"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                bulk_payment_id = await conn.fetchval("""
                    INSERT INTO bulk_payments (organization_id, batch_id, batch_name, total_amount, 
                                             total_recipients, initiated_by, status)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING id
                """, org_id, batch_id, batch_name, Decimal(str(total_amount)), 
                     total_recipients, user_id, 'PROCESSING')
                return bulk_payment_id
        except Exception as e:
            logger.error(f"Failed to create bulk payment: {e}")
            raise

    @staticmethod
    async def create_bulk_payment_item(bulk_payment_id: int, phone_number: str, amount: float,
                                     account_reference: str = None, remarks: str = None):
        """Create bulk payment item"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO bulk_payment_items (bulk_payment_id, phone_number, 
                                                   amount, account_reference, remarks, status)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """, bulk_payment_id, phone_number, Decimal(str(amount)), 
                     account_reference, remarks, 'PENDING')
        except Exception as e:
            logger.error(f"Failed to create bulk payment item: {e}")
            raise

    @staticmethod
    async def update_bulk_payment_status(bulk_payment_id: int, org_id: str, status: str):
        """Update bulk payment status"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    UPDATE bulk_payments SET status = $1, completed_at = NOW()
                    WHERE id = $2 AND organization_id = $3
                """, status, bulk_payment_id, org_id)
        except Exception as e:
            logger.error(f"Failed to update bulk payment status: {e}")
            raise

    @staticmethod
    async def update_bulk_payment_item_status(org_id: str, status: str, result_code: int, result_desc: str):
        """Update bulk payment item status from callback"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
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
        except Exception as e:
            logger.error(f"Failed to update bulk payment item status: {e}")
            raise

    @staticmethod
    async def create_reversal(original_transaction_id: int, amount: float, reason: str, user_id: str):
        """Create transaction reversal record"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO reversals (original_transaction_id, amount, 
                                         reason, initiated_by, status)
                    VALUES ($1, $2, $3, $4, $5)
                """, original_transaction_id, Decimal(str(amount)), reason, user_id, 'PENDING')
        except Exception as e:
            logger.error(f"Failed to create reversal: {e}")
            raise

    @staticmethod
    async def get_original_transaction(transaction_id: str, org_id: str):
        """Get original transaction for reversal"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                return await conn.fetchrow("""
                    SELECT id FROM transactions WHERE transaction_id = $1 AND organization_id = $2
                """, transaction_id, org_id)
        except Exception as e:
            logger.error(f"Failed to get original transaction: {e}")
            raise

    @staticmethod
    async def create_balance_log(org_id: str, account_type: str, balance: float):
        """Create balance log entry"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO balance_logs (organization_id, account_type, balance, checked_at)
                    VALUES ($1, $2, $3, NOW())
                """, org_id, account_type, balance)
        except Exception as e:
            logger.error(f"Failed to create balance log: {e}")
            raise

    @staticmethod
    async def generate_report_data(org_id: str, date_from: str, date_to: str) -> Dict:
        """Generate report data for organization"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
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
                """, org_id, date_from, date_to)
                
                # Transaction by type for this organization
                transactions_by_type = await conn.fetch("""
                    SELECT transaction_type, COUNT(*) as count, SUM(amount) as total_amount
                    FROM transactions 
                    WHERE organization_id = $1 AND created_at BETWEEN $2 AND $3 AND status = 'SUCCESS'
                    GROUP BY transaction_type
                """, org_id, date_from, date_to)
                
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
                """, org_id, date_from, date_to)
                
                # Bulk payment summary for this organization
                bulk_summary = await conn.fetchrow("""
                    SELECT 
                        COUNT(*) as total_batches,
                        SUM(total_amount) as total_bulk_amount,
                        SUM(total_recipients) as total_recipients
                    FROM bulk_payments
                    WHERE organization_id = $1 AND created_at BETWEEN $2 AND $3
                """, org_id, date_from, date_to)
                
                return {
                    'summary': dict(transaction_summary),
                    'by_type': [dict(row) for row in transactions_by_type],
                    'daily_breakdown': [dict(row) for row in daily_breakdown],
                    'bulk_payments': dict(bulk_summary)
                }
                
        except Exception as e:
            logger.error(f"Failed to generate report data: {e}")
            raise

    @staticmethod
    async def store_report(org_id: str, report_type: str, report_name: str, 
                          date_from: str, date_to: str, report_data: Dict, user_id: str):
        """Store generated report"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                report_id = await conn.fetchval("""
                    INSERT INTO reports (organization_id, report_type, report_name, date_from, date_to, 
                                       report_data, generated_by, expires_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    RETURNING id
                """, org_id, report_type, report_name, date_from, date_to,
                    json.dumps(report_data), user_id, 
                    datetime.now() + timedelta(days=30))
                return report_id
        except Exception as e:
            logger.error(f"Failed to store report: {e}")
            raise
