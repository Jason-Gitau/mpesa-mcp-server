import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from utils.database import get_db_pool

logger = logging.getLogger(__name__)

class AuditService:
    """Audit logging and tracking service"""

    @staticmethod
    async def log_audit(user_id: str, org_id: str, action: str, tool_name: str, 
                       request_data: Dict, response_data: Dict, status: str,
                       ip_address: str = None, user_agent: str = None):
        """Log audit trail with organization context"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO audit_logs (organization_id, user_id, action, tool_name, request_data, 
                                          response_data, status, ip_address, user_agent)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """, org_id, user_id, action, tool_name, json.dumps(request_data), 
                     json.dumps(response_data), status, ip_address, user_agent)
        except Exception as e:
            logger.error(f"Failed to log audit: {e}")
            # Don't raise exception to prevent disrupting main flow
            pass

    @staticmethod
    async def get_audit_logs(org_filter: str = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get audit logs with optional organization filter"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
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
                return [dict(log) for log in logs]
                
        except Exception as e:
            logger.error(f"Failed to get audit logs: {e}")
            raise

    @staticmethod
    async def get_user_activity(user_id: str, org_id: str = None, days: int = 30) -> List[Dict]:
        """Get user activity logs"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                query = """
                    SELECT a.*, o.name as organization_name
                    FROM audit_logs a
                    LEFT JOIN organizations o ON a.organization_id = o.id
                    WHERE a.user_id = $1 AND a.created_at >= NOW() - INTERVAL '%s days'
                """
                params = [user_id]
                
                if org_id:
                    query += " AND a.organization_id = $2"
                    params.append(org_id)
                
                query += " ORDER BY a.created_at DESC"
                
                logs = await conn.fetch(query % days, *params)
                return [dict(log) for log in logs]
                
        except Exception as e:
            logger.error(f"Failed to get user activity: {e}")
            raise

    @staticmethod
    async def get_organization_activity_summary(org_id: str, days: int = 30) -> Dict:
        """Get organization activity summary"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                summary = await conn.fetchrow("""
                    SELECT 
                        COUNT(*) as total_activities,
                        COUNT(DISTINCT user_id) as active_users,
                        COUNT(CASE WHEN status = 'SUCCESS' THEN 1 END) as successful_activities,
                        COUNT(CASE WHEN status = 'FAILED' THEN 1 END) as failed_activities,
                        COUNT(CASE WHEN action = 'STK_PUSH_INITIATED' THEN 1 END) as stk_push_count,
                        COUNT(CASE WHEN action = 'BULK_PAYMENT' THEN 1 END) as bulk_payment_count
                    FROM audit_logs
                    WHERE organization_id = $1 AND created_at >= NOW() - INTERVAL '%s days'
                """ % days, org_id)
                
                # Get daily breakdown
                daily_activity = await conn.fetch("""
                    SELECT 
                        DATE(created_at) as activity_date,
                        COUNT(*) as daily_count,
                        COUNT(CASE WHEN status = 'SUCCESS' THEN 1 END) as daily_success
                    FROM audit_logs
                    WHERE organization_id = $1 AND created_at >= NOW() - INTERVAL '%s days'
                    GROUP BY DATE(created_at)
                    ORDER BY activity_date DESC
                """ % days, org_id)
                
                # Get top actions
                top_actions = await conn.fetch("""
                    SELECT 
                        action,
                        COUNT(*) as action_count
                    FROM audit_logs
                    WHERE organization_id = $1 AND created_at >= NOW() - INTERVAL '%s days'
                    GROUP BY action
                    ORDER BY action_count DESC
                    LIMIT 10
                """ % days, org_id)
                
                return {
                    'summary': dict(summary) if summary else {},
                    'daily_activity': [dict(row) for row in daily_activity],
                    'top_actions': [dict(row) for row in top_actions]
                }
                
        except Exception as e:
            logger.error(f"Failed to get organization activity summary: {e}")
            raise

    @staticmethod
    async def log_login_attempt(username: str, success: bool, ip_address: str = None, 
                              user_agent: str = None, org_slug: str = None):
        """Log login attempts for security monitoring"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO login_attempts (username, success, ip_address, user_agent, 
                                              organization_slug, attempted_at)
                    VALUES ($1, $2, $3, $4, $5, NOW())
                """, username, success, ip_address, user_agent, org_slug)
        except Exception as e:
            logger.error(f"Failed to log login attempt: {e}")
            pass

    @staticmethod
    async def get_failed_login_attempts(hours: int = 24) -> List[Dict]:
        """Get failed login attempts for security monitoring"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                attempts = await conn.fetch("""
                    SELECT username, ip_address, user_agent, organization_slug, attempted_at,
                           COUNT(*) as attempt_count
                    FROM login_attempts
                    WHERE success = false AND attempted_at >= NOW() - INTERVAL '%s hours'
                    GROUP BY username, ip_address, user_agent, organization_slug, 
                             DATE_TRUNC('hour', attempted_at)
                    HAVING COUNT(*) >= 3
                    ORDER BY attempt_count DESC, attempted_at DESC
                """ % hours)
                
                return [dict(attempt) for attempt in attempts]
                
        except Exception as e:
            logger.error(f"Failed to get failed login attempts: {e}")
            raise

    @staticmethod
    async def log_security_event(event_type: str, description: str, user_id: str = None,
                                org_id: str = None, ip_address: str = None, metadata: Dict = None):
        """Log security-related events"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO security_events (event_type, description, user_id, organization_id,
                                               ip_address, metadata, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, NOW())
                """, event_type, description, user_id, org_id, ip_address, 
                     json.dumps(metadata) if metadata else None)
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
            pass

    @staticmethod
    async def get_security_events(org_id: str = None, days: int = 30) -> List[Dict]:
        """Get security events"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                query = """
                    SELECT s.*, u.username, o.name as organization_name
                    FROM security_events s
                    LEFT JOIN users u ON s.user_id = u.id
                    LEFT JOIN organizations o ON s.organization_id = o.id
                    WHERE s.created_at >= NOW() - INTERVAL '%s days'
                """
                params = []
                
                if org_id:
                    query += " AND s.organization_id = $1"
                    params.append(org_id)
                
                query += " ORDER BY s.created_at DESC"
                
                events = await conn.fetch(query % days, *params)
                return [dict(event) for event in events]
                
        except Exception as e:
            logger.error(f"Failed to get security events: {e}")
            raise

    @staticmethod
    async def cleanup_old_logs(days: int = 90):
        """Cleanup old audit logs and events"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                # Cleanup old audit logs
                audit_deleted = await conn.fetchval("""
                    DELETE FROM audit_logs 
                    WHERE created_at < NOW() - INTERVAL '%s days'
                    RETURNING COUNT(*)
                """ % days)
                
                # Cleanup old login attempts
                login_deleted = await conn.fetchval("""
                    DELETE FROM login_attempts 
                    WHERE attempted_at < NOW() - INTERVAL '%s days'
                    RETURNING COUNT(*)
                """ % days)
                
                # Cleanup old security events (keep longer)
                security_deleted = await conn.fetchval("""
                    DELETE FROM security_events 
                    WHERE created_at < NOW() - INTERVAL '%s days'
                    RETURNING COUNT(*)
                """ % (days * 2))
                
                logger.info(f"Cleanup completed: {audit_deleted} audit logs, "
                          f"{login_deleted} login attempts, {security_deleted} security events deleted")
                
                return {
                    'audit_logs_deleted': audit_deleted or 0,
                    'login_attempts_deleted': login_deleted or 0,
                    'security_events_deleted': security_deleted or 0
                }
                
        except Exception as e:
            logger.error(f"Log cleanup failed: {e}")
            raise

    @staticmethod
    async def export_audit_logs(org_id: str, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Export audit logs for compliance"""
        try:
            pool = get_db_pool()
            async with pool.acquire() as conn:
                logs = await conn.fetch("""
                    SELECT a.*, u.username, u.email, o.name as organization_name
                    FROM audit_logs a
                    LEFT JOIN users u ON a.user_id = u.id
                    LEFT JOIN organizations o ON a.organization_id = o.id
                    WHERE a.organization_id = $1 
                    AND a.created_at BETWEEN $2 AND $3
                    ORDER BY a.created_at ASC
                """, org_id, start_date, end_date)
                
                return [dict(log) for log in logs]
                
        except Exception as e:
            logger.error(f"Failed to export audit logs: {e}")
            raise
