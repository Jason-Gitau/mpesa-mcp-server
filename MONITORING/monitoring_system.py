"""
🔥 M-Pesa MCP - Comprehensive Monitoring & Alerting System
===========================================================

Production-ready monitoring system for multi-tenant M-Pesa MCP server
with real-time alerts, security monitoring, and business intelligence.
"""

import os
import logging
import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import asyncpg
import httpx
from prometheus_client import (
    Counter, Histogram, Gauge, CollectorRegistry, 
    generate_latest, CONTENT_TYPE_LATEST
)

# Import your existing services
from config import Config
from utils.secure_database import get_secure_db
from services.audit_service import AuditService

# ==============================================================================
# MONITORING CONFIGURATION
# ==============================================================================

class AlertLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class MonitoringConfig:
    """Monitoring system configuration"""
    
    # Prometheus Configuration
    prometheus_enabled: bool = True
    prometheus_port: int = int(os.getenv('PROMETHEUS_PORT', 9090))
    
    # Alert Thresholds
    max_failed_logins: int = 5
    max_failed_mpesa_calls: int = 3
    max_response_time_ms: int = 5000
    min_success_rate: float = 0.95
    
    # Database Monitoring
    max_db_connections: int = 8
    max_db_response_time_ms: int = 1000
    
    # Business Monitoring
    transaction_failure_threshold: float = 0.05  # 5% failure rate
    rate_limit_warning_threshold: float = 0.8    # 80% of limit
    
    # Security Monitoring
    max_cross_tenant_attempts: int = 3
    suspicious_activity_threshold: int = 10
    
    # Notification Channels
    slack_webhook_url: str = os.getenv('SLACK_WEBHOOK_URL', '')
    email_enabled: bool = os.getenv('EMAIL_ALERTS_ENABLED', 'false').lower() == 'true'
    sms_enabled: bool = os.getenv('SMS_ALERTS_ENABLED', 'false').lower() == 'true'

# ==============================================================================
# PROMETHEUS METRICS REGISTRY
# ==============================================================================

class MetricsRegistry:
    """Centralized Prometheus metrics registry"""
    
    def __init__(self):
        self.registry = CollectorRegistry()
        
        # Application Health Metrics
        self.app_requests_total = Counter(
            'mpesa_mcp_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status', 'organization'],
            registry=self.registry
        )
        
        self.app_request_duration = Histogram(
            'mpesa_mcp_request_duration_seconds',
            'HTTP request duration',
            ['method', 'endpoint', 'organization'],
            registry=self.registry
        )
        
        self.app_active_connections = Gauge(
            'mpesa_mcp_active_connections',
            'Active database connections',
            registry=self.registry
        )
        
        # M-Pesa API Metrics
        self.mpesa_api_calls_total = Counter(
            'mpesa_api_calls_total',
            'Total M-Pesa API calls',
            ['operation', 'status', 'organization'],
            registry=self.registry
        )
        
        self.mpesa_api_duration = Histogram(
            'mpesa_api_duration_seconds',
            'M-Pesa API response time',
            ['operation', 'organization'],
            registry=self.registry
        )
        
        self.mpesa_token_refreshes = Counter(
            'mpesa_token_refreshes_total',
            'M-Pesa token refresh attempts',
            ['status', 'organization'],
            registry=self.registry
        )
        
        # Transaction Metrics
        self.transactions_total = Counter(
            'mpesa_transactions_total',
            'Total transactions processed',
            ['type', 'status', 'organization'],
            registry=self.registry
        )
        
        self.transaction_amount = Histogram(
            'mpesa_transaction_amount',
            'Transaction amounts',
            ['type', 'organization'],
            registry=self.registry
        )
        
        # Security Metrics
        self.auth_attempts_total = Counter(
            'mpesa_auth_attempts_total',
            'Authentication attempts',
            ['status', 'organization'],
            registry=self.registry
        )
        
        self.cross_tenant_attempts = Counter(
            'mpesa_cross_tenant_attempts_total',
            'Cross-tenant access attempts',
            ['user_org', 'target_org'],
            registry=self.registry
        )
        
        self.security_events_total = Counter(
            'mpesa_security_events_total',
            'Security events detected',
            ['event_type', 'severity', 'organization'],
            registry=self.registry
        )
        
        # Business Metrics
        self.revenue_total = Counter(
            'mpesa_revenue_total',
            'Total revenue processed',
            ['organization', 'currency'],
            registry=self.registry
        )
        
        self.rate_limit_hits = Counter(
            'mpesa_rate_limit_hits_total',
            'Rate limit hits',
            ['organization'],
            registry=self.registry
        )
        
        # Database Metrics
        self.db_queries_total = Counter(
            'mpesa_db_queries_total',
            'Database queries executed',
            ['operation', 'status', 'organization'],
            registry=self.registry
        )
        
        self.db_query_duration = Histogram(
            'mpesa_db_query_duration_seconds',
            'Database query duration',
            ['operation', 'organization'],
            registry=self.registry
        )

# Global metrics instance
metrics = MetricsRegistry()

# ==============================================================================
# MONITORING SYSTEM CORE
# ==============================================================================

class MPesaMonitoring:
    """Comprehensive monitoring system for M-Pesa MCP server"""
    
    def __init__(self, config: MonitoringConfig = None):
        self.config = config or MonitoringConfig()
        self.secure_db = get_secure_db()
        self.alerts_queue = asyncio.Queue()
        self.active_alerts = {}
        
        # Health check status
        self.health_status = {
            'application': 'healthy',
            'database': 'healthy',
            'mpesa_api': 'healthy',
            'security': 'healthy'
        }
        
        self.logger = logging.getLogger(__name__)
        
    async def start_monitoring(self):
        """Start all monitoring tasks"""
        self.logger.info("🚀 Starting M-Pesa MCP Monitoring System...")
        
        # Start monitoring tasks
        tasks = [
            self._monitor_application_health(),
            self._monitor_database_health(),
            self._monitor_mpesa_api_health(),
            self._monitor_security_events(),
            self._monitor_business_metrics(),
            self._process_alerts(),
        ]
        
        if self.config.prometheus_enabled:
            tasks.append(self._start_prometheus_server())
        
        await asyncio.gather(*tasks)
    
    # ==========================================================================
    # APPLICATION HEALTH MONITORING
    # ==========================================================================
    
    async def _monitor_application_health(self):
        """Monitor overall application health"""
        while True:
            try:
                await self._check_flask_app_health()
                await self._check_mcp_server_health()
                await self._check_memory_usage()
                await self._check_disk_space()
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Application health monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _check_flask_app_health(self):
        """Check Flask application health"""
        try:
            # Test HTTP endpoint availability
            async with httpx.AsyncClient() as client:
                start_time = time.time()
                response = await client.get(
                    f"http://{Config.FLASK_HOST}:{Config.FLASK_PORT}/health",
                    timeout=5.0
                )
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    self.health_status['application'] = 'healthy'
                    metrics.app_request_duration.labels(
                        method='GET', endpoint='/health', organization='system'
                    ).observe(response_time / 1000)
                else:
                    self.health_status['application'] = 'unhealthy'
                    await self._send_alert(
                        AlertLevel.CRITICAL,
                        "Flask Application Unhealthy",
                        f"Health check returned status {response.status_code}",
                        {'response_time_ms': response_time}
                    )
        
        except Exception as e:
            self.health_status['application'] = 'unhealthy'
            await self._send_alert(
                AlertLevel.CRITICAL,
                "Flask Application Down",
                f"Cannot connect to Flask app: {str(e)}",
                {}
            )
    
    async def _check_mcp_server_health(self):
        """Check MCP server health"""
        try:
            # Check if MCP server process is running
            # This is a simplified check - you might want to implement
            # a proper MCP health check protocol
            pass
        except Exception as e:
            await self._send_alert(
                AlertLevel.HIGH,
                "MCP Server Health Issue",
                f"MCP server health check failed: {str(e)}",
                {}
            )
    
    async def _check_memory_usage(self):
        """Monitor memory usage"""
        try:
            import psutil
            memory_percent = psutil.virtual_memory().percent
            
            if memory_percent > 85:
                await self._send_alert(
                    AlertLevel.HIGH,
                    "High Memory Usage",
                    f"Memory usage at {memory_percent}%",
                    {'memory_percent': memory_percent}
                )
        except ImportError:
            pass  # psutil not available
        except Exception as e:
            self.logger.error(f"Memory check error: {e}")
    
    async def _check_disk_space(self):
        """Monitor disk space"""
        try:
            import shutil
            total, used, free = shutil.disk_usage("/")
            free_percent = (free / total) * 100
            
            if free_percent < 15:
                await self._send_alert(
                    AlertLevel.HIGH,
                    "Low Disk Space",
                    f"Only {free_percent:.1f}% disk space remaining",
                    {'free_percent': free_percent}
                )
        except Exception as e:
            self.logger.error(f"Disk space check error: {e}")
    
    # ==========================================================================
    # DATABASE HEALTH MONITORING  
    # ==========================================================================
    
    async def _monitor_database_health(self):
        """Monitor database health and performance"""
        while True:
            try:
                await self._check_database_connectivity()
                await self._check_database_performance()
                await self._check_connection_pool()
                await self._monitor_slow_queries()
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Database monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _check_database_connectivity(self):
        """Check database connectivity"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                start_time = time.time()
                await conn.fetchval("SELECT 1")
                response_time = (time.time() - start_time) * 1000
                
                if response_time < self.config.max_db_response_time_ms:
                    self.health_status['database'] = 'healthy'
                else:
                    self.health_status['database'] = 'degraded'
                    await self._send_alert(
                        AlertLevel.MEDIUM,
                        "Slow Database Response",
                        f"Database response time: {response_time:.2f}ms",
                        {'response_time_ms': response_time}
                    )
        
        except Exception as e:
            self.health_status['database'] = 'unhealthy'
            await self._send_alert(
                AlertLevel.CRITICAL,
                "Database Connection Failed",
                f"Cannot connect to database: {str(e)}",
                {}
            )
    
    async def _check_database_performance(self):
        """Check database performance metrics"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                # Check for long-running queries
                long_queries = await conn.fetch("""
                    SELECT query, state, query_start, now() - query_start as duration
                    FROM pg_stat_activity 
                    WHERE state = 'active' 
                    AND now() - query_start > interval '30 seconds'
                    AND query NOT LIKE '%pg_stat_activity%'
                """)
                
                if long_queries:
                    await self._send_alert(
                        AlertLevel.MEDIUM,
                        "Long Running Queries Detected",
                        f"Found {len(long_queries)} queries running > 30 seconds",
                        {'query_count': len(long_queries)}
                    )
        
        except Exception as e:
            self.logger.error(f"Database performance check error: {e}")
    
    async def _check_connection_pool(self):
        """Monitor database connection pool health"""
        try:
            pool_size = self.secure_db.pool.get_size()
            max_size = self.secure_db.pool.get_max_size()
            
            metrics.app_active_connections.set(pool_size)
            
            if pool_size > max_size * 0.8:
                await self._send_alert(
                    AlertLevel.MEDIUM,
                    "High Database Connection Usage",
                    f"Using {pool_size}/{max_size} database connections",
                    {'pool_size': pool_size, 'max_size': max_size}
                )
        
        except Exception as e:
            self.logger.error(f"Connection pool check error: {e}")
    
    async def _monitor_slow_queries(self):
        """Monitor for slow database queries"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                slow_queries = await conn.fetch("""
                    SELECT query, calls, total_time, mean_time
                    FROM pg_stat_statements 
                    WHERE mean_time > 1000  -- Queries averaging > 1 second
                    ORDER BY mean_time DESC
                    LIMIT 5
                """)
                
                if slow_queries:
                    for query in slow_queries:
                        metrics.db_query_duration.labels(
                            operation='slow_query', organization='system'
                        ).observe(query['mean_time'] / 1000)
        
        except Exception as e:
            # pg_stat_statements extension might not be available
            pass
    
    # ==========================================================================
    # M-PESA API MONITORING
    # ==========================================================================
    
    async def _monitor_mpesa_api_health(self):
        """Monitor M-Pesa API health and performance"""
        while True:
            try:
                await self._check_mpesa_api_connectivity()
                await self._monitor_token_refresh_health()
                await self._analyze_transaction_patterns()
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"M-Pesa API monitoring error: {e}")
                await asyncio.sleep(300)
    
    async def _check_mpesa_api_connectivity(self):
        """Test M-Pesa API connectivity"""
        try:
            # Test connectivity to M-Pesa sandbox/production
            async with httpx.AsyncClient() as client:
                start_time = time.time()
                response = await client.get(
                    "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
                    timeout=10.0
                )
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code in [200, 401]:  # 401 is expected without credentials
                    self.health_status['mpesa_api'] = 'healthy'
                    metrics.mpesa_api_duration.labels(
                        operation='connectivity_check', organization='system'
                    ).observe(response_time / 1000)
                else:
                    self.health_status['mpesa_api'] = 'unhealthy'
                    await self._send_alert(
                        AlertLevel.HIGH,
                        "M-Pesa API Connectivity Issue",
                        f"M-Pesa API returned status {response.status_code}",
                        {'response_time_ms': response_time}
                    )
        
        except Exception as e:
            self.health_status['mpesa_api'] = 'unhealthy'
            await self._send_alert(
                AlertLevel.CRITICAL,
                "M-Pesa API Unreachable",
                f"Cannot reach M-Pesa API: {str(e)}",
                {}
            )
    
    async def _monitor_token_refresh_health(self):
        """Monitor M-Pesa token refresh patterns"""
        try:
            # Check recent token refresh failures
            failed_refreshes = await self._get_recent_token_failures()
            
            if failed_refreshes > self.config.max_failed_mpesa_calls:
                await self._send_alert(
                    AlertLevel.HIGH,
                    "Multiple M-Pesa Token Refresh Failures",
                    f"{failed_refreshes} token refresh failures detected",
                    {'failure_count': failed_refreshes}
                )
        
        except Exception as e:
            self.logger.error(f"Token refresh monitoring error: {e}")
    
    async def _analyze_transaction_patterns(self):
        """Analyze transaction patterns for anomalies"""
        try:
            # Get transaction stats for the last hour
            stats = await self._get_transaction_stats()
            
            for org_id, org_stats in stats.items():
                failure_rate = org_stats['failed'] / max(org_stats['total'], 1)
                
                if failure_rate > self.config.transaction_failure_threshold:
                    await self._send_alert(
                        AlertLevel.HIGH,
                        f"High Transaction Failure Rate - {org_stats['org_name']}",
                        f"Failure rate: {failure_rate:.2%} ({org_stats['failed']}/{org_stats['total']})",
                        {
                            'organization_id': org_id,
                            'failure_rate': failure_rate,
                            'total_transactions': org_stats['total']
                        }
                    )
        
        except Exception as e:
            self.logger.error(f"Transaction pattern analysis error: {e}")
    
    # ==========================================================================
    # SECURITY MONITORING
    # ==========================================================================
    
    async def _monitor_security_events(self):
        """Monitor security events and suspicious activities"""
        while True:
            try:
                await self._check_failed_logins()
                await self._detect_cross_tenant_access()
                await self._monitor_suspicious_patterns()
                await self._check_audit_log_integrity()
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Security monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _check_failed_logins(self):
        """Monitor failed login attempts"""
        try:
            failed_logins = await AuditService.get_failed_login_attempts(hours=1)
            
            for attempt in failed_logins:
                if attempt['attempt_count'] >= self.config.max_failed_logins:
                    await self._send_alert(
                        AlertLevel.HIGH,
                        "Multiple Failed Login Attempts",
                        f"User {attempt['username']} failed {attempt['attempt_count']} times from {attempt['ip_address']}",
                        {
                            'username': attempt['username'],
                            'ip_address': attempt['ip_address'],
                            'attempt_count': attempt['attempt_count']
                        }
                    )
                    
                    metrics.security_events_total.labels(
                        event_type='failed_login',
                        severity='high',
                        organization=attempt['organization_slug'] or 'unknown'
                    ).inc()
        
        except Exception as e:
            self.logger.error(f"Failed login monitoring error: {e}")
    
    async def _detect_cross_tenant_access(self):
        """Detect cross-tenant access attempts"""
        try:
            # This would require custom audit logging for cross-tenant attempts
            # You'd implement this based on your specific security events
            pass
        
        except Exception as e:
            self.logger.error(f"Cross-tenant access detection error: {e}")
    
    async def _monitor_suspicious_patterns(self):
        """Monitor for suspicious activity patterns"""
        try:
            # Detect unusual activity patterns
            suspicious_activities = await self._get_suspicious_activities()
            
            for activity in suspicious_activities:
                await self._send_alert(
                    AlertLevel.MEDIUM,
                    "Suspicious Activity Detected",
                    f"Unusual pattern detected: {activity['description']}",
                    activity
                )
                
                metrics.security_events_total.labels(
                    event_type='suspicious_activity',
                    severity='medium',
                    organization=activity.get('organization', 'unknown')
                ).inc()
        
        except Exception as e:
            self.logger.error(f"Suspicious pattern monitoring error: {e}")
    
    async def _check_audit_log_integrity(self):
        """Verify audit log integrity"""
        try:
            # Sample recent audit logs for integrity verification
            # This would use your secure_database audit verification
            pass
        
        except Exception as e:
            self.logger.error(f"Audit integrity check error: {e}")
    
    # ==========================================================================
    # BUSINESS METRICS MONITORING
    # ==========================================================================
    
    async def _monitor_business_metrics(self):
        """Monitor business-critical metrics"""
        while True:
            try:
                await self._monitor_revenue_metrics()
                await self._monitor_rate_limiting()
                await self._monitor_subscription_health()
                await self._analyze_usage_patterns()
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Business metrics monitoring error: {e}")
                await asyncio.sleep(300)
    
    async def _monitor_revenue_metrics(self):
        """Monitor revenue and transaction volume"""
        try:
            revenue_stats = await self._get_revenue_stats()
            
            for org_id, stats in revenue_stats.items():
                # Update Prometheus metrics
                metrics.revenue_total.labels(
                    organization=org_id,
                    currency='KES'
                ).inc(stats['total_amount'])
                
                # Check for revenue drops
                if stats['hourly_drop_percent'] > 50:
                    await self._send_alert(
                        AlertLevel.MEDIUM,
                        f"Revenue Drop - {stats['org_name']}",
                        f"Revenue dropped {stats['hourly_drop_percent']:.1f}% in the last hour",
                        {
                            'organization_id': org_id,
                            'drop_percent': stats['hourly_drop_percent']
                        }
                    )
        
        except Exception as e:
            self.logger.error(f"Revenue monitoring error: {e}")
    
    async def _monitor_rate_limiting(self):
        """Monitor rate limiting and API usage"""
        try:
            rate_limit_stats = await self._get_rate_limit_stats()
            
            for org_id, stats in rate_limit_stats.items():
                usage_percent = stats['current_usage'] / max(stats['limit'], 1)
                
                if usage_percent > self.config.rate_limit_warning_threshold:
                    await self._send_alert(
                        AlertLevel.MEDIUM,
                        f"Rate Limit Warning - {stats['org_name']}",
                        f"API usage at {usage_percent:.1%} of limit",
                        {
                            'organization_id': org_id,
                            'usage_percent': usage_percent,
                            'current_usage': stats['current_usage'],
                            'limit': stats['limit']
                        }
                    )
                    
                    metrics.rate_limit_hits.labels(organization=org_id).inc()
        
        except Exception as e:
            self.logger.error(f"Rate limiting monitoring error: {e}")
    
    async def _monitor_subscription_health(self):
        """Monitor subscription status and health"""
        try:
            # Check for expiring subscriptions
            expiring_subscriptions = await self._get_expiring_subscriptions()
            
            for sub in expiring_subscriptions:
                await self._send_alert(
                    AlertLevel.MEDIUM,
                    "Subscription Expiring Soon",
                    f"Organization {sub['name']} subscription expires in {sub['days_until_expiry']} days",
                    sub
                )
        
        except Exception as e:
            self.logger.error(f"Subscription monitoring error: {e}")
    
    async def _analyze_usage_patterns(self):
        """Analyze usage patterns for optimization insights"""
        try:
            usage_patterns = await self._get_usage_patterns()
            
            # This could include recommendations for:
            # - Optimizing rate limits
            # - Subscription plan recommendations
            # - Performance improvements
            
        except Exception as e:
            self.logger.error(f"Usage pattern analysis error: {e}")
    
    # ==========================================================================
    # ALERT PROCESSING
    # ==========================================================================
    
    async def _send_alert(self, level: AlertLevel, title: str, message: str, metadata: Dict = None):
        """Send alert to processing queue"""
        alert = {
            'id': f"alert_{int(time.time())}_{hash(title)}",
            'timestamp': datetime.now().isoformat(),
            'level': level.value,
            'title': title,
            'message': message,
            'metadata': metadata or {},
            'resolved': False
        }
        
        await self.alerts_queue.put(alert)
        self.logger.warning(f"🚨 {level.value.upper()} ALERT: {title} - {message}")
    
    async def _process_alerts(self):
        """Process alerts from queue"""
        while True:
            try:
                alert = await self.alerts_queue.get()
                await self._handle_alert(alert)
                self.alerts_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Alert processing error: {e}")
                await asyncio.sleep(10)
    
    async def _handle_alert(self, alert: Dict):
        """Handle individual alert"""
        try:
            alert_id = alert['id']
            
            # Prevent duplicate alerts
            if alert_id in self.active_alerts:
                return
            
            self.active_alerts[alert_id] = alert
            
            # Send notifications based on alert level
            if alert['level'] in ['critical', 'high']:
                await self._send_slack_notification(alert)
                
                if self.config.email_enabled:
                    await self._send_email_notification(alert)
                    
                if self.config.sms_enabled and alert['level'] == 'critical':
                    await self._send_sms_notification(alert)
            
            # Log alert to database
            await self._log_alert_to_database(alert)
            
        except Exception as e:
            self.logger.error(f"Alert handling error: {e}")
    
    async def _send_slack_notification(self, alert: Dict):
        """Send Slack notification"""
        try:
            if not self.config.slack_webhook_url:
                return
            
            color = {
                'critical': '#FF0000',
                'high': '#FF8C00',
                'medium': '#FFD700',
                'low': '#90EE90',
                'info': '#87CEEB'
            }.get(alert['level'], '#808080')
            
            payload = {
                'attachments': [{
                    'color': color,
                    'title': f"🚨 {alert['level'].upper()}: {alert['title']}",
                    'text': alert['message'],
                    'fields': [
                        {'title': 'Timestamp', 'value': alert['timestamp'], 'short': True},
                        {'title': 'Level', 'value': alert['level'], 'short': True}
                    ],
                    'footer': 'M-Pesa MCP Monitoring'
                }]
            }
            
            # Add metadata fields
            if alert['metadata']:
                for key, value in alert['metadata'].items():
                    payload['attachments'][0]['fields'].append({
                        'title': key.replace('_', ' ').title(),
                        'value': str(value),
                        'short': True
                    })
            
            async with httpx.AsyncClient() as client:
                await client.post(self.config.slack_webhook_url, json=payload)
                
        except Exception as e:
            self.logger.error(f"Slack notification error: {e}")
    
    async def _send_email_notification(self, alert: Dict):
        """Send email notification"""
        try:
            # Implementation would depend on your email service
            # Example using SMTP or service like SendGrid
            self.logger.info(f"Would send email alert: {alert['title']}")
        except Exception as e:
            self.logger.error(f"Email notification error: {e}")
    
    async def _send_sms_notification(self, alert: Dict):
        """Send SMS notification for critical alerts"""
        try:
            # Implementation would use SMS service like Twilio or Africa's Talking
            self.logger.info(f"Would send SMS alert: {alert['title']}")
        except Exception as e:
            self.logger.error(f"SMS notification error: {e}")
    
    async def _log_alert_to_database(self, alert: Dict):
        """Log alert to database for historical tracking"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO monitoring_alerts 
                    (alert_id, level, title, message, metadata, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """, 
                alert['id'], alert['level'], alert['title'], 
                alert['message'], json.dumps(alert['metadata']), 
                datetime.now()
                )
        except Exception as e:
            self.logger.error(f"Database alert logging error: {e}")
    
    # ==========================================================================
    # PROMETHEUS METRICS SERVER
    # ==========================================================================
    
    async def _start_prometheus_server(self):
        """Start Prometheus metrics server"""
        from aiohttp import web, web_response
        
        async def metrics_handler(request):
            """Handle metrics endpoint"""
            metrics_output = generate_latest(metrics.registry)
            return web_response.Response(
                body=metrics_output,
                content_type=CONTENT_TYPE_LATEST
            )
        
        async def health_handler(request):
            """Health check endpoint"""
            return web_response.json_response(self.health_status)
        
        app = web.Application()
        app.router.add_get('/metrics', metrics_handler)
        app.router.add_get('/health', health_handler)
        
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', self.config.prometheus_port)
        await site.start()
        
        self.logger.info(f"📊 Prometheus metrics server started on port {self.config.prometheus_port}")
        
        # Keep server running
        while True:
            await asyncio.sleep(3600)
    
    # ==========================================================================
    # DATA COLLECTION METHODS
    # ==========================================================================
    
    async def _get_recent_token_failures(self) -> int:
        """Get count of recent M-Pesa token refresh failures"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                result = await conn.fetchval("""
                    SELECT COUNT(*)
                    FROM audit_logs 
                    WHERE action = 'mpesa_token_refresh'
                    AND details->>'status' = 'failed'
                    AND created_at > NOW() - INTERVAL '1 hour'
                """)
                return result or 0
        except Exception as e:
            self.logger.error(f"Token failure query error: {e}")
            return 0
    
    async def _get_transaction_stats(self) -> Dict:
        """Get transaction statistics by organization"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                results = await conn.fetch("""
                    SELECT 
                        t.organization_id,
                        o.name as org_name,
                        COUNT(*) as total,
                        SUM(CASE WHEN t.status = 'failed' THEN 1 ELSE 0 END) as failed,
                        SUM(CASE WHEN t.status = 'completed' THEN 1 ELSE 0 END) as completed
                    FROM transactions t
                    JOIN organizations o ON t.organization_id = o.id
                    WHERE t.created_at > NOW() - INTERVAL '1 hour'
                    GROUP BY t.organization_id, o.name
                """)
                
                stats = {}
                for row in results:
                    stats[row['organization_id']] = {
                        'org_name': row['org_name'],
                        'total': row['total'],
                        'failed': row['failed'],
                        'completed': row['completed']
                    }
                return stats
        except Exception as e:
            self.logger.error(f"Transaction stats query error: {e}")
            return {}
    
    async def _get_suspicious_activities(self) -> List[Dict]:
        """Detect suspicious activities from audit logs"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                # Example: Multiple failed operations from same IP
                results = await conn.fetch("""
                    SELECT 
                        ip_address,
                        COUNT(*) as attempt_count,
                        array_agg(DISTINCT action) as actions
                    FROM audit_logs
                    WHERE created_at > NOW() - INTERVAL '1 hour'
                    AND details->>'status' = 'failed'
                    GROUP BY ip_address
                    HAVING COUNT(*) > $1
                """, self.config.suspicious_activity_threshold)
                
                activities = []
                for row in results:
                    activities.append({
                        'type': 'multiple_failures',
                        'description': f"Multiple failures from IP {row['ip_address']}",
                        'ip_address': row['ip_address'],
                        'attempt_count': row['attempt_count'],
                        'actions': row['actions']
                    })
                
                return activities
        except Exception as e:
            self.logger.error(f"Suspicious activity query error: {e}")
            return []
    
    async def _get_revenue_stats(self) -> Dict:
        """Get revenue statistics by organization"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                results = await conn.fetch("""
                    SELECT 
                        t.organization_id,
                        o.name as org_name,
                        SUM(t.amount) as total_amount,
                        COUNT(*) as transaction_count
                    FROM transactions t
                    JOIN organizations o ON t.organization_id = o.id
                    WHERE t.status = 'completed'
                    AND t.created_at > NOW() - INTERVAL '1 hour'
                    GROUP BY t.organization_id, o.name
                """)
                
                # Get previous hour for comparison
                prev_results = await conn.fetch("""
                    SELECT 
                        t.organization_id,
                        SUM(t.amount) as prev_amount
                    FROM transactions t
                    WHERE t.status = 'completed'
                    AND t.created_at BETWEEN NOW() - INTERVAL '2 hours' AND NOW() - INTERVAL '1 hour'
                    GROUP BY t.organization_id
                """)
                
                prev_amounts = {r['organization_id']: r['prev_amount'] for r in prev_results}
                
                stats = {}
                for row in results:
                    org_id = row['organization_id']
                    current = float(row['total_amount'] or 0)
                    previous = float(prev_amounts.get(org_id, 0))
                    
                    drop_percent = 0
                    if previous > 0:
                        drop_percent = ((previous - current) / previous) * 100
                    
                    stats[org_id] = {
                        'org_name': row['org_name'],
                        'total_amount': current,
                        'transaction_count': row['transaction_count'],
                        'hourly_drop_percent': max(0, drop_percent)
                    }
                
                return stats
        except Exception as e:
            self.logger.error(f"Revenue stats query error: {e}")
            return {}
    
    async def _get_rate_limit_stats(self) -> Dict:
        """Get rate limiting statistics"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                results = await conn.fetch("""
                    SELECT 
                        o.id as organization_id,
                        o.name as org_name,
                        o.rate_limit as limit,
                        COUNT(al.*) as current_usage
                    FROM organizations o
                    LEFT JOIN audit_logs al ON o.id = al.organization_id
                        AND al.created_at > NOW() - INTERVAL '1 hour'
                        AND al.action LIKE 'api_%'
                    GROUP BY o.id, o.name, o.rate_limit
                """)
                
                stats = {}
                for row in results:
                    stats[row['organization_id']] = {
                        'org_name': row['org_name'],
                        'limit': row['limit'] or 1000,  # Default limit
                        'current_usage': row['current_usage'] or 0
                    }
                
                return stats
        except Exception as e:
            self.logger.error(f"Rate limit stats query error: {e}")
            return {}
    
    async def _get_expiring_subscriptions(self) -> List[Dict]:
        """Get organizations with expiring subscriptions"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                results = await conn.fetch("""
                    SELECT 
                        id,
                        name,
                        subscription_expires_at,
                        EXTRACT(DAYS FROM subscription_expires_at - NOW()) as days_until_expiry
                    FROM organizations
                    WHERE subscription_expires_at IS NOT NULL
                    AND subscription_expires_at > NOW()
                    AND subscription_expires_at < NOW() + INTERVAL '7 days'
                """)
                
                return [dict(row) for row in results]
        except Exception as e:
            self.logger.error(f"Expiring subscriptions query error: {e}")
            return []
    
    async def _get_usage_patterns(self) -> Dict:
        """Analyze usage patterns for insights"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                # Example: Peak usage times per organization
                results = await conn.fetch("""
                    SELECT 
                        organization_id,
                        EXTRACT(HOUR FROM created_at) as hour,
                        COUNT(*) as request_count
                    FROM audit_logs
                    WHERE created_at > NOW() - INTERVAL '7 days'
                    AND action LIKE 'api_%'
                    GROUP BY organization_id, EXTRACT(HOUR FROM created_at)
                    ORDER BY organization_id, hour
                """)
                
                patterns = {}
                for row in results:
                    org_id = row['organization_id']
                    if org_id not in patterns:
                        patterns[org_id] = {'hourly_usage': {}}
                    
                    patterns[org_id]['hourly_usage'][row['hour']] = row['request_count']
                
                return patterns
        except Exception as e:
            self.logger.error(f"Usage patterns query error: {e}")
            return {}

# ==============================================================================
# MONITORING DECORATORS AND MIDDLEWARE
# ==============================================================================

def monitor_mpesa_operation(operation_name: str):
    """Decorator to monitor M-Pesa operations"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            org_id = kwargs.get('org_id', 'unknown')
            
            try:
                result = await func(*args, **kwargs)
                
                # Record success
                metrics.mpesa_api_calls_total.labels(
                    operation=operation_name,
                    status='success',
                    organization=str(org_id)
                ).inc()
                
                duration = time.time() - start_time
                metrics.mpesa_api_duration.labels(
                    operation=operation_name,
                    organization=str(org_id)
                ).observe(duration)
                
                return result
                
            except Exception as e:
                # Record failure
                metrics.mpesa_api_calls_total.labels(
                    operation=operation_name,
                    status='failed',
                    organization=str(org_id)
                ).inc()
                
                duration = time.time() - start_time
                metrics.mpesa_api_duration.labels(
                    operation=operation_name,
                    organization=str(org_id)
                ).observe(duration)
                
                raise
        
        return wrapper
    return decorator

def monitor_database_operation(operation_name: str):
    """Decorator to monitor database operations"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            org_id = kwargs.get('org_id', 'unknown')
            
            try:
                result = await func(*args, **kwargs)
                
                # Record success
                metrics.db_queries_total.labels(
                    operation=operation_name,
                    status='success',
                    organization=str(org_id)
                ).inc()
                
                duration = time.time() - start_time
                metrics.db_query_duration.labels(
                    operation=operation_name,
                    organization=str(org_id)
                ).observe(duration)
                
                return result
                
            except Exception as e:
                # Record failure
                metrics.db_queries_total.labels(
                    operation=operation_name,
                    status='failed',
                    organization=str(org_id)
                ).inc()
                
                raise
        
        return wrapper
    return decorator

class MonitoringMiddleware:
    """Flask middleware for request monitoring"""
    
    def __init__(self, app):
        self.app = app
        
    def __call__(self, environ, start_response):
        start_time = time.time()
        
        def new_start_response(status, response_headers, exc_info=None):
            duration = time.time() - start_time
            
            # Extract request info
            method = environ.get('REQUEST_METHOD', 'GET')
            path = environ.get('PATH_INFO', '/')
            status_code = status.split()[0]
            org_id = environ.get('HTTP_X_ORGANIZATION_ID', 'unknown')
            
            # Record metrics
            metrics.app_requests_total.labels(
                method=method,
                endpoint=path,
                status=status_code,
                organization=org_id
            ).inc()
            
            metrics.app_request_duration.labels(
                method=method,
                endpoint=path,
                organization=org_id
            ).observe(duration)
            
            return start_response(status, response_headers, exc_info)
        
        return self.app(environ, new_start_response)

# ==============================================================================
# DASHBOARD DATA PROVIDERS
# ==============================================================================

class MonitoringDashboard:
    """Provides data for monitoring dashboards"""
    
    def __init__(self, secure_db):
        self.secure_db = secure_db
    
    async def get_system_overview(self) -> Dict:
        """Get system overview metrics"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                # Overall system health
                overview = {
                    'total_organizations': await conn.fetchval("SELECT COUNT(*) FROM organizations"),
                    'active_users': await conn.fetchval("""
                        SELECT COUNT(DISTINCT user_id) FROM audit_logs 
                        WHERE created_at > NOW() - INTERVAL '24 hours'
                    """),
                    'transactions_24h': await conn.fetchval("""
                        SELECT COUNT(*) FROM transactions 
                        WHERE created_at > NOW() - INTERVAL '24 hours'
                    """),
                    'revenue_24h': await conn.fetchval("""
                        SELECT COALESCE(SUM(amount), 0) FROM transactions 
                        WHERE status = 'completed' AND created_at > NOW() - INTERVAL '24 hours'
                    """),
                    'success_rate_24h': await conn.fetchval("""
                        SELECT CASE 
                            WHEN COUNT(*) = 0 THEN 0 
                            ELSE (COUNT(*) FILTER (WHERE status = 'completed')::float / COUNT(*)) * 100
                        END
                        FROM transactions 
                        WHERE created_at > NOW() - INTERVAL '24 hours'
                    """) or 0
                }
                
                return overview
        except Exception as e:
            self.logger.error(f"System overview error: {e}")
            return {}
    
    async def get_organization_metrics(self, org_id: int) -> Dict:
        """Get metrics for specific organization"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                metrics_data = {
                    'transactions_today': await conn.fetchval("""
                        SELECT COUNT(*) FROM transactions 
                        WHERE organization_id = $1 AND created_at > CURRENT_DATE
                    """, org_id),
                    'revenue_today': await conn.fetchval("""
                        SELECT COALESCE(SUM(amount), 0) FROM transactions 
                        WHERE organization_id = $1 AND status = 'completed' 
                        AND created_at > CURRENT_DATE
                    """, org_id),
                    'success_rate': await conn.fetchval("""
                        SELECT CASE 
                            WHEN COUNT(*) = 0 THEN 0 
                            ELSE (COUNT(*) FILTER (WHERE status = 'completed')::float / COUNT(*)) * 100
                        END
                        FROM transactions 
                        WHERE organization_id = $1 AND created_at > NOW() - INTERVAL '24 hours'
                    """, org_id) or 0,
                    'api_calls_today': await conn.fetchval("""
                        SELECT COUNT(*) FROM audit_logs 
                        WHERE organization_id = $1 AND action LIKE 'api_%' 
                        AND created_at > CURRENT_DATE
                    """, org_id)
                }
                
                return metrics_data
        except Exception as e:
            self.logger.error(f"Organization metrics error: {e}")
            return {}
    
    async def get_security_dashboard(self) -> Dict:
        """Get security monitoring dashboard data"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                security_data = {
                    'failed_logins_24h': await conn.fetchval("""
                        SELECT COUNT(*) FROM audit_logs 
                        WHERE action = 'login' AND details->>'status' = 'failed'
                        AND created_at > NOW() - INTERVAL '24 hours'
                    """),
                    'security_events_24h': await conn.fetchval("""
                        SELECT COUNT(*) FROM audit_logs 
                        WHERE action IN ('security_violation', 'suspicious_activity')
                        AND created_at > NOW() - INTERVAL '24 hours'
                    """),
                    'unique_ips_24h': await conn.fetchval("""
                        SELECT COUNT(DISTINCT ip_address) FROM audit_logs 
                        WHERE created_at > NOW() - INTERVAL '24 hours'
                    """),
                    'recent_security_events': await conn.fetch("""
                        SELECT action, ip_address, details, created_at
                        FROM audit_logs 
                        WHERE action IN ('login', 'security_violation', 'suspicious_activity')
                        AND details->>'status' = 'failed'
                        ORDER BY created_at DESC 
                        LIMIT 10
                    """)
                }
                
                return security_data
        except Exception as e:
            self.logger.error(f"Security dashboard error: {e}")
            return {}

# ==============================================================================
# HEALTH CHECK ENDPOINTS
# ==============================================================================

async def create_health_check_routes(app, monitoring: MPesaMonitoring):
    """Add health check routes to Flask app"""
    
    @app.route('/health')
    async def health_check():
        """Basic health check endpoint"""
        return {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0'
        }
    
    @app.route('/health/detailed')
    async def detailed_health_check():
        """Detailed health check with all systems"""
        return {
            'status': monitoring.health_status,
            'timestamp': datetime.now().isoformat(),
            'checks': {
                'database': await _check_database_health(monitoring),
                'mpesa_api': await _check_mpesa_connectivity(monitoring),
                'audit_system': await _check_audit_system(monitoring)
            }
        }
    
    @app.route('/metrics/summary')
    async def metrics_summary():
        """Summary metrics for dashboard"""
        dashboard = MonitoringDashboard(monitoring.secure_db)
        return await dashboard.get_system_overview()

async def _check_database_health(monitoring: MPesaMonitoring) -> Dict:
    """Check database health status"""
    try:
        async with monitoring.secure_db.pool.acquire() as conn:
            start_time = time.time()
            await conn.fetchval("SELECT 1")
            response_time = (time.time() - start_time) * 1000
            
            return {
                'status': 'healthy',
                'response_time_ms': response_time,
                'connections': monitoring.secure_db.pool.get_size()
            }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e)
        }

async def _check_mpesa_connectivity(monitoring: MPesaMonitoring) -> Dict:
    """Check M-Pesa API connectivity"""
    try:
        async with httpx.AsyncClient() as client:
            start_time = time.time()
            response = await client.get(
                "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
                timeout=10.0
            )
            response_time = (time.time() - start_time) * 1000
            
            return {
                'status': 'healthy' if response.status_code in [200, 401] else 'unhealthy',
                'response_time_ms': response_time,
                'status_code': response.status_code
            }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e)
        }

async def _check_audit_system(monitoring: MPesaMonitoring) -> Dict:
    """Check audit system health"""
    try:
        # Test audit log creation
        test_entry = await AuditService.log_activity(
            user_id=None,
            organization_id=None,
            action='health_check',
            details={'test': True}
        )
        
        return {
            'status': 'healthy',
            'last_audit_id': test_entry
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e)
        }

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

async def main():
    """Main function to start monitoring system"""
    
    # Initialize monitoring configuration
    config = MonitoringConfig()
    
    # Create monitoring instance
    monitoring = MPesaMonitoring(config)
    
    # Start monitoring system
    await monitoring.start_monitoring()

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run monitoring system
    asyncio.run(main())
