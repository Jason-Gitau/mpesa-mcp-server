# 🚀 M-Pesa MCP - Complete Monitoring & Alerting System

## 📋 Overview

This comprehensive monitoring system provides **enterprise-grade observability** for your M-Pesa MCP multi-tenant server with:

- ✅ **Real-time Application Health Monitoring**
- ✅ **Multi-Tenant Security Monitoring** 
- ✅ **Business Intelligence Dashboards**
- ✅ **Critical Alert System** (Slack, Email, SMS)
- ✅ **Performance Optimization Insights**

## 🛠️ Quick Setup Guide

### Step 1: Install Dependencies

Add monitoring dependencies to your `requirements.txt`:

```bash
# Add these to your existing requirements.txt
prometheus-client==0.17.1
psutil==5.9.5
aiohttp==3.8.5
```

### Step 2: Integrate Monitoring into Your Application

**Update your `main.py`:**

```python
import asyncio
from monitoring_system import MPesaMonitoring, MonitoringConfig, create_health_check_routes

async def main():
    # Initialize your existing Flask app and MCP server
    app = create_app()
    
    # Initialize monitoring
    monitoring_config = MonitoringConfig()
    monitoring = MPesaMonitoring(monitoring_config)
    
    # Add health check routes
    await create_health_check_routes(app, monitoring)
    
    # Start monitoring in background
    monitoring_task = asyncio.create_task(monitoring.start_monitoring())
    
    # Start your existing servers
    flask_task = asyncio.create_task(run_flask_server())
    mcp_task = asyncio.create_task(run_mcp_server())
    
    # Run all tasks together
    await asyncio.gather(flask_task, mcp_task, monitoring_task)

if __name__ == "__main__":
    asyncio.run(main())
```

**Update your services to use monitoring decorators:**

```python
# In your services/mpesa_service.py
from monitoring_system import monitor_mpesa_operation, metrics

class MPesaService:
    
    @monitor_mpesa_operation('stk_push')
    async def initiate_stk_push(self, org_id: int, amount: float, phone: str):
        # Your existing STK Push logic
        pass
    
    @monitor_mpesa_operation('token_refresh')
    async def refresh_access_token(self, org_id: int):
        # Your existing token refresh logic
        pass
```

### Step 3: Deploy the Monitoring Stack

```bash
# Clone the monitoring files
curl -O https://your-repo/docker-compose.monitoring.yml
curl -O https://your-repo/deploy-monitoring.sh

# Set up environment variables
cp .env.monitoring.example .env.monitoring
# Edit .env.monitoring with your configurations

# Deploy the complete stack
chmod +x deploy-monitoring.sh
./deploy-monitoring.sh
```

### Step 4: Configure Alerts

**Set up Slack notifications:**
1. Create a Slack webhook URL
2. Add it to `.env.monitoring`
3. Configure channels in `alertmanager.yml`

**Set up Email alerts:**
1. Configure SMTP settings in `.env.monitoring`
2. Add recipient emails in `alertmanager.yml`

## 📊 Monitoring Dashboards

### System Overview Dashboard
- **Application Health**: Up/down status, response times
- **Request Metrics**: Rate, latency, error rates  
- **M-Pesa API Health**: Success rates, token refresh status
- **Database Performance**: Connection pool, query times
- **Security Events**: Failed logins, suspicious activity

### Organization-Specific Dashboards
Each tenant gets their own dashboard showing:
- Transaction success rates
- Revenue metrics
- API usage vs limits
- Rate limiting status

### Security Dashboard
- Failed authentication attempts
- Cross-tenant access attempts
- Suspicious IP addresses
- Security event trends

## 🚨 Alert Categories

### Critical Alerts (Slack + Email + SMS)
- Application down
- Database connectivity lost
- High error rates (>5%)
- M-Pesa API failures
- Cross-tenant access attempts
- Multiple token refresh failures

### High Priority (Slack + Email)
- High response times (>5 seconds)
- Transaction failure spikes
- Security events
- Authentication failures

### Medium Priority (Slack)
- Resource usage warnings
- Rate limit warnings
- Slow database queries

## 📈 Key Metrics Tracked

### Application Metrics
- `mpesa_mcp_requests_total` - Total HTTP requests
- `mpesa_mcp_request_duration_seconds` - Request latency
- `mpesa_mcp_active_connections` - DB connections

### M-Pesa API Metrics
- `mpesa_api_calls_total` - API call counts
- `mpesa_api_duration_seconds` - API response times
- `mpesa_token_refreshes_total` - Token refresh attempts

### Business Metrics
- `mpesa_transactions_total` - Transaction counts
- `mpesa_revenue_total` - Revenue processed
- `mpesa_rate_limit_hits_total` - Rate limit violations

### Security Metrics
- `mpesa_auth_attempts_total` - Authentication attempts
- `mpesa_cross_tenant_attempts_total` - Cross-tenant access
- `mpesa_security_events_total` - Security incidents

## 🔍 Health Check Endpoints

Your application now provides these monitoring endpoints:

```bash
# Basic health check
GET /health
{
  "status": "healthy",
  "timestamp": "2025-08-18T10:30:00Z",
  "version": "1.0.0"
}

# Detailed health check
GET /health/detailed  
{
  "status": {
    "application": "healthy",
    "database": "healthy", 
    "mpesa_api": "healthy",
    "security": "healthy"
  },
  "checks": {
    "database": {"status": "healthy", "response_time_ms": 45},
    "mpesa_api": {"status": "healthy", "response_time_ms": 1200}
  }
}

# Prometheus metrics
GET /metrics
# Returns Prometheus-formatted metrics

# System overview
GET /metrics/summary
{
  "total_organizations": 25,
  "active_users": 150,
  "transactions_24h": 1250,
  "revenue_24h": 125000.00,
  "success_rate_24h": 98.5
}
```

## 🔧 Custom Monitoring Integration

### Add Custom Metrics

```python
from monitoring_system import metrics

# Custom business metric
def track_subscription_renewal(org_id: str, plan: str):
    metrics.revenue_total.labels(
        organization=org_id,
        currency='KES'
    ).inc(subscription_amounts[plan])

# Custom performance metric  
def track_processing_time(operation: str, org_id: str, duration: float):
    metrics.app_request_duration.labels(
        method='POST',
        endpoint=f'/api/{operation}',
        organization=org_id
    ).observe(duration)
```

### Add Custom Alerts

```python
from monitoring_system import MPesaMonitoring, AlertLevel

async def check_business_rule():
    if suspicious_pattern_detected():
        await monitoring._send_alert(
            AlertLevel.HIGH,
            "Suspicious Business Pattern",
            "Unusual transaction pattern detected",
            {'pattern_type': 'velocity', 'confidence': 0.85}
        )
```

## 📱 Mobile App Integration

Monitor mobile app health by adding app-specific metrics:

```python
# Track mobile app versions
metrics.app_requests_total.labels(
    method='POST',
    endpoint='/api/mobile',
    status='200',
    organization=org_id,
    app_version=request.headers.get('App-Version')
).inc()

# Track mobile-specific errors
if mobile_error:
    metrics.security_events_total.labels(
        event_type='mobile_error',
        severity='medium',
        organization=org_id
    ).inc()
```

## 🔒 Security Monitoring Best Practices

### 1. Multi-Tenant Isolation Monitoring
```python
# Monitor for cross-tenant data access
async def verify_tenant_isolation(user_org: int, requested_org: int):
    if user_org != requested_org:
        await monitoring._send_alert(
            AlertLevel.CRITICAL,
            "Cross-Tenant Access Attempt",
            f"User from org {user_org} tried to access org {requested_org}",
            {'user_org': user_org, 'target_org': requested_org}
        )
```

### 2. Encryption Monitoring
```python
# Monitor encryption operations
def track_encryption_health():
    try:
        test_encrypt_decrypt()
        metrics.security_events_total.labels(
            event_type='encryption_test',
            severity='info',
            organization='system'
        ).inc()
    except Exception:
        # Alert on encryption failures
        pass
```

### 3. Audit Log Integrity
```python
# Verify audit log checksums
async def verify_audit_integrity():
    suspicious_logs = await check_audit_checksums()
    if suspicious_logs:
        await monitoring._send_alert(
            AlertLevel.CRITICAL,
            "Audit Log Tampering Detected",
            f"Found {len(suspicious_logs)} tampered audit entries",
            {'affected_entries': len(suspicious_logs)}
        )
```

## 🎯 Performance Optimization

### Database Query Monitoring
```python
@monitor_database_operation('complex_query')
async def complex_business_query(org_id: int):
    # Your database operation
    # Automatically tracked for performance
    pass
```

### Cache Hit Rate Monitoring
```python
def track_cache_performance(cache_type: str, hit: bool):
    status = 'hit' if hit else 'miss'
    metrics.app_requests_total.labels(
        method='CACHE',
        endpoint=cache_type,
        status=status,
        organization='system'
    ).inc()
```

## 📊 Business Intelligence Features

### Revenue Analytics
- Real-time revenue tracking per organization
- Transaction volume trends
- Success rate analysis
- Peak usage time identification

### Customer Behavior Insights
- API usage patterns
- Transaction frequency analysis
- Feature adoption rates
- Customer churn indicators

### Performance Optimization
- Endpoint response time analysis
- Database query optimization opportunities
- Resource utilization efficiency
- Capacity planning insights

## 🛠️ Troubleshooting Guide

### Common Issues and Solutions

#### 1. Prometheus Metrics Not Showing
```bash
# Check if metrics endpoint is accessible
curl http://localhost:9090/metrics

# Verify monitoring is enabled in config
grep "prometheus_enabled" config.py

# Check monitoring service logs
docker-compose logs mpesa-mcp
```

#### 2. Alerts Not Firing
```bash
# Check AlertManager status
curl http://localhost:9093/api/v1/status

# Verify webhook URLs
grep "SLACK_WEBHOOK" .env.monitoring

# Test alert rules
curl http://localhost:9091/api/v1/rules
```

#### 3. Database Connection Issues
```bash
# Check database connectivity
docker-compose exec postgres pg_isready

# Verify connection pool
curl http://localhost:5000/health/detailed

# Check monitoring database queries
docker-compose logs postgres | grep monitoring
```

#### 4. High Memory Usage
```bash
# Check container memory usage
docker stats

# Analyze memory patterns
curl http://localhost:9090/metrics | grep memory

# Optimize monitoring intervals
# Edit prometheus.yml scrape_interval
```

## 🎛️ Advanced Configuration

### Custom Alert Rules

Create custom alerts in `monitoring/prometheus/custom-alerts.yml`:

```yaml
groups:
- name: custom_business_alerts
  rules:
  - alert: LowDailyRevenue
    expr: sum(rate(mpesa_revenue_total[24h])) < 10000
    for: 1h
    labels:
      severity: medium
    annotations:
      summary: "Daily revenue below threshold"
      description: "Daily revenue is {{ $value }} KES, below 10,000 KES threshold"

  - alert: UnusualTransactionPattern
    expr: rate(mpesa_transactions_total[5m]) > avg_over_time(rate(mpesa_transactions_total[5m])[24h]) * 3
    for: 2m
    labels:
      severity: high
    annotations:
      summary: "Unusual transaction volume spike"
      description: "Transaction rate is 3x higher than 24h average"
```

### Custom Dashboard Panels

Add to Grafana dashboard JSON:

```json
{
  "id": 100,
  "title": "Revenue by Organization",
  "type": "bargauge",
  "targets": [
    {
      "expr": "sum by (organization) (rate(mpesa_revenue_total[24h]))",
      "legendFormat": "{{organization}}"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "unit": "currencyKES"
    }
  }
}
```

### Multi-Environment Support

Configure different environments in `docker-compose.yml`:

```yaml
# Production environment
services:
  mpesa-mcp-prod:
    environment:
      - ENVIRONMENT=production
      - MPESA_ENVIRONMENT=production
      - LOG_LEVEL=INFO
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.mpesa-prod.rule=Host(`api.mpesa-mcp.com`)"

# Staging environment  
  mpesa-mcp-staging:
    environment:
      - ENVIRONMENT=staging
      - MPESA_ENVIRONMENT=sandbox
      - LOG_LEVEL=DEBUG
```

## 📋 Maintenance Tasks

### Daily Tasks
- [ ] Review critical alerts from last 24 hours
- [ ] Check system health dashboard
- [ ] Verify backup completion
- [ ] Monitor transaction success rates

### Weekly Tasks
- [ ] Analyze performance trends
- [ ] Review security events
- [ ] Update alert thresholds if needed
- [ ] Check disk space and cleanup old logs

### Monthly Tasks
- [ ] Review and optimize alert rules
- [ ] Analyze business metrics trends
- [ ] Update monitoring dashboards
- [ ] Performance optimization review
- [ ] Security audit of monitoring system

## 🔐 Security Hardening

### Secure Monitoring Access
```yaml
# Add authentication to Prometheus
command:
  - '--web.config.file=/etc/prometheus/web.yml'
# Create web.yml with basic auth

# Secure Grafana
environment:
  - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_SECURE_PASSWORD}
  - GF_USERS_ALLOW_SIGN_UP=false
  - GF_AUTH_ANONYMOUS_ENABLED=false
```

### Network Security
```yaml
# Restrict network access
networks:
  monitoring:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

services:
  prometheus:
    networks:
      - monitoring
    # No external ports in production
```

### Secrets Management
```bash
# Use Docker secrets for sensitive data
echo "secure_password" | docker secret create grafana_password -
echo "webhook_url" | docker secret create slack_webhook -

# Reference in docker-compose.yml
secrets:
  - grafana_password
  - slack_webhook
```

## 🚀 Production Deployment

### Pre-deployment Checklist
- [ ] All environment variables configured
- [ ] Slack/Email notifications tested
- [ ] Database connection verified
- [ ] SSL certificates installed
- [ ] Firewall rules configured
- [ ] Backup strategy implemented
- [ ] Monitoring system tested end-to-end

### Deployment Command
```bash
# Production deployment
docker-compose -f docker-compose.monitoring.yml \
               -f docker-compose.prod.yml \
               --env-file .env.production \
               up -d

# Verify deployment
./scripts/verify-deployment.sh
```

### Health Check Script
```bash
#!/bin/bash
# File: scripts/verify-deployment.sh

echo "🔍 Verifying M-Pesa MCP Monitoring Deployment..."

# Check service health
services=("mpesa-mcp" "prometheus" "grafana" "alertmanager")
for service in "${services[@]}"; do
    if docker-compose ps $service | grep -q "Up"; then
        echo "✅ $service: Running"
    else
        echo "❌ $service: Not running"
        exit 1
    fi
done

# Test endpoints
endpoints=(
    "http://localhost:5000/health:Application"
    "http://localhost:9091:Prometheus" 
    "http://localhost:3000:Grafana"
    "http://localhost:9093:AlertManager"
)

for endpoint in "${endpoints[@]}"; do
    url=$(echo $endpoint | cut -d: -f1-2)
    name=$(echo $endpoint | cut -d: -f3)
    
    if curl -s $url > /dev/null; then
        echo "✅ $name: Accessible"
    else
        echo "❌ $name: Not accessible"
        exit 1
    fi
done

echo "🎉 All systems operational!"
```

## 📞 Support and Troubleshooting

### Log Locations
```bash
# Application logs
docker-compose logs -f mpesa-mcp

# Monitoring system logs
docker-compose logs -f prometheus grafana alertmanager

# System metrics
curl http://localhost:9090/api/v1/query?query=up

# Recent alerts
curl http://localhost:9093/api/v1/alerts
```

### Performance Tuning

#### Prometheus Optimization
```yaml
# Reduce retention for high-cardinality metrics
global:
  scrape_interval: 30s  # Increase from 15s
  evaluation_interval: 30s

# Optimize storage
command:
  - '--storage.tsdb.retention.time=15d'  # Reduce from 200h
  - '--storage.tsdb.retention.size=10GB'
```

#### Database Optimization
```sql
-- Add indexes for monitoring queries
CREATE INDEX CONCURRENTLY idx_audit_logs_monitoring 
ON audit_logs(created_at, action, organization_id) 
WHERE created_at > NOW() - INTERVAL '7 days';

-- Partition large tables
CREATE TABLE audit_logs_y2025m08 PARTITION OF audit_logs
FOR VALUES FROM ('2025-08-01') TO ('2025-09-01');
```

### Scaling Considerations

#### Horizontal Scaling
```yaml
# Scale monitoring components
services:
  prometheus:
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '2'
          memory: 4G

  grafana:
    deploy:
      replicas: 2
```

#### Monitoring Data Retention
```yaml
# Configure data retention policies
prometheus:
  command:
    - '--storage.tsdb.retention.time=30d'
    - '--storage.tsdb.retention.size=50GB'

# Automated cleanup job
cleanup:
  image: alpine:latest
  command: |
    sh -c "while true; do
      find /data -name '*.log' -mtime +7 -delete
      sleep 86400
    done"
```

## 🎯 Next Steps

After deploying your monitoring system:

1. **📊 Set up custom dashboards** for your specific business metrics
2. **🔔 Configure alert recipients** and test notification channels  
3. **📈 Establish baseline metrics** for performance optimization
4. **🔒 Implement security monitoring rules** specific to your threat model
5. **📱 Add mobile app monitoring** if you have mobile clients
6. **🔄 Set up automated testing** of monitoring system health
7. **📚 Train your team** on using the monitoring tools

## 🆘 Emergency Procedures

### Critical System Down
1. Check application health: `curl http://localhost:5000/health`
2. Review recent alerts in Slack/Email
3. Check system resources: `docker stats`
4. Review application logs: `docker-compose logs --tail=100 mpesa-mcp`
5. Escalate to development team with monitoring data

### Data Breach Suspected  
1. Check security dashboard immediately
2. Review audit logs for suspicious activity
3. Monitor cross-tenant access attempts
4. Verify encryption system integrity
5. Document findings for forensic analysis

### Performance Degradation
1. Check response time metrics in Grafana
2. Analyze database connection pool status
3. Review M-Pesa API latency trends
4. Check system resource utilization
5. Identify bottlenecks and optimize

---

## 📝 Configuration Summary

Your monitoring system includes:

- **✅ Real-time application monitoring** with automatic failover detection
- **✅ Multi-tenant security monitoring** with breach prevention  
- **✅ Business intelligence dashboards** with revenue and transaction analytics
- **✅ Critical alerting system** with Slack, Email, and SMS notifications
- **✅ Performance optimization insights** for database and API optimization
- **✅ Comprehensive health checks** for all system components
- **✅ Scalable architecture** supporting growth and high availability

**🎉 Your M-Pesa MCP server now has enterprise-grade monitoring and alerting!**
