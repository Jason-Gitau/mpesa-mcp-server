

## **Critical Files Needed:**

### **1. Core Application Files**
- `main.py` - To understand the Flask app initialization and startup process
- `config.py` - Configuration management and environment variables
- `requirements.txt` or `pyproject.toml` - Current dependencies

### **2. Service Layer Files**
- `services/mpesa_service.py` - M-Pesa API interactions and error patterns
- `services/auth_service.py` - Authentication logic and failure points
- `services/audit_service.py` - Current audit logging implementation

### **3. Database Layer Files**
- `models/organization.py` - Organization operations and rate limiting
- `models/transaction.py` - Transaction models and status tracking
- `models/user.py` - User management operations
- `utils/database.py` - Database connection handling

### **4. Route Files**
- `routes/mpesa_routes.py` - M-Pesa endpoints and error handling
- `routes/auth_routes.py` - Authentication endpoints
- `routes/admin_routes.py` - Admin operations
- `routes/callback_routes.py` - M-Pesa callback handlers

### **5. Infrastructure Files**
- Any existing `docker-compose.yml` or Dockerfile
- Database schema/migration files
- Current logging configuration
- Environment configuration files (`.env` template)

### **6. MCP Integration Files**
- `mcp/server.py` - MCP protocol implementation

## **Monitoring Strategy Based on Your Architecture:**

Given your multi-tenant, security-focused system, the monitoring will need to track:

### **Application-Level Metrics:**
- Multi-tenant isolation integrity
- M-Pesa API success/failure rates per organization
- JWT token validation failures
- Rate limiting violations per tenant
- Cross-tenant access attempts (security alerts)

### **Business-Level Metrics:**
- Transaction success rates by organization
- Revenue per tenant
- API usage against subscription limits
- Failed payment patterns

### **Security Monitoring:**
- Database query patterns for suspicious activity
- Failed authentication attempts
- Encryption/decryption operations
- Audit log integrity checks

### **Infrastructure Monitoring:**
- Database connection pool health
- Memory usage (important for JWT caching)
- Network latency to M-Pesa APIs
- Disk space for audit logs

## **Next Steps:**

Could you please share the key files listed above? This will allow me to:

1. **Analyze your current error handling patterns**
2. **Understand your logging structure**
3. **Identify critical monitoring points**
4. **Design tenant-aware alerting**
5. **Create security-focused dashboards**
6. **Implement proper health checks**

Once I have these files, I can create a comprehensive monitoring and alerting system that includes:

- **Prometheus metrics collection**
- **Grafana dashboards** (tenant-specific views)
- **AlertManager configuration** for critical issues
- **Security incident detection**
- **Business intelligence monitoring**
- **Multi-tenant aware health checks**

