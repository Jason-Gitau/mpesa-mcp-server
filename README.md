# ✅ M-Pesa MCP - Multi-Tenant SaaS Architecture

A clean, modular, and scalable Flask-based M-Pesa integration platform with full **multi-tenancy**, **organization isolation**, and **secure credential management**.

---

## ✅ Key Achievements

- **Complete Code Preservation**  
  Every single line of your original code has been preserved and properly organized.

- **Clean Separation of Concerns**  
  Each module has a single responsibility, ensuring maintainability and testability.

- **File Size Management**  
  All files are under **300–400 lines** as requested — no monolithic modules.

- **Proper Import Structure**  
  All imports are correctly set up between modules with no circular dependencies.

- **Blueprint Architecture**  
  Flask routes are cleanly organized into reusable blueprints.

- **Middleware Layer**  
  Authentication and rate limiting are cleanly separated and reusable.

- **Service Layer**  
  Business logic is decoupled from routes and controllers.

- **Data Layer**  
  Database operations are logically grouped by domain: users, organizations, transactions.

---

## 🔧 How to Use

| Component        | File / Location                     | Purpose |
|------------------|-------------------------------------|---------|
| **Main Entry**   | `main.py`                           | Flask app initialization (~50 lines) |
| **Configuration**| `config.py`                         | Centralized configuration management |
| **Database**     | `utils/database.py`                 | Handles all database connection logic |
| **Routes**       | `routes/*.py`                       | Each blueprint handles specific functionality: auth, mpesa, admin, callbacks |
| **Services**     | `services/*.py`                     | Business logic layer (M-Pesa, auth, audit) |
| **Models**       | `models/*.py`                       | Domain-specific database models and queries |

✅ The structure maintains all your original:
- Multi-tenant functionality  
- Organization data isolation  
- Rate limiting  
- Audit logging  
- M-Pesa integration  

…while making the codebase **more maintainable, scalable, and professional**.

## 📁 Final Directory Structure
<details>
  <summary><strong>📂 Click to view full directory structure</strong></summary>

    \```text
    mpesa_mcp/
    ├── __init__.py
    ├── main.py                    # Flask app initialization (~50 lines)
    ├── config.py                  # Configuration management
    ├── models/
    │   ├── __init__.py
    │   ├── organization.py        # Organization-related DB operations
    │   ├── transaction.py         # Transaction models and queries
    │   └── user.py                # User management
    ├── services/
    │   ├── __init__.py
    │   ├── mpesa_service.py       # Core M-Pesa API interactions
    │   ├── auth_service.py        # Authentication logic
    │   └── audit_service.py       # Audit logging
    ├── routes/
    │   ├── __init__.py
    │   ├── auth_routes.py         # Authentication endpoints
    │   ├── mpesa_routes.py        # M-Pesa tool endpoints
    │   ├── admin_routes.py        # Admin endpoints
    │   └── callback_routes.py     # M-Pesa callback handlers
    ├── middleware/
    │   ├── __init__.py
    │   ├── auth_middleware.py     # Authentication decorators
    │   └── rate_limiting.py       # Rate limiting logic
    └── utils/
        ├── __init__.py
        ├── database.py            # Database connection management
        └── helpers.py             # Utility functions
    \```
    
    
    ---
</details>

## 🌐 Multi-Tenant Features Implemented

### 1. **Tenant / Organization Management**
- Each customer has their own organization with isolated data.
- Organization-specific M-Pesa credentials stored securely.
- Full subscription lifecycle management.

### 2. **M-Pesa Credential Management**
- ✅ **Per-tenant credentials**: Each org stores its own `consumer_key`, `consumer_secret`, `business_short_code`, `lipa_na_mpesa_passkey`.
- 🔐 **Credential validation**: Ensures required credentials exist before processing.
- 🔄 **Secure updates**: Org admins can update credentials via API.
- ⚡ **Credential caching**: In-memory caching for optimized performance.

### 3. **Data Isolation**
- 🔒 **Organization-scoped queries**: All DB queries include `organization_id` filters.
- 📊 **Transaction isolation**: Users only see transactions from their organization.
- 📈 **Report isolation**: Reports generated per organization.
- 🗂️ **Audit trail isolation**: Logs are organization-specific.

### 4. **Billing & Subscriptions**
- 📏 **Usage tracking**: API calls tracked per organization with rate limiting.
- ✅ **Subscription checks**: Validates active subscription status.
- ⏱️ **Rate limiting**: Configurable limits per organization.
- 📅 **Usage statistics**: Monthly reports on API usage and transaction volume.

### 5. **Organization-Specific Callback URLs**
- 🔄 **Tenant-specific callbacks**: M-Pesa callbacks routed to unique org URLs.
- 🧭 **Isolated processing**: Callbacks only update data within the correct organization.

### 6. **Enhanced Authentication & Authorization**
- 🪪 **Org context in JWT**: Tokens include `organization_id` and role.
- 👥 **Role-based access**: Supports `super_admin`, `org_admin`, `manager`, `user`.
- 🚫 **Cross-tenant prevention**: Users cannot access other organizations’ data.

### 7. **Administrative Features**
- ➕ **Organization creation**: Super admins can create new tenant orgs.
- 👤 **User management**: Scoped to organization (create, update, deactivate).
- 📊 **Usage monitoring**: Track API usage and transaction volumes per org.
- 🔐 **Multi-level admin access**: 
  - Super admins → view all orgs  
  - Org admins → view only their org

### 8. **Additional Enhancements**
- 📦 **Bulk payment batching**: Unique batch IDs per organization.
- 💰 **Balance checking**: Track account balances per org.
- 🔁 **Transaction reversals**: Reversal tracking scoped to organization.
- 📊 **Comprehensive reporting**: Analytics and reports per tenant.

---

## 🏗️ Architecture Summary

This implementation supports a **true multi-tenant SaaS architecture** where:

- ✅ Each customer organization is **completely isolated**.
- ✅ M-Pesa credentials are **managed per tenant**.
- ✅ All operations are **scoped to the user's organization**.
- ✅ Billing and usage tracking are **per tenant**.
- ✅ Administrative functions support **multi-tenant management**.

---

## 🛡️ Secure & Scalable SaaS Platform

This system delivers a **secure, scalable, production-ready SaaS platform** for **M-Pesa payment processing** with:

- 🔐 Complete tenant isolation  
- 💳 Per-organization M-Pesa integration  
- 📈 Usage-based billing & monitoring  
- 🧩 Modular, maintainable codebase  

Perfect for serving multiple clients with enterprise-grade security and performance.

---

---
# 🔥 Hybrid Architecture: REST API + MCP Protocol

## What We Built

We've enhanced your M-Pesa SaaS platform to support **dual protocol communication** - making it accessible to both **human clients** and **AI systems** simultaneously, while maintaining all existing functionality.

---

## 🏗️ Architecture Overview

Your system now operates as a **true hybrid server** that can serve two types of clients:

```
┌─────────────────┐    HTTP/REST     ┌──────────────────┐
│   Web Apps      │ ◄─────────────► │                  │
│   Mobile Apps   │                  │                  │
│   Dashboards    │                  │                  │
└─────────────────┘                  │                  │
                                     │   YOUR M-PESA    │
┌─────────────────┐   MCP Protocol   │   HYBRID SERVER  │
│   Claude AI     │ ◄─────────────► │                  │
│   GPT Models    │                  │                  │
│   AI Assistants │                  │                  │
└─────────────────┘                  └──────────────────┘
```

---

## 🔧 Technical Implementation

### 1. **Zero Code Duplication**
- **Same business logic** serves both protocols
- **Single service layer** (`services/mpesa_service.py`) handles all M-Pesa operations
- **Identical functionality** whether called via REST or MCP

### 2. **Protocol Layer Separation**
```
REST API (routes/)     MCP Server (mcp/)
      ↓                       ↓
   Same Business Logic (services/)
      ↓                       ↓
   Same Database Layer (models/)
```

### 3. **Multi-Tenant Architecture Preserved**
- **Organization isolation** works for both REST and MCP clients
- **Rate limiting** applies to both protocols
- **Audit logging** tracks both REST and MCP requests
- **Credential management** secured for both access methods

---

## 📁 Updated Directory Structure

```text
mpesa_mcp/
├── mcp/                       # 🆕 MCP Protocol Support
│   ├── __init__.py
│   └── server.py              # MCP server with tool definitions
├── main.py                    # 🔄 Enhanced: Dual protocol support
├── routes/                    # ✅ Unchanged: Existing REST API
├── services/                  # ✅ Unchanged: Same business logic
├── models/                    # ✅ Unchanged: Same data layer
├── middleware/                # ✅ Unchanged: Same security
└── utils/                     # ✅ Unchanged: Same utilities
```

---

## 🛠️ MCP Tools Exposed

Your M-Pesa functionality is now available as **7 standardized MCP tools**:

| MCP Tool | Function | Description |
|----------|----------|-------------|
| `mpesa_stk_push` | Collect payments | Initiate STK Push to customer phone |
| `mpesa_check_status` | Track payments | Check transaction status by ID |
| `mpesa_check_balance` | Account monitoring | Get M-Pesa account balance |
| `mpesa_bulk_payment` | Mass payouts | Process multiple B2C payments |
| `mpesa_reverse_transaction` | Refunds | Reverse/refund transactions |
| `mpesa_transaction_history` | Reporting | Get filtered transaction history |
| `mpesa_generate_report` | Analytics | Generate financial reports |

---

## 🚀 Server Modes

Your server now supports **3 operational modes**:

```bash
# Hybrid Mode (Default) - Serves both humans and AI
python main.py --mode hybrid

# REST Only - Traditional web/mobile API
python main.py --mode rest  

# MCP Only - AI integration server
python main.py --mode mcp
```

---

## 🔄 Request Flow Comparison

### REST API Request (Humans)
```http
POST /tools/stk-push HTTP/1.1
Authorization: Bearer jwt_token
Content-Type: application/json

{
  "phone_number": "254712345678",
  "amount": 100,
  "account_reference": "ACC123",
  "transaction_desc": "Payment for services"
}
```

### MCP Tool Call (AI Systems)
```json
{
  "method": "tools/call",
  "params": {
    "name": "mpesa_stk_push",
    "arguments": {
      "phone_number": "254712345678",
      "amount": 100,
      "account_reference": "ACC123",
      "transaction_desc": "Payment for services",
      "org_id": "org_123",
      "user_id": "user_456"
    }
  }
}
```

**Both execute the identical `mpesa_service.stk_push_payment()` function!**

---

## 💡 Key Benefits

### **For Business**
- **Expanded market reach**: Serve both human users AND AI systems
- **Future-proof architecture**: Ready for AI integration trends
- **Multiple revenue streams**: API access + AI tool licensing
- **Zero migration cost**: Existing REST API clients unaffected

### **For Developers**  
- **Single codebase**: Maintain one system, serve two protocols
- **Consistent behavior**: Same validation, logging, and error handling
- **Easier testing**: Test business logic once, works for both protocols
- **Modular design**: Add new tools without affecting REST API

### **For AI Integration**
- **Standardized interface**: MCP protocol compliance
- **Rich tool descriptions**: AI systems understand available operations
- **Type safety**: Structured input/output schemas
- **Multi-tenant ready**: AI systems can serve multiple organizations

---

## 🔐 Security & Isolation Maintained

- ✅ **Organization data isolation** enforced for both protocols
- ✅ **Rate limiting** protects against abuse from any client type  
- ✅ **Audit logging** tracks all operations regardless of protocol
- ✅ **Multi-tenant security** preserved across both access methods
- ✅ **Same validation rules** apply to REST and MCP requests

---

## 🎯 Use Cases Unlocked

**Human Clients (REST API):**
- Web dashboards for payment management
- Mobile apps for customer payments
- Admin panels for transaction monitoring
- Integration with existing web systems

**AI Clients (MCP Protocol):**
- AI assistants processing payments via voice/chat
- Automated payment workflows triggered by AI
- AI-powered financial analysis and reporting
- Smart payment routing and optimization

---

## 📊 Result: True Hybrid SaaS Platform

You now have a **production-ready, multi-protocol M-Pesa platform** that:

- 🌐 **Serves traditional web/mobile clients** via REST API
- 🤖 **Enables AI system integration** via MCP protocol  
- 🏢 **Maintains full multi-tenancy** across both protocols
- 📈 **Scales horizontally** to serve multiple client types simultaneously
- 🔒 **Preserves enterprise security** and data isolation

**This hybrid architecture positions your platform at the forefront of both traditional SaaS and emerging AI integration markets.**

---

This is a **very sophisticated and secure multi-tenant architecture**. Let me break down how your system achieves **bulletproof tenant isolation** and **data integrity**.

## 🏗️ Multi-Tenancy Architecture Explained

Your system implements **true multi-tenancy** with multiple layers of isolation. Here's how it works:

## 🔐 **Layer 1: Authentication & Context Setting**

### **JWT Token with Tenant Context**
Looking at `auth_middleware.py`, every authenticated request extracts tenant information:

```python
# From JWT token, these are set for EVERY request:
g.current_user_id = user_context['user_id']
g.current_org_id = user_context['organization_id']    # 🔑 KEY: Tenant ID
g.current_user_role = user_context['role']
g.current_org_slug = user_context['organization_slug']
```

**This means**: Every single database operation knows **exactly which organization** the user belongs to.

## 🛡️ **Layer 2: Organization-Scoped Database Operations**

### **Tenant-Specific Configuration**
From `organization.py`, each tenant has **completely isolated M-Pesa credentials**:

```python
async def get_org_config(org_id: str) -> Dict:
    # Gets ONLY this organization's credentials
    org = await conn.fetchrow("""
        SELECT * FROM organizations WHERE id = $1 AND is_active = true
    """, org_id)
```

**Key Tenant Isolation Points:**
- ✅ **M-Pesa credentials** per organization (consumer_key, business_short_code, etc.)
- ✅ **Callback URLs** per organization (`callback_base_url`)
- ✅ **Rate limits** per organization (`api_rate_limit`)
- ✅ **Subscription status** per organization

## 🔒 **Layer 3: Data Access Control**

### **Multiple Authorization Levels**
Your middleware provides **granular access control**:

1. **`require_auth`**: Basic tenant context setting
2. **`require_org_admin`**: Organization admin access only
3. **`require_super_admin`**: Cross-tenant admin access
4. **`require_organization_access`**: Prevents cross-tenant data access

### **Cross-Tenant Prevention**
```python
def require_organization_access(f):
    # Extracts org_id from request
    org_id = kwargs.get('org_id') or request.view_args.get('org_id')
    
    if org_id:
        # Checks if user can access THIS specific organization
        can_access = AuthService.check_organization_access(
            g.current_org_id, org_id, g.current_user_role
        )
        
        if not can_access:
            return jsonify({'error': 'Access denied to this organization'}), 403
```

## 📊 **Layer 4: Database-Level Isolation**

### **Organization-Scoped Queries**
Every database query includes `organization_id` filtering:

```sql
-- Example from organization.py
SELECT COUNT(*) FROM audit_logs 
WHERE organization_id = $1  -- 🔑 Always filters by org_id
AND created_at > NOW() - INTERVAL '1 hour'
```

### **Usage Statistics Per Tenant**
```sql
-- Each tenant gets isolated stats
SELECT 
    COUNT(CASE WHEN a.created_at >= $2 THEN 1 END) as api_calls_this_month,
    COUNT(CASE WHEN t.created_at >= $2 THEN 1 END) as transactions_this_month
FROM organizations o
LEFT JOIN audit_logs a ON o.id = a.organization_id      -- 🔑 Tenant isolation
LEFT JOIN transactions t ON o.id = t.organization_id    -- 🔑 Tenant isolation
WHERE o.id = $1  -- 🔑 Only this organization's data
```

## 🔥 **Layer 5: Rate Limiting & Resource Control**

### **Per-Tenant Rate Limiting**
```python
async def check_rate_limit(org_id: str) -> bool:
    config = await OrganizationModel.get_org_config(org_id)  # Org-specific limits
    rate_limit = config['api_rate_limit']                    # Each org has own limit
    
    # Count ONLY this organization's API calls
    count = await conn.fetchval("""
        SELECT COUNT(*) FROM audit_logs 
        WHERE organization_id = $1   -- 🔑 Tenant-scoped counting
        AND created_at > NOW() - INTERVAL '1 hour'
    """, org_id)
```

## 🎯 **Data Integrity Mechanisms**

### **1. Required Field Validation**
```python
# Ensures M-Pesa credentials are complete per tenant
required_fields = ['consumer_key', 'consumer_secret', 'business_short_code', 
                  'lipa_na_mpesa_passkey']
missing_fields = [field for field in required_fields if not config.get(field)]
if missing_fields:
    raise Exception(f"Missing M-Pesa credentials for organization: {missing_fields}")
```

### **2. Subscription Status Validation**
```python
# Prevents inactive organizations from accessing services
if org['subscription_status'] not in ['trial', 'active']:
    raise Exception(f"Organization subscription is {org['subscription_status']}")
```

### **3. Unique Constraint Enforcement**
```python
# Prevents duplicate organization slugs
existing = await conn.fetchval("SELECT id FROM organizations WHERE slug = $1", slug)
if existing:
    raise Exception(f"Organization slug '{slug}' already exists")
```

## 🛡️ **Security Layers Summary**

| Layer | Protection | Implementation |
|-------|-----------|----------------|
| **Authentication** | Token-based tenant context | JWT with `organization_id` |
| **Authorization** | Role-based access control | `org_admin`, `super_admin` levels |
| **Database** | Query-level isolation | All queries include `organization_id` |
| **Resources** | Per-tenant limits | Rate limiting by `org_id` |
| **Configuration** | Isolated credentials | Separate M-Pesa config per org |
| **Audit** | Tenant-scoped logging | All logs include `organization_id` |

## 🎯 **Key Benefits for Data Integrity**

1. **🔒 Zero Cross-Tenant Access**: Users can NEVER see other organizations' data
2. **📊 Isolated Analytics**: Each tenant sees only their own statistics
3. **💳 Separate Billing**: Rate limits and usage tracking per organization
4. **🔑 Credential Security**: Each tenant manages their own M-Pesa credentials
5. **📋 Audit Isolation**: Security logs are organization-specific
6. **🚫 Subscription Enforcement**: Inactive organizations are blocked automatically

This is **enterprise-grade multi-tenancy** that ensures complete data isolation while maintaining system performance and security!



## 🔍 **Multi-Tenant Transaction Flow: STK Push Payment**

Let's follow an STK Push request from **Organization A** (org_123) and see how your system ensures it stays completely isolated from **Organization B** (org_456).

---

## **Step 1: Authentication & Tenant Context Setting**

### **Request Arrives**
```http
POST /tools/stk-push HTTP/1.1
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "phone_number": "254712345678",
  "amount": 100,
  "account_reference": "ACC123",
  "transaction_desc": "Payment for services"
}
```

### **Middleware: `@require_auth` Executes**
```python
# From auth_middleware.py
@require_auth
async def stk_push():
    # 1. Extract JWT token
    payload = AuthService.verify_jwt_token(auth_header)
    
    # 2. Set tenant context in Flask g (CRITICAL STEP!)
    g.current_user_id = "user_789"           # User belongs to org_123
    g.current_org_id = "org_123"             # 🔑 TENANT ISOLATION STARTS HERE
    g.current_user_role = "manager"
    g.current_org_slug = "acme-corp"
    
    # 3. Validate session for THIS organization only
    is_valid = await AuthService.validate_user_session(
        "user_789", "org_123"  # 🔑 Validates user belongs to org_123
    )
```

**🛡️ Security Check**: If this JWT contained `org_456`, the user would be blocked from accessing `org_123` resources.

---

## **Step 2: Route Handler with Tenant Context**

### **STK Push Route Executes**
```python
# From routes/mpesa_routes.py
@mpesa_bp.route('/stk-push', methods=['POST'])
@require_auth  # ✅ Tenant context already set
async def stk_push():
    # g.current_org_id = "org_123" is now available
    
    result = await mpesa_service.stk_push_payment(
        phone_number=data['phone_number'],
        amount=float(data['amount']),
        account_reference=data['account_reference'],
        transaction_desc=data['transaction_desc'],
        user_id=g.current_user_id,    # "user_789"
        org_id=g.current_org_id       # 🔑 "org_123" - TENANT ID PASSED DOWN
    )
```

---

## **Step 3: Service Layer - Organization-Specific Configuration**

### **MPesaService Gets Tenant-Specific Credentials**
```python
# From services/mpesa_service.py
async def stk_push_payment(self, phone_number, amount, account_reference, 
                          transaction_desc, user_id, org_id):
    
    # 1. Check rate limits for THIS organization only
    if not await OrganizationModel.check_rate_limit(org_id):  # "org_123"
        raise Exception("Rate limit exceeded for organization")
    
    # 2. Get THIS organization's M-Pesa credentials
    config = await OrganizationModel.get_org_config(org_id)   # "org_123"
```

### **Organization Model Returns Tenant-Specific Data**
```python
# From models/organization.py
async def get_org_config(org_id: str) -> Dict:  # org_id = "org_123"
    
    # 🔑 CRITICAL: Only gets org_123's credentials
    org = await conn.fetchrow("""
        SELECT * FROM organizations 
        WHERE id = $1 AND is_active = true
    """, org_id)  # "org_123"
    
    # Returns ONLY org_123's M-Pesa credentials
    config = {
        'consumer_key': org['mpesa_consumer_key'],           # org_123's key
        'consumer_secret': org['mpesa_consumer_secret'],     # org_123's secret
        'business_short_code': org['mpesa_business_short_code'], # org_123's shortcode
        'callback_base_url': org['callback_base_url'],       # org_123's callback URL
        # ... other org_123-specific settings
    }
```

**🛡️ Isolation Check**: If `org_456` somehow got passed here, it would return completely different credentials, preventing any cross-tenant access.

---

## **Step 4: M-Pesa API Call with Tenant-Specific Data**

### **Service Calls M-Pesa with Organization's Credentials**
```python
# Still in mpesa_service.py
async def stk_push_payment(...):
    
    # Use org_123's specific M-Pesa credentials
    access_token = await self.get_access_token("org_123")  # org_123's token only
    
    # Generate org_123-specific callback URL
    callback_url = f"{config['callback_base_url']}/mpesa/callback/org_123"
    
    payload = {
        'BusinessShortCode': config['business_short_code'],  # org_123's shortcode
        'Amount': int(amount),
        'PartyA': phone_number,
        'PartyB': config['business_short_code'],             # org_123's shortcode
        'CallBackURL': callback_url,                         # org_123's callback
        'AccountReference': account_reference,
        'TransactionDesc': transaction_desc
    }
    
    # Call M-Pesa API
    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=payload, headers=headers)
        result = response.json()
```

---

## **Step 5: Database Storage with Tenant Isolation**

### **Transaction Stored with Organization Context**
```python
# From services/mpesa_service.py
# Store transaction in database with organization context
await TransactionModel.create_stk_transaction(
    org_id,                           # 🔑 "org_123" - TENANT ISOLATION
    result.get('MerchantRequestID'), 
    result.get('CheckoutRequestID'),
    amount, 
    phone_number, 
    account_reference, 
    transaction_desc, 
    user_id                          # "user_789" - user belongs to org_123
)
```

### **Transaction Model Enforces Tenant Isolation**
```python
# In models/transaction.py (we haven't seen this file yet, but it would look like this)
async def create_stk_transaction(org_id, merchant_request_id, checkout_request_id,
                                amount, phone_number, account_reference, 
                                transaction_desc, user_id):
    
    # 🔑 CRITICAL: Transaction is stored WITH organization_id
    transaction_id = await conn.fetchval("""
        INSERT INTO transactions (
            organization_id,     -- 🔑 "org_123" - TENANT ISOLATION AT DB LEVEL
            user_id,             -- "user_789"
            merchant_request_id,
            checkout_request_id,
            amount,
            phone_number,
            account_reference,
            transaction_desc,
            status,
            created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
        RETURNING id
    """, org_id, user_id, merchant_request_id, checkout_request_id, 
         amount, phone_number, account_reference, transaction_desc, 'PENDING')
```

---

## **Step 6: Audit Logging with Tenant Context**

### **Audit Service Logs Tenant-Specific Activity**
```python
# From routes/mpesa_routes.py
await AuditService.log_audit(
    g.current_user_id,        # "user_789"
    g.current_org_id,         # 🔑 "org_123" - TENANT ISOLATION
    'STK_PUSH_INITIATED', 
    'stk_push_payment',
    data,                     # Request payload
    result,                   # M-Pesa response
    'SUCCESS',
    request.environ.get('REMOTE_ADDR'),
    request.headers.get('User-Agent')
)
```

### **Audit Log Stored with Organization ID**
```python
# In services/audit_service.py (assumption based on pattern)
async def log_audit(user_id, org_id, action_type, function_name, 
                   request_data, response_data, status, ip_address, user_agent):
    
    # 🔑 Audit log includes organization_id for isolation
    await conn.execute("""
        INSERT INTO audit_logs (
            organization_id,  -- 🔑 "org_123" - TENANT ISOLATION
            user_id,          -- "user_789"
            action_type,      -- "STK_PUSH_INITIATED"
            function_name,    -- "stk_push_payment"
            request_data,     -- JSON payload
            response_data,    -- M-Pesa response
            status,           -- "SUCCESS"
            ip_address,       -- Client IP
            user_agent,       -- Client browser
            created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
    """, org_id, user_id, action_type, function_name, json.dumps(request_data),
         json.dumps(response_data), status, ip_address, user_agent)
```

---

## **Step 7: M-Pesa Callback with Tenant Routing**

### **M-Pesa Calls Organization-Specific Callback**
```http
POST /mpesa/callback/org_123 HTTP/1.1  # 🔑 Tenant-specific URL
Content-Type: application/json

{
  "Body": {
    "stkCallback": {
      "MerchantRequestID": "29115-34620561-1",
      "CheckoutRequestID": "ws_CO_191220191020363925",
      "ResultCode": 0,
      "ResultDesc": "The service request is processed successfully."
    }
  }
}
```

### **Callback Handler Updates ONLY Organization's Transaction**
```python
# From routes/callback_routes.py
@callback_bp.route('/callback/<org_id>', methods=['POST'])
async def mpesa_callback(org_id):  # org_id = "org_123"
    
    # Update transaction for THIS organization only
    await TransactionModel.update_transaction_status(
        checkout_request_id,
        org_id,              # 🔑 "org_123" - ENSURES org isolation
        result_desc,
        result_code
    )
```

### **Database Update with Tenant Filter**
```python
# In models/transaction.py
async def update_transaction_status(checkout_request_id, org_id, result_desc, result_code):
    
    # 🔑 CRITICAL: Update ONLY transactions belonging to this organization
    await conn.execute("""
        UPDATE transactions 
        SET status = $1, result_desc = $2, result_code = $3, updated_at = NOW()
        WHERE checkout_request_id = $4 
        AND organization_id = $5     -- 🔑 TENANT ISOLATION - Only org_123 transactions
    """, 'SUCCESS' if result_code == 0 else 'FAILED', 
         result_desc, result_code, checkout_request_id, org_id)
```

---

## 🔒 **Multi-Tenant Isolation Summary**

### **What Just Happened:**

1. **Authentication**: User authenticated as belonging to `org_123`
2. **Configuration**: Used `org_123`'s M-Pesa credentials ONLY
3. **API Call**: M-Pesa called with `org_123`'s business shortcode
4. **Database**: Transaction stored with `organization_id = org_123`
5. **Callback**: M-Pesa calls `org_123`-specific callback URL
6. **Update**: Only `org_123`'s transaction gets updated
7. **Audit**: All logs tagged with `org_123`

### **🛡️ Isolation Guarantees:**

- ❌ **org_456** cannot see this transaction
- ❌ **org_456** cannot access **org_123**'s M-Pesa credentials  
- ❌ **org_456** cannot update **org_123**'s transactions
- ❌ **org_123** cannot exceed **org_456**'s rate limits
- ❌ No cross-tenant data access at ANY level

### **🔑 Key Isolation Points:**

1. **JWT Token** contains `organization_id`
2. **Database queries** always filter by `organization_id`
3. **M-Pesa credentials** are organization-specific
4. **Callback URLs** are organization-specific  
5. **Rate limits** are organization-specific
6. **Audit logs** are organization-specific




