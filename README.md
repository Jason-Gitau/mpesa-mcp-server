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


