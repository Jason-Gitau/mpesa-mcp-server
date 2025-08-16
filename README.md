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


