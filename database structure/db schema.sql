-- =====================================
-- SECURE M-PESA MULTI-TENANT DATABASE
-- =====================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- For encryption

-- =====================================
-- 1. DATABASE ROLES & SECURITY SETUP
-- =====================================

-- Create application-specific roles
CREATE ROLE mpesa_app_reader;
CREATE ROLE mpesa_app_writer;
CREATE ROLE mpesa_admin;

-- Create secure application user
CREATE USER mpesa_application WITH PASSWORD 'your-secure-app-password';
GRANT mpesa_app_reader, mpesa_app_writer TO mpesa_application;

-- =====================================
-- 2. ENCRYPTED ORGANIZATIONS TABLE
-- =====================================

DROP TABLE IF EXISTS organizations CASCADE;
CREATE TABLE organizations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    
    -- ✅ ENCRYPTED M-Pesa credentials (was plain text)
    mpesa_consumer_key_encrypted BYTEA,
    mpesa_consumer_secret_encrypted BYTEA,  
    mpesa_business_short_code_encrypted BYTEA,
    mpesa_lipa_na_mpesa_passkey_encrypted BYTEA,
    mpesa_initiator_name_encrypted BYTEA,
    mpesa_security_credential_encrypted BYTEA,
    
    -- Configuration (less sensitive)
    mpesa_base_url VARCHAR(200) DEFAULT 'https://sandbox.safaricom.co.ke',
    callback_base_url VARCHAR(200),
    
    -- Organization settings
    is_active BOOLEAN DEFAULT true,
    subscription_status VARCHAR(20) DEFAULT 'trial' CHECK (subscription_status IN ('trial', 'active', 'suspended', 'cancelled')),
    subscription_plan VARCHAR(50) DEFAULT 'basic',
    api_rate_limit INTEGER DEFAULT 1000,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- ✅ Security: Encryption key identifier
    encryption_key_id VARCHAR(50) DEFAULT 'default'
);

-- ✅ Enable Row Level Security
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

-- =====================================
-- 3. SECURE USERS TABLE
-- =====================================

DROP TABLE IF EXISTS users CASCADE;
CREATE TABLE users (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    
    -- ✅ Enhanced password security
    password_hash VARCHAR(255) NOT NULL,
    password_salt VARCHAR(100) NOT NULL,  -- Additional salt
    password_iterations INTEGER DEFAULT 100000,  -- PBKDF2 iterations
    
    -- Access control
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('super_admin', 'org_admin', 'manager', 'user')),
    permissions JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    
    -- Security tracking
    last_login TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(organization_id, username),
    UNIQUE(organization_id, email)
);

-- ✅ Enable Row Level Security
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- =====================================
-- 4. SECURE TRANSACTIONS TABLE
-- =====================================

DROP TABLE IF EXISTS transactions CASCADE;
CREATE TABLE transactions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Transaction identifiers
    transaction_id VARCHAR(100),
    merchant_request_id VARCHAR(100),
    checkout_request_id VARCHAR(100),
    
    -- Transaction details
    transaction_type VARCHAR(20) CHECK (transaction_type IN ('STK_PUSH', 'C2B', 'B2C', 'REVERSAL')),
    amount DECIMAL(12, 2),
    
    -- ✅ Encrypted sensitive data
    phone_number_encrypted BYTEA,  -- Encrypted phone numbers
    account_reference VARCHAR(100),
    transaction_desc TEXT,
    
    -- Status and results
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED', 'CANCELLED', 'REVERSED')),
    mpesa_receipt_number VARCHAR(100),
    result_code INTEGER,
    result_desc TEXT,
    callback_data JSONB,
    
    -- Security and audit
    initiated_by UUID REFERENCES users(id),
    ip_address INET,  -- Track IP for security
    user_agent TEXT,  -- Track user agent
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(organization_id, transaction_id)
);

-- ✅ Enable Row Level Security
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;

-- =====================================
-- 5. SECURE AUDIT LOGS (IMMUTABLE)
-- =====================================

DROP TABLE IF EXISTS audit_logs CASCADE;
CREATE TABLE audit_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    
    -- Action details
    action VARCHAR(100) NOT NULL,
    tool_name VARCHAR(100),
    request_data JSONB,
    response_data JSONB,
    status VARCHAR(20) CHECK (status IN ('SUCCESS', 'FAILED', 'ERROR')),
    
    -- Security context
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(100),
    
    -- ✅ Tamper detection
    checksum VARCHAR(64),  -- SHA256 hash for integrity
    
    -- Timestamp (immutable)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    -- ✅ NO updated_at - audit logs are immutable
);

-- ✅ Enable Row Level Security
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- ✅ Make audit logs immutable
CREATE OR REPLACE RULE audit_logs_no_update AS ON UPDATE TO audit_logs DO INSTEAD NOTHING;
CREATE OR REPLACE RULE audit_logs_no_delete AS ON DELETE TO audit_logs DO INSTEAD NOTHING;

-- =====================================
-- 6. OTHER SECURE TABLES
-- =====================================

-- API Tokens with enhanced security
DROP TABLE IF EXISTS api_tokens CASCADE;
CREATE TABLE api_tokens (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    token_type VARCHAR(20) DEFAULT 'access_token',
    
    -- ✅ Encrypted token storage
    access_token_hash VARCHAR(64),  -- SHA256 hash of token (not plain text)
    token_prefix VARCHAR(10),       -- First 10 chars for identification
    
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    last_used TIMESTAMP WITH TIME ZONE
);

ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;

-- Bulk payments (keep existing structure, add RLS)
CREATE TABLE bulk_payments (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    batch_id VARCHAR(100) NOT NULL,
    batch_name VARCHAR(200),
    total_amount DECIMAL(12, 2),
    total_recipients INTEGER,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),
    initiated_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(organization_id, batch_id)
);

ALTER TABLE bulk_payments ENABLE ROW LEVEL SECURITY;

-- Other tables (same pattern - add RLS to all)
CREATE TABLE bulk_payment_items (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bulk_payment_id UUID REFERENCES bulk_payments(id) ON DELETE CASCADE,
    phone_number_encrypted BYTEA,  -- ✅ Encrypted
    amount DECIMAL(12, 2) NOT NULL,
    account_reference VARCHAR(100),
    remarks TEXT,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED')),
    mpesa_receipt_number VARCHAR(100),
    result_code INTEGER,
    result_desc TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================
-- 7. ROW LEVEL SECURITY POLICIES
-- =====================================

-- ✅ CRITICAL: Tenant isolation for organizations
CREATE POLICY "organizations_tenant_isolation" ON organizations
    FOR ALL 
    TO mpesa_application
    USING (id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- ✅ CRITICAL: User access limited to their organization
CREATE POLICY "users_org_isolation" ON users
    FOR ALL
    TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- ✅ CRITICAL: Transaction isolation by organization
CREATE POLICY "transactions_tenant_isolation" ON transactions
    FOR ALL
    TO mpesa_application  
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- ✅ CRITICAL: Audit log isolation
CREATE POLICY "audit_logs_tenant_isolation" ON audit_logs
    FOR ALL
    TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- ✅ Apply same pattern to all other tables
CREATE POLICY "bulk_payments_tenant_isolation" ON bulk_payments
    FOR ALL TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

CREATE POLICY "api_tokens_tenant_isolation" ON api_tokens  
    FOR ALL TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- ✅ Super admin override policy (can access all orgs)
CREATE POLICY "super_admin_override" ON organizations
    FOR ALL
    TO mpesa_application
    USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = COALESCE(current_setting('app.current_user_id', true)::UUID, '00000000-0000-0000-0000-000000000000')
            AND role = 'super_admin'
            AND is_active = true
        )
    );

-- =====================================
-- 8. PERFORMANCE INDEXES
-- =====================================

-- Organizations
CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_organizations_active ON organizations(is_active) WHERE is_active = true;

-- Users  
CREATE INDEX idx_users_org_id ON users(organization_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = true;

-- Transactions
CREATE INDEX idx_transactions_org_id ON transactions(organization_id);
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_created_at ON transactions(created_at);
CREATE INDEX idx_transactions_type ON transactions(transaction_type);
CREATE INDEX idx_transactions_phone_hash ON transactions(phone_number_encrypted);  -- For encrypted search

-- Audit logs
CREATE INDEX idx_audit_logs_org_id ON audit_logs(organization_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

-- =====================================
-- 9. SECURITY FUNCTIONS
-- =====================================

-- Function to set organization context
CREATE OR REPLACE FUNCTION set_org_context(org_id UUID, user_id UUID DEFAULT NULL)
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_org_id', org_id::TEXT, true);
    IF user_id IS NOT NULL THEN
        PERFORM set_config('app.current_user_id', user_id::TEXT, true);
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function for secure credential encryption
CREATE OR REPLACE FUNCTION encrypt_credential(credential TEXT, key_id TEXT DEFAULT 'default')
RETURNS BYTEA AS $$
DECLARE
    encryption_key TEXT;
BEGIN
    -- Get encryption key (in production, this would come from a secure key management system)
    encryption_key := COALESCE(current_setting('app.encryption_key', true), 'default-key-change-in-production');
    
    -- Use pgcrypto to encrypt
    RETURN pgp_sym_encrypt(credential, encryption_key);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function for secure credential decryption  
CREATE OR REPLACE FUNCTION decrypt_credential(encrypted_credential BYTEA, key_id TEXT DEFAULT 'default')
RETURNS TEXT AS $$
DECLARE
    encryption_key TEXT;
BEGIN
    -- Get encryption key
    encryption_key := COALESCE(current_setting('app.encryption_key', true), 'default-key-change-in-production');
    
    -- Use pgcrypto to decrypt
    RETURN pgp_sym_decrypt(encrypted_credential, encryption_key);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================
-- 10. AUDIT TRIGGER FOR INTEGRITY
-- =====================================

CREATE OR REPLACE FUNCTION generate_audit_checksum()
RETURNS TRIGGER AS $$
BEGIN
    -- Generate SHA256 checksum for tamper detection
    NEW.checksum := encode(digest(
        CONCAT(
            NEW.organization_id::TEXT,
            NEW.user_id::TEXT, 
            NEW.action,
            NEW.tool_name,
            NEW.status,
            NEW.created_at::TEXT
        ), 'sha256'
    ), 'hex');
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_logs_checksum_trigger
    BEFORE INSERT ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION generate_audit_checksum();

-- =====================================
-- 11. GRANT PERMISSIONS
-- =====================================

-- Grant table permissions to application user
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mpesa_application;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mpesa_application;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mpesa_application;

-- Restrict dangerous operations
REVOKE DELETE ON audit_logs FROM mpesa_application;  -- Audit logs are immutable
REVOKE UPDATE ON audit_logs FROM mpesa_application;  -- Audit logs are immutable

-- =====================================
-- 12. SAMPLE DATA (FOR TESTING)
-- =====================================

-- Set encryption key (CHANGE IN PRODUCTION!)
SELECT set_config('app.encryption_key', 'your-production-encryption-key-here', false);

-- Insert sample organization with encrypted credentials
INSERT INTO organizations (
    name, 
    slug, 
    mpesa_consumer_key_encrypted,
    mpesa_consumer_secret_encrypted,
    mpesa_business_short_code_encrypted,
    mpesa_lipa_na_mpesa_passkey_encrypted,
    subscription_status,
    subscription_plan
) VALUES (
    'Demo Organization', 
    'demo-org',
    encrypt_credential('demo_consumer_key'),
    encrypt_credential('demo_consumer_secret'),
    encrypt_credential('174379'),
    encrypt_credential('demo_passkey'),
    'active',
    'enterprise'
);

-- Get the organization ID
SELECT set_org_context(id) FROM organizations WHERE slug = 'demo-org' \gset

-- Insert sample admin user
INSERT INTO users (
    organization_id, 
    username, 
    email, 
    password_hash, 
    password_salt,
    role, 
    permissions
) SELECT 
    id,
    'admin',
    'admin@demo-org.com',
    crypt('secure_password', gen_salt('bf', 12)),  -- Secure password hashing
    gen_salt('bf', 12),
    'org_admin',
    '{"mpesa": true, "admin": true}'::jsonb
FROM organizations WHERE slug = 'demo-org';

-- =====================================
-- 13. SECURITY VERIFICATION QUERIES
-- =====================================

-- Test tenant isolation (run these to verify security)
/*
-- Set organization context
SELECT set_org_context('your-org-id-here'::UUID);

-- These should only return data for the current organization
SELECT name FROM organizations;
SELECT username FROM users;  
SELECT transaction_type FROM transactions;
SELECT action FROM audit_logs;

-- Without organization context, these should return empty
RESET app.current_org_id;
SELECT name FROM organizations;  -- Should be empty due to RLS
*/
