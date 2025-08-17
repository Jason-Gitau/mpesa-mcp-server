-- =====================================
-- SECURE DATABASE MIGRATION SCRIPT
-- Run this to upgrade your existing database
-- =====================================

-- STEP 1: Backup existing data
CREATE TABLE organizations_backup AS SELECT * FROM organizations;
CREATE TABLE users_backup AS SELECT * FROM users;
CREATE TABLE transactions_backup AS SELECT * FROM transactions;
CREATE TABLE audit_logs_backup AS SELECT * FROM audit_logs;

-- STEP 2: Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- STEP 3: Create secure database roles
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mpesa_app_reader') THEN
        CREATE ROLE mpesa_app_reader;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mpesa_app_writer') THEN
        CREATE ROLE mpesa_app_writer;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mpesa_admin') THEN
        CREATE ROLE mpesa_admin;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mpesa_application') THEN
        CREATE USER mpesa_application WITH PASSWORD 'change-this-password-in-production';
        GRANT mpesa_app_reader, mpesa_app_writer TO mpesa_application;
    END IF;
END
$$;

-- STEP 4: Add encrypted columns to organizations
ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS mpesa_consumer_key_encrypted BYTEA,
ADD COLUMN IF NOT EXISTS mpesa_consumer_secret_encrypted BYTEA,
ADD COLUMN IF NOT EXISTS mpesa_business_short_code_encrypted BYTEA,
ADD COLUMN IF NOT EXISTS mpesa_lipa_na_mpesa_passkey_encrypted BYTEA,
ADD COLUMN IF NOT EXISTS mpesa_initiator_name_encrypted BYTEA,
ADD COLUMN IF NOT EXISTS mpesa_security_credential_encrypted BYTEA,
ADD COLUMN IF NOT EXISTS encryption_key_id VARCHAR(50) DEFAULT 'default';

-- STEP 5: Add security fields to users
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS password_salt VARCHAR(100),
ADD COLUMN IF NOT EXISTS password_iterations INTEGER DEFAULT 100000,
ADD COLUMN IF NOT EXISTS last_login TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE;

-- STEP 6: Add encrypted phone numbers to transactions
ALTER TABLE transactions 
ADD COLUMN IF NOT EXISTS phone_number_encrypted BYTEA,
ADD COLUMN IF NOT EXISTS ip_address INET,
ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- STEP 7: Enhance audit_logs for security
ALTER TABLE audit_logs 
ADD COLUMN IF NOT EXISTS session_id VARCHAR(100),
ADD COLUMN IF NOT EXISTS checksum VARCHAR(64);

-- STEP 8: Create secure API tokens table
DROP TABLE IF EXISTS api_tokens;
CREATE TABLE api_tokens (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    token_type VARCHAR(20) DEFAULT 'access_token',
    access_token_hash VARCHAR(64),  -- SHA256 hash instead of plain text
    token_prefix VARCHAR(10),       -- First 10 chars for identification
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    last_used TIMESTAMP WITH TIME ZONE
);

-- STEP 9: Create encryption/decryption functions
CREATE OR REPLACE FUNCTION set_org_context(org_id UUID, user_id UUID DEFAULT NULL)
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_org_id', org_id::TEXT, true);
    IF user_id IS NOT NULL THEN
        PERFORM set_config('app.current_user_id', user_id::TEXT, true);  
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION encrypt_credential(credential TEXT, key_id TEXT DEFAULT 'default')
RETURNS BYTEA AS $$
DECLARE
    encryption_key TEXT;
BEGIN
    -- Get encryption key from environment or use default
    encryption_key := COALESCE(
        current_setting('app.encryption_key', true), 
        'change-this-key-in-production-use-32-bytes'
    );
    
    -- Use pgcrypto to encrypt
    RETURN pgp_sym_encrypt(credential, encryption_key);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION decrypt_credential(encrypted_credential BYTEA, key_id TEXT DEFAULT 'default')
RETURNS TEXT AS $$
DECLARE
    encryption_key TEXT;
BEGIN
    -- Get encryption key
    encryption_key := COALESCE(
        current_setting('app.encryption_key', true),
        'change-this-key-in-production-use-32-bytes'
    );
    
    -- Use pgcrypto to decrypt
    RETURN pgp_sym_decrypt(encrypted_credential, encryption_key);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- STEP 10: Migrate existing plain text credentials to encrypted format
DO $$
DECLARE
    org_record RECORD;
    encryption_key TEXT := 'change-this-key-in-production-use-32-bytes';
BEGIN
    -- Set the encryption key
    PERFORM set_config('app.encryption_key', encryption_key, true);
    
    -- Encrypt existing credentials
    FOR org_record IN SELECT * FROM organizations WHERE 
        mpesa_consumer_key IS NOT NULL OR
        mpesa_consumer_secret IS NOT NULL OR
        mpesa_business_short_code IS NOT NULL OR
        mpesa_lipa_na_mpesa_passkey IS NOT NULL
    LOOP
        UPDATE organizations SET
            mpesa_consumer_key_encrypted = CASE 
                WHEN mpesa_consumer_key IS NOT NULL 
                THEN encrypt_credential(mpesa_consumer_key) 
                ELSE NULL END,
            mpesa_consumer_secret_encrypted = CASE 
                WHEN mpesa_consumer_secret IS NOT NULL 
                THEN encrypt_credential(mpesa_consumer_secret) 
                ELSE NULL END,
            mpesa_business_short_code_encrypted = CASE 
                WHEN mpesa_business_short_code IS NOT NULL 
                THEN encrypt_credential(mpesa_business_short_code) 
                ELSE NULL END,
            mpesa_lipa_na_mpesa_passkey_encrypted = CASE 
                WHEN mpesa_lipa_na_mpesa_passkey IS NOT NULL 
                THEN encrypt_credential(mpesa_lipa_na_mpesa_passkey) 
                ELSE NULL END,
            mpesa_initiator_name_encrypted = CASE 
                WHEN mpesa_initiator_name IS NOT NULL 
                THEN encrypt_credential(mpesa_initiator_name) 
                ELSE NULL END,
            mpesa_security_credential_encrypted = CASE 
                WHEN mpesa_security_credential IS NOT NULL 
                THEN encrypt_credential(mpesa_security_credential) 
                ELSE NULL END
        WHERE id = org_record.id;
    END LOOP;
    
    RAISE NOTICE 'Encrypted credentials for % organizations', 
        (SELECT COUNT(*) FROM organizations WHERE mpesa_consumer_key_encrypted IS NOT NULL);
END
$$;

-- STEP 11: Encrypt existing phone numbers in transactions
DO $$
DECLARE
    txn_record RECORD;
    encryption_key TEXT := 'change-this-key-in-production-use-32-bytes';
BEGIN
    PERFORM set_config('app.encryption_key', encryption_key, true);
    
    FOR txn_record IN SELECT * FROM transactions WHERE phone_number IS NOT NULL LOOP
        UPDATE transactions SET
            phone_number_encrypted = encrypt_credential(phone_number)
        WHERE id = txn_record.id;
    END LOOP;
    
    RAISE NOTICE 'Encrypted phone numbers for % transactions', 
        (SELECT COUNT(*) FROM transactions WHERE phone_number_encrypted IS NOT NULL);
END
$$;

-- STEP 12: Enable Row Level Security on all tables
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;  
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE bulk_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE bulk_payment_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE balance_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE callback_urls ENABLE ROW LEVEL SECURITY;
ALTER TABLE reversals ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;

-- STEP 13: Drop old insecure RLS policies
DROP POLICY IF EXISTS "Users can view their own data" ON users;
DROP POLICY IF EXISTS "Super admins can view all users" ON users;
DROP POLICY IF EXISTS "Org admins can view org users" ON users;
DROP POLICY IF EXISTS "Users can only see their org transactions" ON transactions;

-- STEP 14: Create secure RLS policies
-- Organizations
CREATE POLICY "organizations_tenant_isolation" ON organizations
    FOR ALL TO mpesa_application
    USING (id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- Users  
CREATE POLICY "users_org_isolation" ON users
    FOR ALL TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- Transactions
CREATE POLICY "transactions_tenant_isolation" ON transactions
    FOR ALL TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- Audit logs
CREATE POLICY "audit_logs_tenant_isolation" ON audit_logs
    FOR ALL TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- Bulk payments
CREATE POLICY "bulk_payments_tenant_isolation" ON bulk_payments
    FOR ALL TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- API tokens
CREATE POLICY "api_tokens_tenant_isolation" ON api_tokens  
    FOR ALL TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- Apply same pattern to remaining tables
CREATE POLICY "bulk_payment_items_tenant_isolation" ON bulk_payment_items
    FOR ALL TO mpesa_application
    USING (bulk_payment_id IN (
        SELECT id FROM bulk_payments WHERE organization_id = 
        COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000')
    ));

CREATE POLICY "balance_logs_tenant_isolation" ON balance_logs
    FOR ALL TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

CREATE POLICY "callback_urls_tenant_isolation" ON callback_urls
    FOR ALL TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

CREATE POLICY "reversals_tenant_isolation" ON reversals
    FOR ALL TO mpesa_application
    USING (original_transaction_id IN (
        SELECT id FROM transactions WHERE organization_id = 
        COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000')
    ));

CREATE POLICY "reports_tenant_isolation" ON reports
    FOR ALL TO mpesa_application
    USING (organization_id = COALESCE(current_setting('app.current_org_id', true)::UUID, '00000000-0000-0000-0000-000000000000'));

-- Super admin override (can access all organizations)
CREATE POLICY "super_admin_override" ON organizations
    FOR ALL TO mpesa_application
    USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = COALESCE(current_setting('app.current_user_id', true)::UUID, '00000000-0000-0000-0000-000000000000')
            AND role = 'super_admin' 
            AND is_active = true
        )
    );

-- STEP 15: Create audit checksum trigger
CREATE OR REPLACE FUNCTION generate_audit_checksum()
RETURNS TRIGGER AS $$
BEGIN
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

DROP TRIGGER IF EXISTS audit_logs_checksum_trigger ON audit_logs;
CREATE TRIGGER audit_logs_checksum_trigger
    BEFORE INSERT ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION generate_audit_checksum();

-- STEP 16: Make audit logs immutable
CREATE OR REPLACE RULE audit_logs_no_update AS ON UPDATE TO audit_logs DO INSTEAD NOTHING;
CREATE OR REPLACE RULE audit_logs_no_delete AS ON DELETE TO audit_logs DO INSTEAD NOTHING;

-- STEP 17: Grant permissions to application user
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mpesa_application;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mpesa_application;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO mpesa_application;

-- Restrict dangerous operations on audit logs
REVOKE DELETE ON audit_logs FROM mpesa_application;
REVOKE UPDATE ON audit_logs FROM mpesa_application;

-- STEP 18: Create security verification function
CREATE OR REPLACE FUNCTION verify_security_setup()
RETURNS TABLE (
    check_name TEXT,
    status TEXT,
    details TEXT
) AS $$
BEGIN
    -- Check encryption
    RETURN QUERY SELECT 
        'Encryption Test'::TEXT,
        CASE WHEN encrypt_credential('test') IS NOT NULL THEN 'PASS' ELSE 'FAIL' END::TEXT,
        'Database encryption functions working'::TEXT;
    
    -- Check RLS
    RETURN QUERY SELECT 
        'RLS Enabled'::TEXT,
        CASE WHEN (
            SELECT COUNT(*) FROM pg_class c 
            JOIN pg_namespace n ON n.oid = c.relnamespace 
            WHERE n.nspname = 'public' 
            AND c.relname IN ('organizations', 'users', 'transactions', 'audit_logs')
            AND c.relrowsecurity = true
        ) = 4 THEN 'PASS' ELSE 'FAIL' END::TEXT,
        'Row Level Security enabled on critical tables'::TEXT;
        
    -- Check encrypted credentials
    RETURN QUERY SELECT 
        'Credential Migration'::TEXT,
        CASE WHEN (
            SELECT COUNT(*) FROM organizations WHERE mpesa_consumer_key_encrypted IS NOT NULL
        ) > 0 THEN 'PASS' ELSE 'FAIL' END::TEXT,
        format('%s organizations have encrypted credentials', 
            (SELECT COUNT(*) FROM organizations WHERE mpesa_consumer_key_encrypted IS NOT NULL)
        );
END;
$$ LANGUAGE plpgsql;

-- STEP 19: Drop old plain text columns (DANGEROUS - only after verification!)
-- UNCOMMENT THESE AFTER VERIFYING MIGRATION IS SUCCESSFUL:
-- ALTER TABLE organizations DROP COLUMN IF EXISTS mpesa_consumer_key;
-- ALTER TABLE organizations DROP COLUMN IF EXISTS mpesa_consumer_secret;
-- ALTER TABLE organizations DROP COLUMN IF EXISTS mpesa_business_short_code;
-- ALTER TABLE organizations DROP COLUMN IF EXISTS mpesa_lipa_na_mpesa_passkey;
-- ALTER TABLE organizations DROP COLUMN IF EXISTS mpesa_initiator_name;
-- ALTER TABLE organizations DROP COLUMN IF EXISTS mpesa_security_credential;
-- ALTER TABLE transactions DROP COLUMN IF EXISTS phone_number;

-- STEP 20: Run security verification
SELECT * FROM verify_security_setup();

-- Final message
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '🎉 DATABASE SECURITY MIGRATION COMPLETED!';
    RAISE NOTICE '';
    RAISE NOTICE '✅ SECURITY IMPROVEMENTS:';
    RAISE NOTICE '   • M-Pesa credentials are now encrypted';
    RAISE NOTICE '   • Row Level Security
