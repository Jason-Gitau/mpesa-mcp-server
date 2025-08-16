-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Organizations/Tenants table for multi-tenant support
CREATE TABLE organizations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    mpesa_consumer_key TEXT,
    mpesa_consumer_secret TEXT,
    mpesa_business_short_code VARCHAR(20),
    mpesa_lipa_na_mpesa_passkey TEXT,
    mpesa_initiator_name VARCHAR(100),
    mpesa_security_credential TEXT,
    mpesa_base_url VARCHAR(200) DEFAULT 'https://sandbox.safaricom.co.ke',
    callback_base_url VARCHAR(200),
    is_active BOOLEAN DEFAULT true,
    subscription_status VARCHAR(20) DEFAULT 'trial' CHECK (subscription_status IN ('trial', 'active', 'suspended', 'cancelled')),
    subscription_plan VARCHAR(50) DEFAULT 'basic',
    api_rate_limit INTEGER DEFAULT 1000,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Users table for permission management
CREATE TABLE users (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('super_admin', 'org_admin', 'manager', 'user')),
    permissions JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(organization_id, username),
    UNIQUE(organization_id, email)
);

-- API tokens table for OAuth management
CREATE TABLE api_tokens (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    token_type VARCHAR(20) DEFAULT 'access_token',
    access_token TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

-- Transaction logs table
CREATE TABLE transactions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    transaction_id VARCHAR(100),
    merchant_request_id VARCHAR(100),
    checkout_request_id VARCHAR(100),
    transaction_type VARCHAR(20) CHECK (transaction_type IN ('STK_PUSH', 'C2B', 'B2C', 'REVERSAL')),
    amount DECIMAL(12, 2),
    phone_number VARCHAR(15),
    account_reference VARCHAR(100),
    transaction_desc TEXT,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED', 'CANCELLED', 'REVERSED')),
    mpesa_receipt_number VARCHAR(100),
    result_code INTEGER,
    result_desc TEXT,
    callback_data JSONB,
    initiated_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(organization_id, transaction_id)
);

-- Bulk payments table
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

-- Individual payments within bulk payments
CREATE TABLE bulk_payment_items (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bulk_payment_id UUID REFERENCES bulk_payments(id) ON DELETE CASCADE,
    phone_number VARCHAR(15) NOT NULL,
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

-- Account balance logs
CREATE TABLE balance_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    account_type VARCHAR(20) CHECK (account_type IN ('PAYBILL', 'TILL')),
    balance DECIMAL(12, 2),
    currency VARCHAR(3) DEFAULT 'KES',
    checked_by UUID REFERENCES users(id),
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Callback URLs management
CREATE TABLE callback_urls (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    url_type VARCHAR(50) CHECK (url_type IN ('VALIDATION', 'CONFIRMATION', 'RESULT', 'TIMEOUT')),
    url VARCHAR(500) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_tested TIMESTAMP WITH TIME ZONE,
    test_status VARCHAR(20) CHECK (test_status IN ('SUCCESS', 'FAILED', 'PENDING'))
);

-- Audit trail for all MCP server actions
CREATE TABLE audit_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    tool_name VARCHAR(100),
    request_data JSONB,
    response_data JSONB,
    status VARCHAR(20) CHECK (status IN ('SUCCESS', 'FAILED', 'ERROR')),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Transaction reversals
CREATE TABLE reversals (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_transaction_id UUID REFERENCES transactions(id),
    reversal_transaction_id VARCHAR(100),
    amount DECIMAL(12, 2),
    reason TEXT,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED')),
    result_code INTEGER,
    result_desc TEXT,
    initiated_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Reports cache for automated reports
CREATE TABLE reports (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    report_type VARCHAR(50) CHECK (report_type IN ('DAILY', 'WEEKLY', 'MONTHLY', 'CUSTOM')),
    report_name VARCHAR(200),
    date_from DATE,
    date_to DATE,
    report_data JSONB,
    generated_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Create indexes for better performance
CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_users_organization_id ON users(organization_id);
CREATE INDEX idx_transactions_organization_id ON transactions(organization_id);
CREATE INDEX idx_transactions_phone_number ON transactions(phone_number);
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_created_at ON transactions(created_at);
CREATE INDEX idx_transactions_type ON transactions(transaction_type);
CREATE INDEX idx_audit_logs_organization_id ON audit_logs(organization_id);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_bulk_payments_organization_id ON bulk_payments(organization_id);
CREATE INDEX idx_bulk_payments_status ON bulk_payments(status);
CREATE INDEX idx_bulk_payment_items_bulk_payment_id ON bulk_payment_items(bulk_payment_id);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at triggers
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_transactions_updated_at BEFORE UPDATE ON transactions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_bulk_payment_items_updated_at BEFORE UPDATE ON bulk_payment_items FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Row Level Security (RLS) policies
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE bulk_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE reversals ENABLE ROW LEVEL SECURITY;

-- Basic RLS policies (you can customize these based on your needs)
CREATE POLICY "Users can view their own data" ON users FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Super admins can view all users" ON users FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM users WHERE id = auth.uid() AND role = 'super_admin'
    )
);
CREATE POLICY "Org admins can view org users" ON users FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM users WHERE id = auth.uid() AND role = 'org_admin' 
        AND organization_id = users.organization_id
    )
);

-- Transactions are scoped to organization
CREATE POLICY "Users can only see their org transactions" ON transactions FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM users WHERE id = auth.uid() AND organization_id = transactions.organization_id
    )
);

-- Insert default super admin and sample organization
INSERT INTO organizations (name, slug, subscription_status, subscription_plan) VALUES 
('Default Organization', 'default-org', 'active', 'enterprise');

-- Get the organization ID for the default org
INSERT INTO users (organization_id, username, email, password_hash, role, permissions) 
SELECT id, 'super_admin', 'admin@yourdomain.com', 'your_hashed_password_here', 'super_admin', '{"all": true}'
FROM organizations WHERE slug = 'default-org';
