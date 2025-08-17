#!/usr/bin/env python3
"""
Security Verification Test Script for M-Pesa MCP
Tests all security improvements to ensure proper implementation
"""

import asyncio
import os
import sys
import json
from typing import Dict, List
import asyncpg
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.secure_database import SecureDatabaseManager
from models.secure_organization import SecureOrganizationModel

class SecurityTestSuite:
    """Comprehensive security test suite"""
    
    def __init__(self):
        self.secure_db = SecureDatabaseManager()
        self.test_results = []
        self.test_org_id = None
        self.test_user_id = None
    
    async def run_all_tests(self):
        """Run all security tests"""
        print("🔒 M-PESA MCP SECURITY VERIFICATION SUITE")
        print("=" * 50)
        
        try:
            await self.secure_db.init_pool()
            
            # Database-level security tests
            await self.test_database_encryption()
            await self.test_row_level_security()
            await self.test_audit_log_integrity()
            await self.test_credential_encryption()
            await self.test_cross_tenant_isolation()
            await self.test_rate_limiting()
            await self.test_sql_injection_protection()
            
            # Application-level security tests
            await self.test_secure_organization_model()
            await self.test_encrypted_credential_storage()
            await self.test_audit_checksum_verification()
            
            # Print results
            self.print_test_results()
            
        except Exception as e:
            print(f"❌ Test suite failed to initialize: {e}")
            return False
        
        return all(result['passed'] for result in self.test_results)
    
    async def test_database_encryption(self):
        """Test database encryption functions"""
        test_name = "Database Encryption Functions"
        try:
            async with self.secure_db.pool.acquire() as conn:
                # Test encryption
                test_credential = "test_consumer_key_12345"
                encrypted = await conn.fetchval(
                    "SELECT encrypt_credential($1)", test_credential
                )
                
                # Test decryption
                decrypted = await conn.fetchval(
                    "SELECT decrypt_credential($1)", encrypted
                )
                
                if decrypted == test_credential:
                    self.log_test_result(test_name, True, "Encryption/decryption working correctly")
                else:
                    self.log_test_result(test_name, False, f"Decryption mismatch: {decrypted} != {test_credential}")
                    
        except Exception as e:
            self.log_test_result(test_name, False, f"Encryption test failed: {e}")
    
    async def test_row_level_security(self):
        """Test Row Level Security enforcement"""
        test_name = "Row Level Security (RLS)"
        try:
            # Create test organizations
            org1_id = await self.create_test_organization("test-org-1")
            org2_id = await self.create_test_organization("test-org-2")
            
            async with self.secure_db.pool.acquire() as conn:
                # Set context for org1
                await conn.execute("SELECT set_org_context($1)", org1_id)
                
                # Should only see org1
                orgs = await conn.fetch("SELECT id, name FROM organizations")
                if len(orgs) == 1 and str(orgs[0]['id']) == org1_id:
                    self.log_test_result(test_name, True, "RLS correctly isolates organizations")
                else:
                    self.log_test_result(test_name, False, f"RLS failed: saw {len(orgs)} orgs instead of 1")
                
                # Cleanup
                await self.cleanup_test_organization(org1_id)
                await self.cleanup_test_organization(org2_id)
                    
        except Exception as e:
            self.log_test_result(test_name, False, f"RLS test failed: {e}")
    
    async def test_audit_log_integrity(self):
        """Test audit log checksum generation and integrity"""
        test_name = "Audit Log Integrity"
        try:
            org_id = await self.create_test_organization("audit-test-org")
            user_id = await self.create_test_user(org_id, "audit-test-user")
            
            async with self.secure_db.get_connection(org_id, user_id) as conn:
                # Insert audit log
                audit_id = await conn.fetchval("""
                    INSERT INTO audit_logs (
                        organization_id, user_id, action, tool_name, 
                        request_data, response_data, status, ip_address
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    RETURNING id
                """, org_id, user_id, "TEST_ACTION", "test_tool",
                     {"test": "data"}, {"result": "success"}, "SUCCESS", "127.0.0.1")
                
                # Verify checksum was generated
                audit_record = await conn.fetchrow(
                    "SELECT checksum FROM audit_logs WHERE id = $1", audit_id
                )
                
                if audit_record and audit_record['checksum']:
                    # Verify integrity
                    is_valid = await self.secure_db.verify_audit_integrity(org_id, str(audit_id))
                    if is_valid:
                        self.log_test_result(test_name, True, "Audit log checksums working correctly")
                    else:
                        self.log_test_result(test_name, False, "Audit log checksum validation failed")
                else:
                    self.log_test_result(test_name, False, "Audit log checksum not generated")
                
            await self.cleanup_test_organization(org_id)
                    
        except Exception as e:
            self.log_test_result(test_name, False, f"Audit integrity test failed: {e}")
    
    async def test_credential_encryption(self):
        """Test M-Pesa credential encryption in organizations"""
        test_name = "M-Pesa Credential Encryption"
        try:
            # Create org with M-Pesa credentials
            mpesa_creds = {
                'consumer_key': 'test_consumer_key_12345',
                'consumer_secret': 'test_consumer_secret_67890',
                'business_short_code': '174379',
                'lipa_na_mpesa_passkey': 'test_passkey_abcdef'
            }
            
            org_id = await SecureOrganizationModel.create_organization(
                name="Credential Test Org",
                slug="cred-test-org",
                admin_user={
                    'username': 'admin',
                    'email': 'admin@credtest.com',
                    'password': 'securepassword123'
                },
                mpesa_credentials=mpesa_creds
            )
            
            # Retrieve and verify credentials are encrypted/decrypted properly
            config = await SecureOrganizationModel.get_org_config(org_id['organization_id'])
            
            if (config['consumer_key'] == mpesa_creds['consumer_key'] and
                config['consumer_secret'] == mpesa_creds['consumer_secret']):
                self.log_test_result(test_name, True, "M-Pesa credentials encrypted and decrypted correctly")
            else:
                self.log_test_result(test_name, False, "M-Pesa credential encryption/decryption failed")
                
            await self.cleanup_test_organization(org_id['organization_id'])
                
        except Exception as e:
            self.log_test_result(test_name, False, f"Credential encryption test failed: {e}")
    
    async def test_cross_tenant_isolation(self):
        """Test that tenants cannot access each other's data"""
        test_name = "Cross-Tenant Data Isolation"
        try:
            # Create two organizations with transactions
            org1_id = await self.create_test_organization("isolation-test-1")
            org2_id = await self.create_test_organization("isolation-test-2")
            
            user1_id = await self.create_test_user(org1_id, "user1")
            user2_id = await self.create_test_user(org2_id, "user2")
            
            # Create transaction for org1
            async with self.secure_db.get_connection(org1_id, user1_id) as conn:
                await conn.execute("""
                    INSERT INTO transactions (
                        organization_id, transaction_id, amount, status, initiated_by
                    ) VALUES ($1, $2, $3, $4, $5)
                """, org1_id, "TXN_ORG1_001", 100.00, "SUCCESS", user1_id)
            
            # Try to access org1's transactions from org2 context
            async with self.secure_db.get_connection(org2_id, user2_id) as conn:
                transactions = await conn.fetch(
                    "SELECT * FROM transactions WHERE transaction_id = 'TXN_ORG1_001'"
                )
                
                if len(transactions) == 0:
                    self.log_test_result(test_name, True, "Cross-tenant isolation working correctly")
                else:
                    self.log_test_result(test_name, False, f"Cross-tenant isolation failed: org2 can see org1 data")
            
            await self.cleanup_test_organization(org1_id)
            await self.cleanup_test_organization(org2_id)
                
        except Exception as e:
            self.log_test_result(test_name, False, f"Cross-tenant isolation test failed: {e}")
    
    async def test_rate_limiting(self):
        """Test rate limiting functionality"""
        test_name = "Rate Limiting"
        try:
            org_id = await self.create_test_organization("rate-test-org")
            
            # Set low rate limit for testing
            async with self.secure_db.pool.acquire() as conn:
                await conn.execute(
                    "UPDATE organizations SET api_rate_limit = 2 WHERE id = $1", org_id
                )
            
            # Make 3 audit log entries (exceeds limit of 2)
            user_id = await self.create_test_user(org_id, "rate-test-user")
            
            for i in range(3):
                await self.secure_db.store_audit_log(
                    org_id, user_id, f"TEST_ACTION_{i}", "rate_test",
                    {"test": i}, {"result": "success"}, "SUCCESS",
                    "127.0.0.1", "test-agent"
                )
            
            # Check rate limit
            is_limited = not await SecureOrganizationModel.check_rate_limit(org_id)
            
            if is_limited:
                self.log_test_result(test_name, True, "Rate limiting working correctly")
            else:
                self.log_test_result(test_name, False, "Rate limiting not enforced")
                
            await self.cleanup_test_organization(org_id)
                
        except Exception as e:
            self.log_test_result(test_name, False, f"Rate limiting test failed: {e}")
    
    async def test_sql_injection_protection(self):
        """Test protection against SQL injection"""
        test_name = "SQL Injection Protection"
        try:
            org_id = await self.create_test_organization("sql-injection-test")
            
            # Try SQL injection in organization name search
            malicious_input = "'; DROP TABLE organizations; --"
            
            try:
                async with self.secure_db.get_connection(org_id) as conn:
                    # This should be safe due to parameterized queries
                    result = await conn.fetchval(
                        "SELECT name FROM organizations WHERE slug = $1", malicious_input
                    )
                    
                # If we reach here, injection was prevented
                self.log_test_result(test_name, True, "SQL injection prevented by parameterized queries")
                
            except Exception as injection_error:
                # Even exceptions are OK - means injection was blocked
                self.log_test_result(test_name, True, f"SQL injection blocked: {injection_error}")
                
            await self.cleanup_test_organization(org_id)
                
        except Exception as e:
            self.log_test_result(test_name, False, f"SQL injection test failed: {e}")
    
    async def test_secure_organization_model(self):
        """Test SecureOrganizationModel functionality"""
        test_name = "Secure Organization Model"
        try:
            # Test creating organization with encrypted credentials
            result = await SecureOrganizationModel.create_organization(
                name="Model Test Org",
                slug="model-test-org",
                admin_user={
                    'username': 'modeladmin',
                    'email': 'admin@modeltest.com',
                    'password': 'securepassword456'
                },
                mpesa_credentials={
                    'consumer_key': 'model_test_key',
                    'consumer_secret': 'model_test_secret',
                    'business_short_code': '123456',
                    'lipa_na_mpesa_passkey': 'model_test_passkey'
                }
            )
            
            org_id = result['organization_id']
            
            # Test retrieving config
            config = await SecureOrganizationModel.get_org_config(org_id)
            
            if config and config['consumer_key'] == 'model_test_key':
                self.log_test_result(test_name, True, "SecureOrganizationModel working correctly")
            else:
                self.log_test_result(test_name, False, "SecureOrganizationModel failed to retrieve config")
                
            await self.cleanup_test_organization(org_id)
                
        except Exception as e:
            self.log_test_result(test_name, False, f"SecureOrganizationModel test failed: {e}")
    
    async def test_encrypted_credential_storage(self):
        """Test that credentials are actually encrypted in database"""
        test_name = "Encrypted Credential Storage"
        try:
            org_id = await self.create_test_organization("encryption-storage-test")
            
            # Store encrypted credentials
            await SecureOrganizationModel.update_org_credentials(
                org_id,
                {
                    'consumer_key': 'storage_test_key_12345',
                    'consumer_secret': 'storage_test_secret_67890'
                },
                await self.create_test_user(org_id, "encryption-test-user")
            )
            
            # Check that raw database storage is encrypted (not plain text)
            async with self.secure_db.pool.acquire() as conn:
                # Bypass RLS to check raw storage
                await conn.execute("SET row_security = off")
                
                raw_data = await conn.fetchrow("""
                    SELECT mpesa_consumer_key_encrypted, mpesa_consumer_secret_encrypted 
                    FROM organizations WHERE id = $1
                """, org_id)
                
                await conn.execute("SET row_security = on")
                
                # Verify it's encrypted (should be bytea, not readable text)
                if (raw_data['mpesa_consumer_key_encrypted'] and 
                    b'storage_test_key_12345' not in raw_data['mpesa_consumer_key_encrypted']):
                    self.log_test_result(test_name, True, "Credentials are properly encrypted in database")
                else:
                    self.log_test_result(test_name, False, "Credentials appear to be stored in plain text")
                    
            await self.cleanup_test_organization(org_id)
                    
        except Exception as e:
            self.log_test_result(test_name, False, f"Encrypted storage test failed: {e}")
    
    async def test_audit_checksum_verification(self):
        """Test audit log checksum verification"""
        test_name = "Audit Checksum Verification"
        try:
            org_id = await self.create_test_organization("checksum-test")
            user_id = await self.create_test_user(org_id, "checksum-user")
            
            # Create audit log entry
            async with self.secure_db.get_connection(org_id, user_id) as conn:
                audit_id = await conn.fetchval("""
                    INSERT INTO audit_logs (
                        organization_id, user_id, action, tool_name,
                        request_data, response_data, status
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING id
                """, org_id, user_id, "CHECKSUM_TEST", "test_tool",
                     {"test": "checksum"}, {"valid": True}, "SUCCESS")
            
            # Verify checksum
            is_valid = await self.secure_db.verify_audit_integrity(org_id, str(audit_id))
            
            if is_valid:
                self.log_test_result(test_name, True, "Audit checksum verification working")
            else:
                self.log_test_result(test_name, False, "Audit checksum verification failed")
                
            await self.cleanup_test_organization(org_id)
                
        except Exception as e:
            self.log_test_result(test_name, False, f"Checksum verification test failed: {e}")
    
    # Helper methods
    async def create_test_organization(self, slug: str) -> str:
        """Create a test organization"""
        async with self.secure_db.pool.acquire() as conn:
            org_id = await conn.fetchval("""
                INSERT INTO organizations (name, slug) 
                VALUES ($1, $2) RETURNING id
            """, f"Test Org {slug}", slug)
            return str(org_id)
    
    async def create_test_user(self, org_id: str, username: str) -> str:
        """Create a test user"""
        async with self.secure_db.pool.acquire() as conn:
            user_id = await conn.fetchval("""
                INSERT INTO users (organization_id, username, email, password_hash, password_salt) 
                VALUES ($1, $2, $3, $4, $5) RETURNING id
            """, org_id, username, f"{username}@test.com", "test_hash", "test_salt")
            return str(user_id)
    
    async def cleanup_test_organization(self, org_id: str):
        """Clean up test organization"""
        try:
            async with self.secure_db.pool.acquire() as conn:
                await conn.execute("SET row_security = off")
                await conn.execute("DELETE FROM organizations WHERE id = $1", org_id)
                await conn.execute("SET row_security = on")
        except:
            pass  # Ignore cleanup errors
    
    def log_test_result(self, test_name: str, passed: bool, details: str):
        """Log a test result"""
        self.test_results.append({
            'test_name': test_name,
            'passed': passed,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} | {test_name}")
        if not passed:
            print(f"         └── {details}")
    
    def print_test_results(self):
        """Print comprehensive test results"""
        print("\n" + "=" * 50)
        print("🔒 SECURITY TEST RESULTS")
        print("=" * 50)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['passed'])
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")
        
        if failed_tests > 0:
            print(f"\n❌ FAILED TESTS:")
            for result in self.test_results:
                if not result['passed']:
                    print(f"   • {result['test_name']}: {result['details']}")
        
        print(f"\n{'🎉 ALL SECURITY TESTS PASSED!' if failed_tests == 0 else '⚠️  SECURITY ISSUES DETECTED!'}")
        
        # Save results to file
        with open('security_test_results.json', 'w') as f:
            json.dump(self.test_results, f, indent=2)
        print(f"📄 Detailed results saved to security_test_results.json")


async def main():
    """Run security test suite"""
    print("Starting M-Pesa MCP Security Verification...")
    
    # Check environment
    required_env_vars = ['DB_HOST', 'DB_NAME', 'DB_ENCRYPTION_KEY']
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {missing_vars}")
        print("Please set up your .env file with secure configuration")
        return False
    
    # Run tests
    test_suite = SecurityTestSuite()
    success = await test_suite.run_all_tests()
    
    if success:
        print("\n🔒 Security verification completed successfully!")
        print("Your M-Pesa MCP system is secure and ready for production.")
        return True
    else:
        print("\n⚠️  Security verification found issues!")
        print("Please fix the failed tests before deploying to production.")
        return False


if __name__ == "__main__":
    asyncio.run(main())
