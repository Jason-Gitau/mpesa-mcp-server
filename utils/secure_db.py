import os
import logging
import asyncio
import hashlib
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager
import asyncpg
from cryptography.fernet import Fernet

from config import Config

logger = logging.getLogger(__name__)

class SecureDatabaseManager:
    """Secure database manager with encryption and RLS support"""
    
    def __init__(self):
        self.pool = None
        # Load encryption key from environment (CRITICAL: Use proper key management in production)
        self.encryption_key = os.getenv('DB_ENCRYPTION_KEY', 'default-key-change-in-production')
        
        # Initialize Fernet for additional client-side encryption if needed
        if len(self.encryption_key) == 32:  # Fernet requires 32-byte key
            self.fernet = Fernet(self.encryption_key.encode())
        else:
            # Generate proper Fernet key if needed
            self.fernet = Fernet(Fernet.generate_key())
            logger.warning("Using generated encryption key - set DB_ENCRYPTION_KEY in production!")
    
    async def init_pool(self):
        """Initialize secure database connection pool"""
        try:
            self.pool = await asyncpg.create_pool(
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                database=Config.DB_NAME,
                user='mpesa_application',  # Use our secure application user
                password=os.getenv('DB_APP_PASSWORD', 'your-secure-app-password'),
                min_size=Config.DB_MIN_SIZE,
                max_size=Config.DB_MAX_SIZE,
                
                # Security settings
                ssl='require',  # Require SSL/TLS
                server_settings={
                    'application_name': 'mpesa_mcp_server',
                    'app.encryption_key': self.encryption_key,  # Set encryption key
                }
            )
            
            logger.info("✅ Secure database pool initialized")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize secure database pool: {e}")
            raise
    
    @asynccontextmanager
    async def get_connection(self, org_id: str, user_id: Optional[str] = None):
        """Get database connection with organization context set"""
        if not self.pool:
            await self.init_pool()
        
        async with self.pool.acquire() as conn:
            try:
                # ✅ CRITICAL: Set organization context for Row Level Security
                await conn.execute(
                    "SELECT set_org_context($1, $2)",
                    org_id, user_id
                )
                
                logger.debug(f"🔒 Database context set: org_id={org_id}, user_id={user_id}")
                yield conn
                
            except Exception as e:
                logger.error(f"❌ Database operation failed: {e}")
                raise
            finally:
                # Clear context when done
                try:
                    await conn.execute("RESET app.current_org_id")
                    await conn.execute("RESET app.current_user_id")
                except:
                    pass  # Context will be cleared when connection is returned to pool

    async def encrypt_credential(self, credential: str) -> bytes:
        """Encrypt sensitive credential using database function"""
        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                "SELECT encrypt_credential($1)", credential
            )
            return result
    
    async def decrypt_credential(self, encrypted_credential: bytes) -> str:
        """Decrypt sensitive credential using database function"""
        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                "SELECT decrypt_credential($1)", encrypted_credential
            )
            return result
    
    def hash_phone_number(self, phone_number: str) -> str:
        """Create searchable hash of phone number for indexing"""
        return hashlib.sha256(f"{phone_number}{self.encryption_key}".encode()).hexdigest()[:16]
    
    async def store_audit_log(self, org_id: str, user_id: str, action: str, 
                            tool_name: str, request_data: Dict, response_data: Dict,
                            status: str, ip_address: str, user_agent: str):
        """Store tamper-proof audit log with checksum"""
        async with self.get_connection(org_id, user_id) as conn:
            await conn.execute("""
                INSERT INTO audit_logs (
                    organization_id, user_id, action, tool_name,
                    request_data, response_data, status,
                    ip_address, user_agent, session_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """, org_id, user_id, action, tool_name,
                 request_data, response_data, status,
                 ip_address, user_agent, f"session_{user_id}_{org_id}")

    async def verify_audit_integrity(self, org_id: str, audit_id: str) -> bool:
        """Verify audit log hasn't been tampered with"""
        async with self.get_connection(org_id) as conn:
            log = await conn.fetchrow("""
                SELECT organization_id, user_id, action, tool_name, 
                       status, created_at, checksum
                FROM audit_logs WHERE id = $1
            """, audit_id)
            
            if not log:
                return False
            
            # Recalculate checksum
            expected_checksum = hashlib.sha256(
                f"{log['organization_id']}{log['user_id']}{log['action']}"
                f"{log['tool_name']}{log['status']}{log['created_at']}".encode()
            ).hexdigest()
            
            return log['checksum'] == expected_checksum

# Global instance
secure_db = SecureDatabaseManager()

async def init_secure_database():
    """Initialize secure database connection"""
    await secure_db.init_pool()

def get_secure_db():
    """Get secure database manager instance"""
    return secure_db
