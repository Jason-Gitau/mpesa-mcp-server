import logging
import asyncpg
from typing import Optional

from config import Config

logger = logging.getLogger(__name__)

# Global database pool
_db_pool: Optional[asyncpg.Pool] = None

async def init_database():
    """Initialize database connection pool"""
    global _db_pool
    
    try:
        db_config = Config.get_database_url()
        _db_pool = await asyncpg.create_pool(**db_config)
        logger.info("Database connection pool initialized")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

def get_db_pool() -> asyncpg.Pool:
    """Get database connection pool"""
    if _db_pool is None:
        raise Exception("Database not initialized. Call init_database() first.")
    return _db_pool

async def close_database():
    """Close database connection pool"""
    global _db_pool
    
    if _db_pool:
        await _db_pool.close()
        _db_pool = None
        logger.info("Database connection pool closed")

async def test_database_connection():
    """Test database connectivity"""
    try:
        pool = get_db_pool()
        async with pool.acquire() as conn:
            result = await conn.fetchval('SELECT 1')
            return result == 1
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False

async def execute_query(query: str, *args):
    """Execute a database query"""
    try:
        pool = get_db_pool()
        async with pool.acquire() as conn:
            return await conn.execute(query, *args)
    except Exception as e:
        logger.error(f"Query execution failed: {e}")
        raise

async def fetch_one(query: str, *args):
    """Fetch one row from database"""
    try:
        pool = get_db_pool()
        async with pool.acquire() as conn:
            return await conn.fetchrow(query, *args)
    except Exception as e:
        logger.error(f"Fetch one failed: {e}")
        raise

async def fetch_all(query: str, *args):
    """Fetch all rows from database"""
    try:
        pool = get_db_pool()
        async with pool.acquire() as conn:
            return await conn.fetch(query, *args)
    except Exception as e:
        logger.error(f"Fetch all failed: {e}")
        raise

async def fetch_value(query: str, *args):
    """Fetch single value from database"""
    try:
        pool = get_db_pool()
        async with pool.acquire() as conn:
            return await conn.fetchval(query, *args)
    except Exception as e:
        logger.error(f"Fetch value failed: {e}")
        raise

class DatabaseTransaction:
    """Context manager for database transactions"""
    
    def __init__(self):
        self.conn = None
        self.transaction = None
    
    async def __aenter__(self):
        pool = get_db_pool()
        self.conn = await pool.acquire()
        self.transaction = self.conn.transaction()
        await self.transaction.start()
        return self.conn
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            await self.transaction.rollback()
        else:
            await self.transaction.commit()
        
        await self.conn.close()

async def with_transaction(func, *args, **kwargs):
    """Execute function within a database transaction"""
    async with DatabaseTransaction() as conn:
        return await func(conn, *args, **kwargs)

class DatabaseMigrator:
    """Database migration utilities"""
    
    @staticmethod
    async def create_migration_table():
        """Create migrations tracking table"""
        query = """
        CREATE TABLE IF NOT EXISTS migrations (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL UNIQUE,
            applied_at TIMESTAMP DEFAULT NOW()
        )
        """
        await execute_query(query)
    
    @staticmethod
    async def has_migration(name: str) -> bool:
        """Check if migration has been applied"""
        result = await fetch_value(
            "SELECT COUNT(*) FROM migrations WHERE name = $1", name
        )
        return result > 0
    
    @staticmethod
    async def record_migration(name: str):
        """Record that migration has been applied"""
        await execute_query(
            "INSERT INTO migrations (name) VALUES ($1)", name
        )
    
    @staticmethod
    async def run_migration(name: str, migration_sql: str):
        """Run a database migration"""
        if await DatabaseMigrator.has_migration(name):
            logger.info(f"Migration {name} already applied")
            return
        
        try:
            async with DatabaseTransaction() as conn:
                await conn.execute(migration_sql)
                await conn.execute(
                    "INSERT INTO migrations (name) VALUES ($1)", name
                )
            logger.info(f"Migration {name} applied successfully")
        except Exception as e:
            logger.error(f"Migration {name} failed: {e}")
            raise

async def check_database_health() -> dict:
    """Check database health and return status"""
    try:
        pool = get_db_pool()
        
        # Test basic connectivity
        async with pool.acquire() as conn:
            await conn.fetchval('SELECT 1')
        
        # Get pool stats
        pool_size = pool.get_size()
        pool_idle = pool.get_idle_size()
        
        return {
            'status': 'healthy',
            'pool_size': pool_size,
            'pool_idle': pool_idle,
            'pool_busy': pool_size - pool_idle
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e)
        }

async def cleanup_expired_tokens():
    """Cleanup expired API tokens"""
    try:
        result = await execute_query("""
            DELETE FROM api_tokens 
            WHERE expires_at < NOW()
        """)
        logger.info(f"Cleaned up expired tokens: {result}")
    except Exception as e:
        logger.error(f"Token cleanup failed: {e}")

async def cleanup_old_audit_logs(days: int = 90):
    """Cleanup old audit logs"""
    try:
        result = await execute_query("""
            DELETE FROM audit_logs 
            WHERE created_at < NOW() - INTERVAL '%s days'
        """ % days)
        logger.info(f"Cleaned up old audit logs: {result}")
    except Exception as e:
        logger.error(f"Audit log cleanup failed: {e}")

async def get_database_stats() -> dict:
    """Get database statistics"""
    try:
        stats = {}
        
        # Table row counts
        tables = ['organizations', 'users', 'transactions', 'audit_logs', 'bulk_payments']
        for table in tables:
            count = await fetch_value(f"SELECT COUNT(*) FROM {table}")
            stats[f"{table}_count"] = count
        
        # Recent activity
        stats['recent_transactions'] = await fetch_value("""
            SELECT COUNT(*) FROM transactions 
            WHERE created_at >= NOW() - INTERVAL '24 hours'
        """)
        
        stats['recent_logins'] = await fetch_value("""
            SELECT COUNT(*) FROM login_attempts 
            WHERE attempted_at >= NOW() - INTERVAL '24 hours' AND success = true
        """)
        
        return stats
    except Exception as e:
        logger.error(f"Failed to get database stats: {e}")
        return {}

class ConnectionManager:
    """Database connection manager for long-running operations"""
    
    def __init__(self):
        self.connections = {}
    
    async def get_connection(self, identifier: str):
        """Get or create a connection for identifier"""
        if identifier not in self.connections:
            pool = get_db_pool()
            self.connections[identifier] = await pool.acquire()
        return self.connections[identifier]
    
    async def close_connection(self, identifier: str):
        """Close connection for identifier"""
        if identifier in self.connections:
            await self.connections[identifier].close()
            del self.connections[identifier]
    
    async def close_all(self):
        """Close all managed connections"""
        for conn in self.connections.values():
            await conn.close()
        self.connections.clear()
