import os
import sys
import logging
import asyncio
from flask import Flask
from flask_cors import CORS

# Your existing imports (unchanged)
from config import Config
from utils.database import init_database
from routes.auth_routes import auth_bp
from routes.mpesa_routes import mpesa_bp
from routes.admin_routes import admin_bp
from routes.callback_routes import callback_bp

# NEW: MCP imports
from mcp.server.stdio import stdio_server
from mcp.server.sse import SseServerTransport
from mcp.server import Server

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_flask_app():
    """Create and configure Flask application (UNCHANGED)"""
    app = Flask(__name__)
    CORS(app)
    
    # Load configuration
    app.config['SECRET_KEY'] = Config.SECRET_KEY
    
    # Initialize database before first request
    @app.before_first_request
    async def init_app():
        """Initialize the application"""
        await init_database()
    
    # Register blueprints (SAME as before)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(mpesa_bp, url_prefix='/tools')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(callback_bp, url_prefix='/mpesa')
    
    return app

async def run_mcp_server():
    """Run MCP server for AI integration"""
    from mcp.server import MPesaMCPServer
    
    mcp_server = MPesaMCPServer()
    
    # Run via stdio (standard for MCP)
    async with stdio_server() as (read_stream, write_stream):
        logger.info("🤖 MCP Server started - AI clients can now connect!")
        await mcp_server.run(
            Server.create_transport(read_stream, write_stream)
        )

def run_flask_server():
    """Run Flask REST API server for human clients"""
    from dotenv import load_dotenv
    load_dotenv()
    
    app = create_flask_app()
    logger.info(f"🌐 REST API Server starting on {Config.FLASK_HOST}:{Config.FLASK_PORT}")
    logger.info(f"📍 Endpoints available:")
    logger.info(f"   • Authentication: http://{Config.FLASK_HOST}:{Config.FLASK_PORT}/auth/")
    logger.info(f"   • M-Pesa Tools: http://{Config.FLASK_HOST}:{Config.FLASK_PORT}/tools/")
    logger.info(f"   • Admin Panel: http://{Config.FLASK_HOST}:{Config.FLASK_PORT}/admin/")
    logger.info(f"   • Callbacks: http://{Config.FLASK_HOST}:{Config.FLASK_PORT}/mpesa/")
    
    app.run(
        host=Config.FLASK_HOST,
        port=Config.FLASK_PORT,
        debug=Config.FLASK_DEBUG
    )

async def run_hybrid_server():
    """Run both REST API and MCP server simultaneously"""
    logger.info("🚀 Starting HYBRID M-Pesa Server...")
    logger.info("📊 Multi-tenant SaaS with dual protocol support:")
    logger.info("   • REST API for web/mobile clients")
    logger.info("   • MCP Protocol for AI integration")
    
    # Run both servers concurrently
    await asyncio.gather(
        asyncio.create_task(run_mcp_server()),
        asyncio.create_task(
            asyncio.to_thread(run_flask_server)
        )
    )

def main():
    """Main entry point - supports multiple modes"""
    import argparse
    
    parser = argparse.ArgumentParser(description='M-Pesa Multi-tenant Server')
    parser.add_argument('--mode', choices=['rest', 'mcp', 'hybrid'], 
                       default='hybrid', help='Server mode to run')
    
    args = parser.parse_args()
    
    if args.mode == 'rest':
        logger.info("🌐 Starting REST API mode only")
        run_flask_server()
        
    elif args.mode == 'mcp':
        logger.info("🤖 Starting MCP mode only")
        asyncio.run(run_mcp_server())
        
    else:  # hybrid (default)
        logger.info("🔥 Starting HYBRID mode - REST + MCP")
        asyncio.run(run_hybrid_server())

if __name__ == '__main__':
    main()
