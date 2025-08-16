import os
import logging
from flask import Flask
from flask_cors import CORS

from config import Config
from utils.database import init_database
from routes.auth_routes import auth_bp
from routes.mpesa_routes import mpesa_bp
from routes.admin_routes import admin_bp
from routes.callback_routes import callback_bp

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    CORS(app)
    
    # Load configuration
    app.config['SECRET_KEY'] = Config.SECRET_KEY
    
    # Initialize database before first request
    @app.before_first_request
    async def init_app():
        """Initialize the application"""
        await init_database()
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(mpesa_bp, url_prefix='/tools')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(callback_bp, url_prefix='/mpesa')
    
    return app

def main():
    """Main entry point"""
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Create and run Flask app
    app = create_app()
    app.run(
        host=Config.FLASK_HOST,
        port=Config.FLASK_PORT,
        debug=Config.FLASK_DEBUG
    )

if __name__ == '__main__':
    main()
