"""
API routes and endpoints
"""

from .auth_routes import auth_bp
from .mpesa_routes import mpesa_bp
from .admin_routes import admin_bp
from .callback_routes import callback_bp

__all__ = ['auth_bp', 'mpesa_bp', 'admin_bp', 'callback_bp']
