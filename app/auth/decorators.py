from functools import wraps
from flask import abort, redirect, url_for, flash
from flask_login import current_user

def role_required(*roles):
    """
    Decorator to restrict view access to specific user roles.
    Example: @role_required('admin', 'finance')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            
            # Check if user's role matches any of the allowed roles
            if current_user.role not in roles:
                # Flask automatically routes this to the 403 error handler we defined
                abort(403)
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """Decorator to restrict access to Admins only."""
    return role_required('admin')(f)
