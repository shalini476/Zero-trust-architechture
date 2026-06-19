"""
Zero Trust Security Platform — Role-Based Access Decorators
Zerofox

Custom decorators that enforce role-based access control (RBAC) on routes.
All decorators must be applied AFTER @login_required to ensure the user
is authenticated before checking their role.

Usage:
    from app.decorators import admin_required, role_required

    @app.route('/admin-only')
    @login_required
    @admin_required
    def admin_view():
        ...
"""

from functools import wraps

from flask import abort, flash, redirect, url_for
from flask_login import current_user


def admin_required(f):
    """
    Decorator that restricts access to users with the 'admin' role.
    Returns HTTP 403 Forbidden for non-admin users.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles):
    """
    Decorator that restricts access to users whose role is in the provided list.

    Args:
        *roles: One or more role strings (e.g. 'admin', 'hr', 'finance').

    Example:
        @role_required('admin', 'hr')
        def hr_panel():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def login_required_with_trust(min_trust: int = 0):
    """
    Decorator that requires authentication AND a minimum trust score.
    Users below the threshold are shown a warning and redirected.

    Args:
        min_trust: Minimum trust score required (0-100).
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if current_user.trust_score < min_trust:
                flash(
                    f'Access denied: your trust score ({current_user.trust_score}) '
                    f'is below the required minimum ({min_trust}).',
                    'danger'
                )
                return redirect(url_for('dashboard.user_dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
