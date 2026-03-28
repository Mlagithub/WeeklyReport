"""
Database models and association tables.

This module contains all SQLAlchemy model definitions extracted from app.py.
Association tables are defined first to ensure they exist before models reference them.
Per D-10: Record.date has index=True for query optimization.
"""

from datetime import datetime
from functools import wraps

from flask import current_app, flash, g, redirect, request, url_for
from flask_admin.contrib.sqla import ModelView
from flask_security import current_user
from flask_security.models.sqla import FsRoleMixin, FsUserMixin
from flask_security.utils import hash_password
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload

from extensions import db

# =============================================================================
# Association Tables
# Defined BEFORE models that reference them to avoid SQLAlchemy errors.
# =============================================================================

user_records = db.Table(
    "user_records",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("record_id", db.Integer, db.ForeignKey("record.id"), primary_key=True),
)

roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("role_id", db.Integer, db.ForeignKey("role.id"), primary_key=True),
)

users_groups = db.Table(
    "users_groups",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column("group_id", db.Integer, db.ForeignKey("group.id"), primary_key=True),
)


# =============================================================================
# Decorator for database transactions
# =============================================================================


def with_db_transaction(func):
    """
    Decorator for database write operations.
    Per D-03: Unified error handling
    Per D-05: try/except/rollback/re-raise pattern
    Per D-06: Rollback on exception
    Per D-07: Re-raise after rollback
    Per D-08: Flash generic user message
    Per D-09: Log full stack trace
    Per D-10: Use current_app.logger.error()
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SQLAlchemyError as e:
            # Log full exception with stack trace (D-09, D-10)
            current_app.logger.error(f"Database error in {func.__name__}: {str(e)}", exc_info=True)
            # Rollback the transaction (D-06)
            db.session.rollback()
            # Flash user-friendly message (D-08)
            flash("操作失败，请重试", "warning")
            # Re-raise for Flask error handler (D-07)
            raise

    return wrapper


# =============================================================================
# Model Classes
# =============================================================================


class Record(db.Model):
    """Weekly report record model."""

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    date = db.Column(db.Date(), index=True)  # Added index per D-10
    createtime = db.Column(db.DateTime, default=datetime.utcnow)


class Role(db.Model, FsRoleMixin):
    """User role model for Flask-Security."""

    __tablename__ = "role"


class User(db.Model, FsUserMixin):
    """User model with permission-related methods."""

    __tablename__ = "user"
    email = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), unique=False, nullable=False)
    records = db.relationship("Record", secondary="user_records", backref="user")

    @property
    def is_admin(self):
        """Check if user has admin role."""
        return any(role.name == "admin" for role in self.roles)

    @staticmethod
    def with_role(role_name):
        """Check if current user has a specific role."""
        if current_user.is_authenticated:
            return any(role.name == role_name for role in current_user.roles)
        else:
            return False

    @staticmethod
    def can_view_group(group):
        """Check if current user can view a specific group's records."""
        all_permissions = User.all_permissions(current_user)
        if "view_all" in all_permissions or (
            "view_group" in all_permissions and any(g.name == group.name for g in current_user.groups)
        ):
            return True
        else:
            return False

    @staticmethod
    def all_permissions(user):
        """Get all permissions for a user (request-level cached to avoid stale permissions)."""
        cache_key = f"_user_perms_{user.id}"
        if not hasattr(g, cache_key):
            perms = tuple(set(p for role in user.roles for p in role.permissions))
            setattr(g, cache_key, perms)
        return list(getattr(g, cache_key))

    @staticmethod
    def managed_group(user):
        """Get groups managed by user (uses eager loading to avoid N+1 queries)."""
        groups = []
        all_permissions = User.all_permissions(user)
        if "view_all" in all_permissions:
            groups = Group.query.options(joinedload(Group.users)).all()
        elif "view_group" in all_permissions:
            # Use eager loading for groups and users
            user_with_groups = (
                User.query.options(joinedload(User.groups).joinedload(Group.users)).filter_by(id=user.id).first()
            )
            if user_with_groups:
                groups = [g for g in user_with_groups.groups if User.can_view_group(g)]

        return groups

    @staticmethod
    @with_db_transaction
    def change_user_password(username, password):
        """Change a user's password by username."""
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = hash_password(password)
            db.session.commit()
            flash("密码已更改")
            return True
        else:
            flash(f"用户{username}不存在", "warning")
            return False


class Group(db.Model):
    """Group model for organizing users."""

    __tablename__ = "group"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    users = db.relationship("User", secondary="users_groups", backref="groups")

    @staticmethod
    def list_all(user=None):
        """List all groups or groups visible to a specific user."""
        if user:
            return [g for g in user.groups if User.can_view_group(g)]
        else:
            return Group.query.options(joinedload(Group.users)).all()

    def __repr__(self):
        return f"{self.name}"


class AIConfig(db.Model):
    """AI service configuration model - single system-wide config.

    Per CONFIG-03: Configuration persists in database.
    Per SEC-01: API Key encrypted, not plaintext.
    Per CONTEXT.md: Single record - one AI config for the whole system.
    """

    __tablename__ = "ai_config"

    id = db.Column(db.Integer, primary_key=True)
    api_url = db.Column(db.String(255), nullable=False)
    api_key_encrypted = db.Column(db.Text, nullable=False)  # Encrypted storage per SEC-01
    model_name = db.Column(db.String(100), nullable=False)
    polish_prompt = db.Column(db.Text, nullable=True)  # Per POLISH-02: Admin configurable polish prompt

    DEFAULT_POLISH_PROMPT = "请对以下文本进行润色，使其更加专业、流畅、简洁。保持原有内容和意思不变，优化表达方式："

    @staticmethod
    def get_config():
        """Get the single AI config record or None if not configured.

        Per CONTEXT.md: Show config form with empty fields if missing.
        """
        return AIConfig.query.first()

    @property
    def masked_key(self):
        """Get masked API key for display (last 4 chars visible).

        Per CONTEXT.md D-locked: Show masked value in UI.
        Per UI-SPEC.md: Masked display format '****abcd'.
        """
        from ai_utils import decrypt_api_key, mask_api_key

        try:
            decrypted = decrypt_api_key(self.api_key_encrypted)
            return mask_api_key(decrypted)
        except Exception:
            # If decryption fails, return placeholder
            return "****"


class AITemplate(db.Model):
    """AI prompt template model for report generation.

    Per TEMPLATE-01: Template storage with name and content.
    Per TEMPLATE-02: Placeholder support for {time_range}, {user_name}, {records}, {record_count}, {date_range}.
    """

    __tablename__ = "ai_template"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    time_range = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def get_by_time_range(time_range):
        """Get all templates for a specific time range.

        Args:
            time_range: One of "weekly", "monthly", "quarterly", "yearly"

        Returns:
            List of AITemplate objects matching the time range.
        """
        return AITemplate.query.filter_by(time_range=time_range).all()

    def __repr__(self):
        return f"<AITemplate {self.name}>"


# =============================================================================
# Flask-Admin View
# =============================================================================


class UserModelView(ModelView):
    """Custom ModelView for Flask-Admin with permission checks."""

    def __init__(self, model, session, **kwargs):
        # For User model, limit related fields to avoid loading large data
        if model == User:
            self.form_ajax_refs = {
                "roles": {"fields": ["name"]},
            }
            self.form_excluded_columns = ["records"]
        elif model == Record:
            # Record view uses pagination and lazy loading
            self.column_filters = ["date", "content"]
            self.page_size = 20
        super().__init__(model, session, **kwargs)

    def is_accessible(self):
        """Check if current user can access admin panel."""
        if not current_user.is_authenticated:
            return False
        permissions = User.all_permissions(current_user)
        return current_user.is_admin or "edit_database" in permissions

    def inaccessible_callback(self, name, **kwargs):
        """Redirect to login if not accessible."""
        return redirect(url_for("login", next=request.url))
