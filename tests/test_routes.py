"""Integration tests for authentication and CRUD routes."""

import pytest
from datetime import date
from app import app, db, user_datastore, User, Record, Role
from flask_security.utils import hash_password


class TestAuthentication:
    """Tests for authentication routes (login, register, logout)."""

    def test_login_page_loads(self, client):
        """Test that the login page loads successfully."""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'username' in response.data.lower() or b'login' in response.data.lower()

    def test_login_success(self, client, test_user):
        """Test successful login with valid credentials."""
        response = client.post('/login', data={
            'username': test_user['username'],
            'password': test_user['password']
        }, follow_redirects=True)
        assert response.status_code == 200
        # Verify user is logged in by accessing a protected route
        protected_response = client.get('/manage_records')
        assert protected_response.status_code == 200

    def test_login_invalid_password(self, client, test_user):
        """Test login with correct username but wrong password."""
        response = client.post('/login', data={
            'username': test_user['username'],
            'password': 'wrongpassword123'
        }, follow_redirects=True)
        assert response.status_code == 200
        # Should stay on login page (form re-rendered with error)
        # Check for flash message or form error indicator
        # Chinese: '用户名或密码不正确' (username or password incorrect)
        assert b'warning' in response.data or b'\xe4\xb8\x8d\xe6\xad\xa3\xe7\xa1\xae' in response.data or b'is-invalid' in response.data

    def test_login_nonexistent_user(self, client):
        """Test login with a username that doesn't exist."""
        response = client.post('/login', data={
            'username': 'nonexistentuser',
            'password': 'somepassword123'
        }, follow_redirects=True)
        assert response.status_code == 200
        # Should stay on login page (form re-rendered with error)
        # Check for flash message or form error indicator
        assert b'warning' in response.data or b'\xe4\xb8\x8d\xe6\xad\xa3\xe7\xa1\xae' in response.data or b'is-invalid' in response.data

    def test_register_page_loads(self, client):
        """Test that the registration page loads successfully."""
        response = client.get('/register')
        assert response.status_code == 200

    def test_register_new_user(self, client):
        """Test successful registration of a new user."""
        response = client.post('/register', data={
            'username': 'newuser',
            'password': 'NewPass123',
            'password_confirm': 'NewPass123'
        }, follow_redirects=True)
        assert response.status_code == 200
        # Verify user exists in database
        with client.application.app_context():
            user = User.query.filter_by(username='newuser').first()
            assert user is not None

    def test_register_duplicate_username(self, client, test_user):
        """Test registration with an already existing username."""
        response = client.post('/register', data={
            'username': test_user['username'],  # Same username as test_user
            'password': 'AnotherPass123',
            'password_confirm': 'AnotherPass123'
        }, follow_redirects=True)
        assert response.status_code == 200
        # Should show warning flash message about existing username
        # Chinese: '用户名已存在'
        assert b'warning' in response.data or b'\xe5\xb7\xb2\xe5\xad\x98\xe5\x9c\xa8' in response.data

    def test_register_password_mismatch(self, client):
        """Test registration with password confirmation mismatch."""
        response = client.post('/register', data={
            'username': 'mismatchuser',
            'password': 'Password123',
            'password_confirm': 'DifferentPassword123'
        }, follow_redirects=True)
        assert response.status_code == 200
        # Should show validation error

    def test_logout(self, auth_client):
        """Test successful logout."""
        response = auth_client.get('/logout', follow_redirects=True)
        assert response.status_code == 200
        # Verify user is logged out - accessing protected route should redirect to login
        protected_response = auth_client.get('/manage_records')
        assert protected_response.status_code == 302
        assert '/login' in protected_response.location

    def test_protected_route_redirects_to_login(self, client):
        """Test that unauthenticated users are redirected to login for protected routes."""
        response = client.get('/manage_records')
        assert response.status_code == 302
        assert '/login' in response.location

    def test_home_requires_login(self, client):
        """Test that the home page requires authentication."""
        response = client.get('/')
        assert response.status_code == 302
        assert '/login' in response.location

    def test_home_authenticated(self, auth_client):
        """Test that authenticated users can access the home page."""
        response = auth_client.get('/')
        assert response.status_code == 200