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


def create_user_helper(client, username, password, roles=None):
    """Helper function to create additional users in tests."""
    with client.application.app_context():
        user = user_datastore.create_user(
            email=f'{username}@test.com',
            username=username,
            password=hash_password(password),
            roles=roles or []
        )
        db.session.commit()
        return {'username': username, 'password': password, 'id': user.id}


class TestRecordCRUD:
    """Tests for Record CRUD operations (create, read, update, delete)."""

    def test_create_records_page_requires_auth(self, client):
        """Test that create_records page requires authentication."""
        response = client.get('/create_records')
        assert response.status_code == 302
        assert '/login' in response.location

    def test_create_records_page_loads(self, auth_client):
        """Test that authenticated users can access create_records page."""
        response = auth_client.get('/create_records')
        assert response.status_code == 200
        # Check for form elements
        assert b'form' in response.data.lower() or b'date' in response.data.lower()

    def test_create_record_success(self, auth_client):
        """Test successful record creation."""
        response = auth_client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>Test content</p>'
        }, follow_redirects=True)
        assert response.status_code == 200
        # Verify record exists in database
        with auth_client.application.app_context():
            record = Record.query.filter_by(content='<p>Test content</p>').first()
            assert record is not None
            assert record.date == date(2026, 3, 23)

    def test_create_record_missing_fields(self, auth_client):
        """Test record creation with missing required fields."""
        response = auth_client.post('/create_records', data={
            'date': '',  # Missing date
            'body': '<p>Test content</p>'
        }, follow_redirects=True)
        assert response.status_code == 200
        # Should show validation error or stay on form

    def test_manage_records_page_loads(self, auth_client):
        """Test that manage_records page loads for authenticated users."""
        response = auth_client.get('/manage_records')
        assert response.status_code == 200

    def test_manage_records_shows_user_records(self, auth_client, test_user):
        """Test that manage_records shows records owned by the user."""
        # First create a record
        auth_client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>User record content</p>'
        }, follow_redirects=True)
        # Then check it appears on manage_records
        response = auth_client.get('/manage_records')
        assert response.status_code == 200
        assert b'User record content' in response.data or b'2026-03-23' in response.data

    def test_edit_record_page_loads(self, auth_client):
        """Test that edit_record page loads for record owner."""
        # First create a record
        auth_client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>Original content</p>'
        }, follow_redirects=True)
        # Then access edit page
        response = auth_client.get('/edit_record/1')
        assert response.status_code == 200
        # Check form is pre-populated
        assert b'Original content' in response.data or b'2026-03-23' in response.data

    def test_edit_record_success(self, auth_client):
        """Test successful record edit."""
        # First create a record
        auth_client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>Original content</p>'
        }, follow_redirects=True)
        # Then edit it
        response = auth_client.post('/edit_record/1', data={
            'date': '2026-03-24',
            'body': '<p>Updated content</p>'
        }, follow_redirects=True)
        assert response.status_code == 200
        # Verify record updated in database
        with auth_client.application.app_context():
            record = db.session.get(Record, 1)
            assert record is not None
            assert record.content == '<p>Updated content</p>'
            assert record.date == date(2026, 3, 24)

    def test_edit_record_not_found(self, auth_client):
        """Test editing a non-existent record returns 404."""
        response = auth_client.get('/edit_record/99999')
        assert response.status_code == 404

    def test_edit_record_forbidden(self, client, test_user):
        """Test that user cannot edit another user's record."""
        # Create user A (test_user) and a record owned by A
        client.post('/login', data={
            'username': test_user['username'],
            'password': test_user['password']
        })
        client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>User A record</p>'
        }, follow_redirects=True)
        client.get('/logout', follow_redirects=True)

        # Create user B
        create_user_helper(client, 'userb', 'UserBPass123')

        # Login as user B and try to edit user A's record
        client.post('/login', data={
            'username': 'userb',
            'password': 'UserBPass123'
        })
        response = client.get('/edit_record/1')
        assert response.status_code == 403

    def test_delete_record_success(self, auth_client):
        """Test successful record deletion."""
        # First create a record
        auth_client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>Record to delete</p>'
        }, follow_redirects=True)
        # Then delete it
        response = auth_client.post('/delete_record/1', follow_redirects=True)
        assert response.status_code == 200
        # Verify record removed from database
        with auth_client.application.app_context():
            record = db.session.get(Record, 1)
            assert record is None

    def test_delete_record_not_found(self, auth_client):
        """Test deleting a non-existent record returns 404."""
        response = auth_client.post('/delete_record/99999')
        assert response.status_code == 404

    def test_delete_record_forbidden(self, client, test_user):
        """Test that user cannot delete another user's record."""
        # Create user A (test_user) and a record owned by A
        client.post('/login', data={
            'username': test_user['username'],
            'password': test_user['password']
        })
        client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>User A record to protect</p>'
        }, follow_redirects=True)
        client.get('/logout', follow_redirects=True)

        # Create user B
        create_user_helper(client, 'userc', 'UserCPass123')

        # Login as user B and try to delete user A's record
        client.post('/login', data={
            'username': 'userc',
            'password': 'UserCPass123'
        })
        response = client.post('/delete_record/1')
        assert response.status_code == 403

    def test_admin_can_edit_any_record(self, client, test_user):
        """Test that admin user can edit any record."""
        # Create user A (test_user) and a record owned by A
        client.post('/login', data={
            'username': test_user['username'],
            'password': test_user['password']
        })
        client.post('/create_records', data={
            'date': '2026-03-23',
            'body': '<p>User record for admin test</p>'
        }, follow_redirects=True)
        client.get('/logout', follow_redirects=True)

        # Create admin user with view_all permission
        with client.application.app_context():
            admin_role = Role(name='admin', description='Admin', permissions=['view_all', 'edit_database'])
            db.session.add(admin_role)
            db.session.commit()
            admin_user = create_user_helper(client, 'adminuser', 'AdminPass123', roles=[admin_role])

        # Login as admin and edit user A's record
        client.post('/login', data={
            'username': admin_user['username'],
            'password': admin_user['password']
        })
        response = client.get('/edit_record/1')
        assert response.status_code == 200  # Admin can access edit page