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

    def test_manage_records_default_user_filter(self, auth_client, test_user):
        """Test that user dropdown defaults to current user when no URL param (FIND-01)."""
        response = auth_client.get('/manage_records')
        assert response.status_code == 200
        # Check that the current user's username appears as selected in the dropdown
        # The template should have the current user selected by default
        import re
        # Look for option with current user's username that has 'selected' attribute
        # Pattern matches: <option value="testuser" selected> or <option selected value="testuser">
        pattern = rf'<option[^>]*value="{test_user["username"]}"[^>]*selected[^>]*>'
        assert re.search(pattern, response.text), \
            f"Expected current user '{test_user['username']}' to be selected by default in user dropdown"

    def test_manage_records_default_time_filter(self, auth_client):
        """Test that time_range dropdown defaults to last_7_days when no URL param (FIND-02)."""
        response = auth_client.get('/manage_records')
        assert response.status_code == 200
        # Check that 'last_7_days' is selected by default in time_range dropdown
        import re
        # Pattern matches: <option value="last_7_days" selected> or similar
        pattern = r'<option[^>]*value="last_7_days"[^>]*selected[^>]*>'
        assert re.search(pattern, response.text), \
            "Expected 'last_7_days' to be selected by default in time_range dropdown"

    def test_manage_records_can_clear_filters(self, auth_client):
        """Test that user can still select empty value to clear filters (FIND-03)."""
        response = auth_client.get('/manage_records?user=&time_range=')
        assert response.status_code == 200
        # Verify "不限" options are available (empty value options)
        assert '<option value="">不限</option>' in response.text

class TestHomeRendering:
    """Integration tests for home page rich text rendering (RENDER-01)."""

    def test_home_shows_bold_text(self, auth_client):
        """Test that bold tags are rendered, not escaped."""
        # Create a record with bold content
        auth_client.post('/create_records', data={
            'date': '2026-03-26',
            'body': '<p>This is <b>bold</b> text</p>'
        }, follow_redirects=True)

        # Fetch home page
        response = auth_client.get('/')
        assert response.status_code == 200

        # Bold tag should appear in output (not escaped)
        # The sanitize_html filter preserves <b> tags
        assert b'<b>' in response.data or b'<strong>' in response.data

    def test_home_shows_italic_text(self, auth_client):
        """Test that italic tags are rendered, not escaped."""
        auth_client.post('/create_records', data={
            'date': '2026-03-26',
            'body': '<p>This is <i>italic</i> text</p>'
        }, follow_redirects=True)

        response = auth_client.get('/')
        assert response.status_code == 200

        # Italic tag should appear in output
        assert b'<i>' in response.data or b'<em>' in response.data

    def test_home_shows_list_items(self, auth_client):
        """Test that list tags are rendered correctly."""
        auth_client.post('/create_records', data={
            'date': '2026-03-26',
            'body': '<ul><li>Item 1</li><li>Item 2</li></ul>'
        }, follow_redirects=True)

        response = auth_client.get('/')
        assert response.status_code == 200

        # List tags should appear in output
        assert b'<ul>' in response.data or b'<li>' in response.data


class TestXSSPrevention:
    """Integration tests for XSS prevention on home page (RENDER-02)."""

    def test_xss_script_filtered_on_home(self, auth_client):
        """Test that script tags are escaped in user content on home page."""
        # Create a record with XSS attempt
        auth_client.post('/create_records', data={
            'date': '2026-03-26',
            'body': '<script>alert("xss")</script><p>safe content</p>'
        }, follow_redirects=True)

        response = auth_client.get('/')
        assert response.status_code == 200

        # Script tag in user content should be escaped (bleach removes it)
        # The XSS payload should NOT appear as raw executable script
        # Check that safe content is preserved and script is escaped
        assert b'safe content' in response.data
        # The script content should be escaped, not rendered as HTML script
        assert b'&lt;script&gt;' in response.data or b'<script>alert' not in response.data

    def test_xss_onclick_filtered_on_home(self, auth_client):
        """Test that onclick attributes are removed from home page."""
        auth_client.post('/create_records', data={
            'date': '2026-03-26',
            'body': '<a onclick="evil()">click me</a>'
        }, follow_redirects=True)

        response = auth_client.get('/')
        assert response.status_code == 200

        # onclick should NOT appear in output
        assert b'onclick' not in response.data

    def test_xss_javascript_url_filtered_on_home(self, auth_client):
        """Test that javascript: URLs are removed from home page."""
        auth_client.post('/create_records', data={
            'date': '2026-03-26',
            'body': '<a href="javascript:alert(1)">dangerous link</a>'
        }, follow_redirects=True)

        response = auth_client.get('/')
        assert response.status_code == 200

        # javascript: should NOT appear in href
        assert b'javascript:' not in response.data

    def test_xss_onerror_filtered_on_home(self, auth_client):
        """Test that onerror attributes are removed from home page."""
        auth_client.post('/create_records', data={
            'date': '2026-03-26',
            'body': '<img src="x" onerror="alert(1)">'
        }, follow_redirects=True)

        response = auth_client.get('/')
        assert response.status_code == 200

        # onerror should NOT appear in output
        assert b'onerror' not in response.data
