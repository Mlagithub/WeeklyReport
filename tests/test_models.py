"""
Unit tests for User model permission methods.
"""
import pytest
from flask import g
from app import app, db, user_datastore, User, Role, Group
from flask_security.utils import hash_password


class TestUserPermissions:
    """Tests for User model permission methods."""

    def test_is_admin_true_for_admin_role(self, client):
        """Admin users should have is_admin property return True."""
        with client.application.app_context():
            # Create admin role
            admin_role = Role(name='admin', permissions=['view_all', 'edit_database'])
            db.session.add(admin_role)

            # Create admin user
            user = user_datastore.create_user(
                email='admin@example.com',
                username='adminuser',
                password=hash_password('AdminPass123'),
                roles=[admin_role]
            )
            db.session.commit()

            assert user.is_admin is True

    def test_is_admin_false_for_non_admin(self, client):
        """Non-admin users should have is_admin property return False."""
        with client.application.app_context():
            # Create employee role without admin
            employee_role = Role(name='employee', permissions=['view_self'])
            db.session.add(employee_role)

            # Create regular user
            user = user_datastore.create_user(
                email='employee@example.com',
                username='employeeuser',
                password=hash_password('EmpPass123'),
                roles=[employee_role]
            )
            db.session.commit()

            assert user.is_admin is False

    def test_all_permissions_returns_list(self, client):
        """all_permissions should return a list of permission strings."""
        with client.application.app_context():
            # Create role with specific permissions
            role = Role(name='team_lead', permissions=['view_self', 'view_group'])
            db.session.add(role)

            # Create user with that role
            user = user_datastore.create_user(
                email='lead@example.com',
                username='leaduser',
                password=hash_password('LeadPass123'),
                roles=[role]
            )
            db.session.commit()

            # Clear any cached permissions
            cache_key = f'_user_perms_{user.id}'
            if hasattr(g, cache_key):
                delattr(g, cache_key)

            result = User.all_permissions(user)

            assert isinstance(result, list)
            assert 'view_self' in result
            assert 'view_group' in result

    def test_all_permissions_caches_result(self, client):
        """all_permissions should cache results on the g object."""
        with client.application.app_context():
            # Create role with permissions
            role = Role(name='employee', permissions=['view_self'])
            db.session.add(role)

            user = user_datastore.create_user(
                email='emp2@example.com',
                username='emp2user',
                password=hash_password('EmpPass123'),
                roles=[role]
            )
            db.session.commit()

            # Clear cache first
            cache_key = f'_user_perms_{user.id}'
            if hasattr(g, cache_key):
                delattr(g, cache_key)

            # First call
            result1 = User.all_permissions(user)
            # Second call should use cache
            result2 = User.all_permissions(user)

            assert result1 == result2
            assert hasattr(g, cache_key)

    def test_can_view_group_with_view_all_permission(self, client):
        """User with view_all can view any group."""
        with client.application.app_context():
            # Create admin role with view_all
            admin_role = Role(name='admin', permissions=['view_all'])
            db.session.add(admin_role)

            user = user_datastore.create_user(
                email='admin2@example.com',
                username='admin2user',
                password=hash_password('AdminPass123'),
                roles=[admin_role]
            )

            # Create a group
            group = Group(name='TestGroup', description='Test group')
            db.session.add(group)
            db.session.commit()

        # Login as the user to set current_user
        client.post('/login', data={
            'username': 'admin2user',
            'password': 'AdminPass123'
        })

        with client.application.app_context():
            group = Group.query.filter_by(name='TestGroup').first()
            assert User.can_view_group(group) is True

    def test_can_view_group_with_view_group_permission(self, client):
        """User with view_group can only view groups they belong to."""
        with client.application.app_context():
            # Create role with view_group
            leader_role = Role(name='leader', permissions=['view_group'])
            db.session.add(leader_role)

            user = user_datastore.create_user(
                email='leader@example.com',
                username='leaderuser',
                password=hash_password('LeaderPass123'),
                roles=[leader_role]
            )

            # Create groups
            own_group = Group(name='OwnGroup', description='Own group')
            other_group = Group(name='OtherGroup', description='Other group')
            db.session.add_all([own_group, other_group])

            # Add user to own_group
            user.groups.append(own_group)
            db.session.commit()

        # Login as the user
        client.post('/login', data={
            'username': 'leaderuser',
            'password': 'LeaderPass123'
        })

        with client.application.app_context():
            own_group = Group.query.filter_by(name='OwnGroup').first()
            other_group = Group.query.filter_by(name='OtherGroup').first()
            # Should be able to view own group
            assert User.can_view_group(own_group) is True
            # Should not be able to view other group
            assert User.can_view_group(other_group) is False

    def test_can_view_group_without_permission(self, client):
        """User without view_all or view_group cannot view any groups."""
        with client.application.app_context():
            # Create role without view permissions
            basic_role = Role(name='basic', permissions=[])
            db.session.add(basic_role)

            user = user_datastore.create_user(
                email='basic@example.com',
                username='basicuser',
                password=hash_password('BasicPass123'),
                roles=[basic_role]
            )

            # Create a group
            group = Group(name='SomeGroup', description='Some group')
            db.session.add(group)
            db.session.commit()

        # Login as the user
        client.post('/login', data={
            'username': 'basicuser',
            'password': 'BasicPass123'
        })

        with client.application.app_context():
            group = Group.query.filter_by(name='SomeGroup').first()
            assert User.can_view_group(group) is False

    def test_managed_group_view_all(self, client):
        """Admin with view_all should manage all groups."""
        with client.application.app_context():
            # Create admin role
            admin_role = Role(name='admin', permissions=['view_all'])
            db.session.add(admin_role)

            user = user_datastore.create_user(
                email='admin3@example.com',
                username='admin3user',
                password=hash_password('AdminPass123'),
                roles=[admin_role]
            )

            # Create multiple groups
            group1 = Group(name='GroupA', description='Group A')
            group2 = Group(name='GroupB', description='Group B')
            group3 = Group(name='GroupC', description='Group C')
            db.session.add_all([group1, group2, group3])
            db.session.commit()

        # Login to set current_user for can_view_group
        client.post('/login', data={
            'username': 'admin3user',
            'password': 'AdminPass123'
        })

        with client.application.app_context():
            user = User.query.filter_by(username='admin3user').first()
            managed = User.managed_group(user)

            assert len(managed) == 3
            group_names = [g.name for g in managed]
            assert 'GroupA' in group_names
            assert 'GroupB' in group_names
            assert 'GroupC' in group_names

    def test_managed_group_view_group(self, client):
        """Leader with view_group should only manage groups they belong to."""
        with client.application.app_context():
            # Create role with view_group
            leader_role = Role(name='groupleader', permissions=['view_group'])
            db.session.add(leader_role)

            user = user_datastore.create_user(
                email='leader2@example.com',
                username='leader2user',
                password=hash_password('LeaderPass123'),
                roles=[leader_role]
            )

            # Create groups
            own_group = Group(name='ManagedGroup', description='Managed group')
            other_group = Group(name='UnmanagedGroup', description='Unmanaged group')
            db.session.add_all([own_group, other_group])

            # Add user to own_group
            user.groups.append(own_group)
            db.session.commit()

        # Login to set current_user for can_view_group
        client.post('/login', data={
            'username': 'leader2user',
            'password': 'LeaderPass123'
        })

        with client.application.app_context():
            user = User.query.filter_by(username='leader2user').first()
            managed = User.managed_group(user)

            assert len(managed) == 1
            assert managed[0].name == 'ManagedGroup'