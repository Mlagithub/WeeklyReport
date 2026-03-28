"""
Unit tests for User model permission methods and authorization functions.
"""
import pytest
from flask import g
from flask_security.core import AnonymousUser
from flask_security.utils import hash_password

from app import (
    Group,
    Record,
    Role,
    User,
    app,
    can_edit_record,
    db,
    get_allowed_groups,
    get_allowed_usernames,
    user_datastore,
)


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


class TestAuthorizationFunctions:
    """Tests for authorization helper functions."""

    def test_can_edit_record_owner(self, client):
        """Record owner should be able to edit their own record."""
        with client.application.app_context():
            # Create user and role
            role = Role(name='employee', permissions=['view_self'])
            db.session.add(role)

            user = user_datastore.create_user(
                email='owner@example.com',
                username='owneruser',
                password=hash_password('OwnerPass123'),
                roles=[role]
            )
            db.session.commit()

            # Create record owned by user
            record = Record(content='Test content')
            record.user.append(user)
            db.session.add(record)
            db.session.commit()

            assert can_edit_record(record, user) is True

    def test_can_edit_record_admin(self, client):
        """Admin with view_all should be able to edit any record."""
        with client.application.app_context():
            # Create admin
            admin_role = Role(name='admin', permissions=['view_all'])
            db.session.add(admin_role)

            admin = user_datastore.create_user(
                email='admin4@example.com',
                username='admin4user',
                password=hash_password('AdminPass123'),
                roles=[admin_role]
            )

            # Create another user's record
            other_role = Role(name='employee', permissions=['view_self'])
            db.session.add(other_role)

            other_user = user_datastore.create_user(
                email='other@example.com',
                username='otheruser',
                password=hash_password('OtherPass123'),
                roles=[other_role]
            )

            record = Record(content='Other user content')
            record.user.append(other_user)
            db.session.add(record)
            db.session.commit()

            assert can_edit_record(record, admin) is True

    def test_can_edit_record_non_owner(self, client):
        """Non-owner without view_all cannot edit others' records."""
        with client.application.app_context():
            # Create two users
            role = Role(name='employee', permissions=['view_self'])
            db.session.add(role)

            user_a = user_datastore.create_user(
                email='usera@example.com',
                username='usera',
                password=hash_password('Pass123'),
                roles=[role]
            )

            user_b = user_datastore.create_user(
                email='userb@example.com',
                username='userb',
                password=hash_password('Pass123'),
                roles=[role]
            )
            db.session.commit()

            # Create record owned by user_a
            record = Record(content='User A content')
            record.user.append(user_a)
            db.session.add(record)
            db.session.commit()

            assert can_edit_record(record, user_b) is False

    def test_can_edit_record_anonymous(self, client):
        """Anonymous users cannot edit any records."""
        with client.application.app_context():
            # Create a record
            record = Record(content='Some content')
            db.session.add(record)
            db.session.commit()

            # AnonymousUser from Flask-Security
            anonymous = AnonymousUser()

            assert can_edit_record(record, anonymous) is False

    def test_get_allowed_usernames_view_all(self, client):
        """Admin with view_all should see all usernames."""
        with client.application.app_context():
            # Create admin
            admin_role = Role(name='admin', permissions=['view_all'])
            db.session.add(admin_role)

            admin = user_datastore.create_user(
                email='admin5@example.com',
                username='admin5user',
                password=hash_password('AdminPass123'),
                roles=[admin_role]
            )

            # Create multiple users
            role = Role(name='employee', permissions=['view_self'])
            db.session.add(role)

            for i in range(3):
                user_datastore.create_user(
                    email=f'user{i}@example.com',
                    username=f'user{i}',
                    password=hash_password('Pass123'),
                    roles=[role]
                )
            db.session.commit()

            usernames = get_allowed_usernames(admin)

            assert 'admin5user' in usernames
            assert 'user0' in usernames
            assert 'user1' in usernames
            assert 'user2' in usernames

    def test_get_allowed_usernames_view_group(self, client):
        """Leader with view_group should see own and group members' usernames."""
        with client.application.app_context():
            # Create leader role
            leader_role = Role(name='leader', permissions=['view_group'])
            db.session.add(leader_role)

            leader = user_datastore.create_user(
                email='leader3@example.com',
                username='leader3user',
                password=hash_password('LeaderPass123'),
                roles=[leader_role]
            )

            # Create group and add leader
            group = Group(name='TeamGroup', description='Team group')
            group.users.append(leader)

            # Create group members
            member_role = Role(name='member', permissions=['view_self'])
            db.session.add(member_role)

            for i in range(2):
                member = user_datastore.create_user(
                    email=f'member{i}@example.com',
                    username=f'member{i}',
                    password=hash_password('Pass123'),
                    roles=[member_role]
                )
                group.users.append(member)

            db.session.add(group)
            db.session.commit()

        # Login to set current_user for managed_group
        client.post('/login', data={
            'username': 'leader3user',
            'password': 'LeaderPass123'
        })

        with client.application.app_context():
            leader = User.query.filter_by(username='leader3user').first()
            usernames = get_allowed_usernames(leader)

            assert 'leader3user' in usernames
            assert 'member0' in usernames
            assert 'member1' in usernames

    def test_get_allowed_usernames_self_only(self, client):
        """User without view permissions should only see own username."""
        with client.application.app_context():
            # Create user with no view permissions
            role = Role(name='basic', permissions=[])
            db.session.add(role)

            user = user_datastore.create_user(
                email='selfonly@example.com',
                username='selfonlyuser',
                password=hash_password('Pass123'),
                roles=[role]
            )

            # Create other users
            other_role = Role(name='other', permissions=[])
            db.session.add(other_role)

            user_datastore.create_user(
                email='otheruser@example.com',
                username='otheruser',
                password=hash_password('Pass123'),
                roles=[other_role]
            )
            db.session.commit()

            usernames = get_allowed_usernames(user)

            assert usernames == ['selfonlyuser']

    def test_get_allowed_groups_view_all(self, client):
        """Admin with view_all should see all groups."""
        with client.application.app_context():
            # Create admin
            admin_role = Role(name='admin', permissions=['view_all'])
            db.session.add(admin_role)

            admin = user_datastore.create_user(
                email='admin6@example.com',
                username='admin6user',
                password=hash_password('AdminPass123'),
                roles=[admin_role]
            )

            # Create multiple groups
            for name in ['Group1', 'Group2', 'Group3']:
                group = Group(name=name, description=f'{name} description')
                db.session.add(group)
            db.session.commit()

        # Login for managed_group
        client.post('/login', data={
            'username': 'admin6user',
            'password': 'AdminPass123'
        })

        with client.application.app_context():
            admin = User.query.filter_by(username='admin6user').first()
            groups = get_allowed_groups(admin)

            assert len(groups) == 3
            group_names = [g.name for g in groups]
            assert 'Group1' in group_names
            assert 'Group2' in group_names
            assert 'Group3' in group_names

    def test_get_allowed_groups_view_group(self, client):
        """Leader with view_group should only see managed groups."""
        with client.application.app_context():
            # Create leader role
            leader_role = Role(name='leader', permissions=['view_group'])
            db.session.add(leader_role)

            leader = user_datastore.create_user(
                email='leader4@example.com',
                username='leader4user',
                password=hash_password('LeaderPass123'),
                roles=[leader_role]
            )

            # Create groups, add leader to one
            managed_group = Group(name='ManagedGroup', description='Managed')
            unmanaged_group = Group(name='UnmanagedGroup', description='Unmanaged')

            managed_group.users.append(leader)
            db.session.add_all([managed_group, unmanaged_group])
            db.session.commit()

        # Login for managed_group
        client.post('/login', data={
            'username': 'leader4user',
            'password': 'LeaderPass123'
        })

        with client.application.app_context():
            leader = User.query.filter_by(username='leader4user').first()
            groups = get_allowed_groups(leader)

            assert len(groups) == 1
            assert groups[0].name == 'ManagedGroup'

    def test_get_allowed_groups_none(self, client):
        """User without permissions should get empty list."""
        with client.application.app_context():
            # Create user without permissions
            role = Role(name='noperms', permissions=[])
            db.session.add(role)

            user = user_datastore.create_user(
                email='noperms@example.com',
                username='nopermsuser',
                password=hash_password('Pass123'),
                roles=[role]
            )

            # Create some groups (user not in any)
            for name in ['GroupA', 'GroupB']:
                group = Group(name=name, description=f'{name} description')
                db.session.add(group)
            db.session.commit()

            groups = get_allowed_groups(user)

            assert groups == []
