import pytest
from flask_security.utils import hash_password

from app import app, db, user_datastore
from models import Role


@pytest.fixture
def client():
    """Create a test client with in-memory database."""
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SECURITY_PASSWORD_SALT"] = "test-salt"

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()


@pytest.fixture
def test_user(client):
    """Create a test user and return user data."""
    with client.application.app_context():
        user = user_datastore.create_user(
            email="test@example.com", username="testuser", password=hash_password("TestPass123")
        )
        db.session.commit()
        return {"username": "testuser", "password": "TestPass123", "id": user.id}


@pytest.fixture
def auth_client(client, test_user):
    """Authenticated test client."""
    client.post("/login", data={"username": test_user["username"], "password": test_user["password"]})
    yield client


@pytest.fixture
def admin_user(client):
    """Create an admin user for testing admin-only features."""
    with client.application.app_context():
        admin_role = Role(name="admin", permissions=["view_all", "edit_database"])
        db.session.add(admin_role)
        user = user_datastore.create_user(
            email="admin@example.com",
            username="adminuser",
            password=hash_password("AdminPass123"),
            roles=[admin_role],
        )
        db.session.commit()
        return {"username": "adminuser", "password": "AdminPass123", "id": user.id}


@pytest.fixture
def admin_client(client, admin_user):
    """Authenticated admin client."""
    client.post("/login", data={"username": admin_user["username"], "password": admin_user["password"]})
    yield client
