from flask_admin import Admin
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_security import Security
from flask_sqlalchemy import SQLAlchemy

# Initialize extensions without app binding
# These will be bound to the app via init_app() in app.py
db = SQLAlchemy()
security = Security()
admin = Admin(name='软件开发组')
ckeditor = CKEditor()
bootstrap = Bootstrap5()
