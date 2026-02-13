from flask import Flask, render_template, redirect, flash, url_for, request, send_from_directory, abort
from flask_security import Security, SQLAlchemyUserDatastore, login_required, login_user, logout_user, current_user
from flask_security.models.sqla import FsUserMixin, FsRoleMixin
from flask_security.forms import LoginForm, RegisterForm, ChangePasswordForm, username_validator
from flask_security import UserMixin
from flask_security.utils import hash_password, verify_password

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text, func, case, and_
from sqlalchemy.orm import joinedload
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SelectMultipleField, SubmitField, DateField, HiddenField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_ckeditor import CKEditor, CKEditorField, upload_fail, upload_success
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin import helpers as admin_helpers
from werkzeug.utils import secure_filename

from utils import DateRange, RecordDownloader

import os
from datetime import date, datetime
import json

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///app.db')
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", '1pvDt-8miZXlUfTnNfEzVVTuEOLIEzKxrHMIQICS_0I')
app.config['CKEDITOR_FILE_UPLOADER'] = 'upload'
app.config['CKEDITOR_SERVER_LOCAL'] = True
# app.config['CKEDITOR_ENABLE_CSRF'] = True  # if you want to enable CSRF protect, uncomment this line
app.config['UPLOADED_PATH'] = os.path.join(basedir, 'uploads')
app.config['BOOTSTRAP_SERVE_LOCAL'] = True 
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT", '1pvDt-8miZXlUfTnNfEzVVTuEOLIEzKxrHMIQICS_0I')
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_RECOVERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SECURITY_USERNAME_ENABLE'] = True
app.config['SECURITY_USERNAME_REQUIRED'] = True
app.config['SECURITY_CHANGEABLE'] = True
app.config['SECURITY_SEND_PASSWORD_RESET_EMAIL'] = False
app.config['SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL'] = False
app.config['SECURITY_USERNAME_MIN_LENGTH'] = 2
app.config['SECURITY_PASSWORD_LENGTH_MIN'] = 8
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024


db = SQLAlchemy(app)

def ensure_record_columns():
    inspector = inspect(db.engine)
    columns = {column['name'] for column in inspector.get_columns('record')}
    if 'createtime' not in columns:
        db.session.execute(text("ALTER TABLE record ADD COLUMN createtime DATETIME"))
        db.session.commit()

with app.app_context():
    ensure_record_columns()

user_records = db.Table(
    'user_records',
    db.Column("user_id", db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column("record_id", db.Integer, db.ForeignKey('record.id'), primary_key=True))

roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True))

users_groups = db.Table(
    'users_groups',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True))


class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    date = db.Column(db.Date())
    createtime = db.Column(db.DateTime, default=datetime.utcnow)

class Role(db.Model, FsRoleMixin):
    __tablename__ = 'role'

class User(db.Model, FsUserMixin):
    __tablename__ = 'user'
    email = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), unique=False, nullable=False)
    records = db.relationship('Record', secondary='user_records', backref='user')

    @property
    def is_admin(self):
        return any(role.name == 'admin' for role in self.roles)
    
    @staticmethod
    def with_role(role_name):
        if current_user.is_authenticated:
            return any(role.name == role_name for role in current_user.roles)
        else:
            return False

    # 组长能看到自己负责组的员工内容
    @staticmethod
    def can_view_group(group):
        all_permissions = User.all_permissions(current_user)
        if 'view_all' in all_permissions or ('view_group' in all_permissions and any(g.name == group.name for g in current_user.groups)):
            return True
        else:
            return False
    
    @staticmethod
    def all_permissions(user):
        rst = list(set(p for role in user.roles for p in role.permissions))
        return rst

    @staticmethod
    def managed_group(user):
        groups = []
        all_permissions = User.all_permissions(user)
        if 'view_all' in all_permissions:
            groups = Group.list_all()
        elif 'view_group' in all_permissions:
            groups = [g for g in user.groups if User.can_view_group(g)]

        return groups
    
    @staticmethod
    def change_user_password(username, password):
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = hash_password(password)
            db.session.commit()
            flash("密码已更改")
            return True
        else:
            flash("用户%s不存在"%(username), 'warning')
            return False

# 定义组（Group）模型
class Group(db.Model):
    __tablename__ = 'group'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    users = db.relationship('User', secondary='users_groups', backref='groups')
    
    @staticmethod
    def list_all(user=None):
        if user:
            return [g for g in user.groups if User.can_view_group(g)]
        else:
            return [group for group in Group.query.all()]
        
    

    def __repr__(self):
        return f'{self.name}'

class UserModelView(ModelView):
    # form_columns = ['email', 'roles']  # 显示 email 和 roles 字段
    form_args = {
        'roles': {
            'query_factory': lambda: db.session.query(Role).all(),  # 显示所有角色
            'get_label': lambda role: role.name  # 显示角色的 name 字段
        },
        'user': {
            'query_factory': lambda: db.session.query(User).all(),  # 显示所有用户
            'get_label': lambda user: user.username  # 显示用户的 name 字段
        },
        'users': {
            'query_factory': lambda: db.session.query(User).all(),  # 显示所有用户
            'get_label': lambda user: user.username  # 显示用户的 name 字段
        },
        'records': {
            'query_factory': lambda: db.session.query(Record).all(),  # 显示所有 Record
            'get_label': lambda record: record.content  # 显示 Record的 content 字段
        }
    }
    def is_accessible(self):
        if not current_user.is_authenticated:
            return False
        permissions = User.all_permissions(current_user)
        return current_user.is_admin or 'edit_database' in permissions

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

admin = Admin(app, name='软件开发组')
admin.add_view(UserModelView(User, db.session))
admin.add_view(UserModelView(Role, db.session))
admin.add_view(UserModelView(Record, db.session))
admin.add_view(UserModelView(Group, db.session))

class MyLoginForm(LoginForm):
    email = HiddenField("Hide Email Field")

class MyRegisterForm(RegisterForm):
    email = HiddenField("Hide Email Field")

class MyChangePasswordForm(ChangePasswordForm):
    user = UserMixin()

class MyForgotPasswordForm(FlaskForm):
    email = HiddenField("Hide Email Field")
    username = StringField(
        "用户名",
        render_kw={"autocomplete": "username"},
        validators=[username_validator],
    )
    new_password = PasswordField(
        "密码",
        render_kw={"autocomplete": "new-password"},
        validators=[DataRequired("请输入密码"), Length(8, 18)],
    )
    new_password_confirm = PasswordField(
        "确认密码",
        render_kw={"autocomplete": "new-password"},
        validators=[DataRequired("请输入密码"), EqualTo("new_password", message="两次输入的密码不一致")],
    )
    submit = SubmitField("修改密码")

    requires_confirmation = False

bootstrap=Bootstrap5(app)
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, login_form=MyLoginForm, register_form=MyRegisterForm, forgot_password_form=MyForgotPasswordForm)
ckeditor = CKEditor(app)

# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.theme.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for,
    )

class RecordFilterForm(FlaskForm):
    user = SelectField("按用户", choices=[], default='')
    groups = SelectMultipleField("按小组", choices=[])
    time_range = SelectField("按日期", choices=[(key, value) for key, value in DateRange.TIME_RANGES.items()])
    # per_page = IntegerRangeField("每页数量", render_kw={'min': '2', 'max': '50'})
    submit = SubmitField("确定")

class RecordDownloadForm(FlaskForm):
    download_submit = SubmitField("下载")

class RecordForm(FlaskForm):
    date = DateField('日期', format='%Y-%m-%d', default=date.today, validators=[DataRequired()])
    body = CKEditorField('内容', validators=[DataRequired()])
    submit = SubmitField('提交')

class ThemeForm(FlaskForm):
    choices=[
        ('default', 'none'),
        ('cerulean', 'Cerulean 5.3.1'),
        ('cosmo', 'Cosmo 5.3.1'),
        ('cyborg', 'Cyborg 5.3.1'),
        ('darkly', 'Darkly 5.3.1'),
        ('flatly', 'Flatly 5.3.1'),
        ('journal', 'Journal 5.3.1'),
        ('litera', 'Litera 5.3.1'),
        ('lumen', 'Lumen 5.3.1'),
        ('lux', 'Lux 5.3.1'),
        ('materia', 'Materia 5.3.1'),
        ('minty', 'Minty 5.3.1'),
        ('morph', 'Morph 5.3.1'),
        ('pulse', 'Pulse 5.3.1'),
        ('quartz', 'Quartz 5.3.1'),
        ('sandstone', 'Sandstone 5.3.1'),
        ('simplex', 'Simplex 5.3.1'),
        ('sketchy', 'Sketchy 5.3.1'),
        ('slate', 'Slate 5.3.1'),
        ('solar', 'Solar 5.3.1'),
        ('spacelab', 'Spacelab 5.3.1'),
        ('superhero', 'Superhero 5.3.1'),
        ('united', 'United 5.3.1'),
        ('vapor', 'Vapor 5.3.1'),
        ('yeti', 'Yeti 5.3.1'),
        ('zephyr', 'Zephyr 5.3.1'),
    ]
    theme_name = SelectField('', choices=choices, default='lumen')
    submit = SubmitField('更改主题')

def get_allowed_groups(user):
    permissions = User.all_permissions(user)
    if 'view_all' in permissions:
        return Group.query.all()
    if 'view_group' in permissions:
        return User.managed_group(user)
    return []

def get_allowed_usernames(user):
    permissions = User.all_permissions(user)
    if 'view_all' in permissions:
        return [u.username for u in User.query.all()]
    if 'view_group' in permissions:
        usernames = {user.username}
        for group in User.managed_group(user):
            for u in group.users:
                usernames.add(u.username)
        return list(usernames)
    return [user.username]

def can_edit_record(record, user):
    if not user.is_authenticated:
        return False
    permissions = User.all_permissions(user)
    if 'view_all' in permissions:
        return True
    if record.user and record.user[0].id == user.id:
        return True
    return False

def build_record_query(params):
    query = db.session.query(Record).options(joinedload(Record.user)).join(user_records).join(User)
    tr = params.get('time_range')
    start_date = None
    end_date = None
    if tr:
        start_date, end_date = DateRange.get_range(tr)
        query = query.filter(Record.date >= start_date, Record.date <= end_date)

    usernames = []
    selected_user = params.get('user')
    allowed_usernames = set(get_allowed_usernames(current_user))
    if selected_user and selected_user in allowed_usernames:
        usernames.append(selected_user)

    selected_groups = params.getlist('groups')
    allowed_group_names = {g.name for g in get_allowed_groups(current_user)}
    filtered_groups = [g for g in selected_groups if g in allowed_group_names]
    if filtered_groups:
        group_users = User.query.join(User.groups).filter(
            Group.name.in_(filtered_groups)
        ).all()
        for u in group_users:
            if u.username in allowed_usernames:
                usernames.append(u.username)

    if usernames:
        usernames = list(set(usernames))
    else:
        usernames = [current_user.username]

    query = query.filter(User.username.in_(usernames))
    return query, start_date, end_date, usernames

@app.route('/')
@login_required
def home():
    user = User.query.filter_by(username=current_user.username).first()
    
    this_week_start, this_week_end = DateRange.this_week()
    this_month_start, this_month_end = DateRange.this_month()
    
    base_query = Record.query.join(user_records).filter(
        user_records.c.user_id == user.id
    )
    
    total_count = base_query.count()
    
    this_week_count = base_query.filter(
        Record.date >= this_week_start,
        Record.date <= this_week_end
    ).count()
    
    this_month_count = base_query.filter(
        Record.date >= this_month_start,
        Record.date <= this_month_end
    ).count()
    
    recent_records = base_query.order_by(Record.date.desc()).limit(5).all()
    
    return render_template('home.html', 
                          this_week_count=this_week_count,
                          this_month_count=this_month_count,
                          total_count=total_count,
                          recent_records=recent_records)

@app.route('/register')
def register():
    return render_template('security/register_user.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    form = MyLoginForm()
    if form.validate_on_submit():
        user = user_datastore.find_user(username=form.username.data)
        if user and verify_password(form.password.data, user.password):
            login_user(user, remember=form.remember.data)
            next_url = request.args.get('next')
            return redirect(next_url or url_for('home'))
        flash('用户名或密码不正确', 'warning')
    return render_template('security/login_user.html', login_user_form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/forgot_password', methods=('GET', 'POST'))
def forgot_password():
    form = MyForgotPasswordForm()
    if form.validate_on_submit():
        if User.change_user_password(form.username.data, form.new_password.data,):
            return redirect(url_for('home'))
        else:
            flash('修改密码失败：%s' % (form.username.data), 'warning')
    return render_template('security/forgot_password.html', forgot_password_form=form)

@app.route('/change_password', methods=('GET', 'POST'))
@login_required
def change_password():
    form = MyChangePasswordForm()
    if form.validate_on_submit():
        if User.change_user_password(current_user.username, form.new_password.data):
            logout_user()
            return redirect(url_for('login'))
        else:
            flash('修改密码失败：%s' % (current_user.username), 'warning')
    return render_template('security/change_password.html', change_password_form=form)

@app.route('/create_records', methods=('GET', 'POST'))
@login_required
def create_records():
    form = RecordForm()
    if form.validate_on_submit():
        date = form.date.data
        body = form.body.data
        record = Record()
        record.createtime = datetime.now()
        record.date = date
        record.content = body
        current_user.records.append(record) # 关联 record 和 user
        db.session.add(record)
        db.session.commit()

        flash('己提交')

        return redirect(url_for('manage_records'))
    
    return render_template('create_records.html', form=form)


@app.route('/edit_record/<int:record_id>', methods=['POST', 'GET'])
@login_required
def edit_record(record_id):
    form = RecordForm()
    record = Record.query.get(record_id)
    if not record:
        abort(404)
    if not can_edit_record(record, current_user):
        abort(403)
    if form.validate_on_submit():
        date = form.date.data
        body = form.body.data
        record.createtime = datetime.now()
        record.date = date
        record.content = body
        db.session.commit()
        flash('己提交')
        return redirect(url_for('manage_records'))
    else:
        form.body.data = record.content
    
    return render_template('create_records.html', form=form)


@app.route('/delete_record/<int:record_id>', methods=['POST', 'GET'])
@login_required
def delete_record(record_id):
    record = Record.query.get(record_id)
    if record and can_edit_record(record, current_user):
        db.session.delete(record)
        db.session.commit()
        flash(f'数据己删除')
    elif not record:
        abort(404)
    else:
        abort(403)
    return redirect(url_for('manage_records'))


@app.route('/download_records', methods=['POST'])
@login_required
def download_records():
    query, start_date, end_date, _ = build_record_query(request.form)
    
    all_weeks = set()
    user_weekly_data = {}
    records = query.all()

    for record in records:
        if not record.user:
            continue
        year, week, _ = record.date.isocalendar()
        week_key = (year, week)
        all_weeks.add(week_key)

        username=record.user[0].username
        if username not in user_weekly_data:
            user_weekly_data[username] = {}
        weekly_data = user_weekly_data[username]
        
        if week_key not in weekly_data:
            weekly_data[week_key] = record.content
        else:
            weekly_data[week_key] += f"\n{record.content}"

    from datetime import datetime
    
    if start_date and end_date:
        filename = f"软件开发组周报_{start_date.strftime('%Y%m%d')}-{end_date.strftime('%Y%m%d')}.xlsx"
    else:
        filename = f"软件开发组周报_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    return RecordDownloader().download(user_weekly_data, all_weeks, filename)

# 用于分页时保存参数
query_params = {
    'user': None,
    'time_range': None,
    'groups': None,
    'query' : None,
}


@app.route('/manage_records', methods=('GET',))
@login_required
def manage_records():
    def build_edit_buttons(record_id):
        return f'''
    <p>
        <a class="btn btn-secondary btn-sm" href="edit_record/{record_id}"> <i class="bi bi-pencil-fill"></i> </a>
    </p>
    <p>
        <a class="btn btn-danger btn-sm" href="delete_record/{record_id}" onclick="return confirm(\'确定要删除这条记录吗？\');"> <i class="bi bi-trash-fill"></i> </a>
    </p>'''
    
    record_form = RecordFilterForm()
    
    uchoices = [(current_user.username, current_user.username)]
    for g in User.managed_group(current_user):
        record_form.groups.choices.append((g.name, g.description))
        for u in g.users:
            uchoices.append((u.username, u.username))
    record_form.user.choices = sorted(list(set(uchoices)))

    hide_groups = not record_form.groups.choices

    query, _, _, current_filter_usernames = build_record_query(request.args)
    query = query.order_by(Record.date.desc())

    this_week_start, this_week_end = DateRange.this_week()
    counts = query.with_entities(
        func.count(Record.id).label('total_count'),
        func.sum(
            case(
                (and_(Record.date >= this_week_start, Record.date <= this_week_end), 1),
                else_=0
            )
        ).label('this_week_count')
    ).first()
    total_count = counts.total_count if counts else 0
    this_week_count = counts.this_week_count or 0

    page = request.args.get('page', 1, type=int)
    pagination = query.paginate(page=page, per_page=5, error_out=False)
    records = pagination.items

    titles = [('name', '用户'), ('content', '内容'), ('date', '日期'), ('edit', '操作')]
    data = []
    for msg in records:
        if not msg.user:
            continue
        id = msg.id
        data.append({'name': msg.user[0].username, 'content': msg.content, 'date': msg.date, 'edit': build_edit_buttons(id)})

    return render_template('manage_records.html', 
                          pagination=pagination, 
                          titles=titles, 
                          data=data, 
                          record_form=record_form, 
                          hide_groups=hide_groups,
                          total_count=total_count,
                          this_week_count=this_week_count,
                          current_filter_usernames=current_filter_usernames)


@app.route('/config', methods=['GET', 'POST'])
@login_required
def config():
    form = ThemeForm()
    if form.validate_on_submit():
        if form.theme_name.data == 'default':
            app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = None
        else:
            app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = form.theme_name.data
        flash(f'Render style has been set to {form.theme_name.data}.')
    else:
        if app.config['BOOTSTRAP_BOOTSWATCH_THEME'] != None:
            form.theme_name.data = app.config['BOOTSTRAP_BOOTSWATCH_THEME']

    return render_template('config.html', form=form)


@app.route('/files/<filename>')
@login_required
def uploaded_files(filename):
    path = app.config['UPLOADED_PATH']
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(404)
    return send_from_directory(path, safe_name)


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    f = request.files.get('upload')
    if not f or not f.filename:
        return upload_fail(message='No file uploaded!')
    extension = f.filename.rsplit('.', 1)[-1].lower()
    if extension not in ['jpg', 'gif', 'png', 'jpeg']:
        return upload_fail(message='Image only!')
    path = app.config['UPLOADED_PATH']
    os.makedirs(path, exist_ok=True)
    filename = secure_filename(f.filename)
    if not filename:
        return upload_fail(message='Invalid filename!')
    f.save(os.path.join(path, filename))
    url = url_for('uploaded_files', filename=filename)
    return upload_success(url=url)


def update_db_from_json():
    with open('static/db_table_data.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 更新角色信息
    roles = data.get('roles', [])
    for role_data in roles:
        role_name = role_data['name']
        role_description = role_data['description']
        role_permissions = role_data['permissions']
        
        # 检查角色是否已经存在
        existing_role = Role.query.filter_by(name=role_name).first()
        if not existing_role:
            new_role = Role(name=role_name, description=role_description, permissions=role_permissions)
            db.session.add(new_role)
    db.session.commit()

    # 更新分组信息
    groups = data.get('groups', [])
    for group_data in groups:
        group_name = group_data['name']
        group_description = group_data['description']
        
        # 检查角色是否已经存在
        existing_group = Group.query.filter_by(name=group_name).first()
        if not existing_group:
            new_group = Group(name=group_name, description=group_description)
            db.session.add(new_group)
    db.session.commit()

    # 更新用户信息
    users = data.get('users', [])
    default_password = os.environ.get("DEFAULT_USER_PASSWORD", "12345678")
    for user in users:
        user_name = user['name']
        user_groups = user['groups']

        # 为所有用户增加 employee 角色
        user_roles = user.get('roles', [])
        if isinstance(user_roles, list):
            user_roles.append('employee')
        else:
            user_roles = ['employee']
        
        # 检查是否已经存在
        existing_user = User.query.filter_by(username=user_name).first()
        if not existing_user:
            # 新建 user
            new_user = user_datastore.create_user(email='%s@nudt.jdcszx.com'%(user_name), username=user_name, password=hash_password(default_password), roles=user_roles)
            # 关联 group 和 user
            for g in user_groups:
                existing_group = Group.query.filter_by(name=g).first()
                if existing_group:
                    new_user.groups.append(existing_group) 

    db.session.commit()


import random
from faker import Faker
fake = Faker()

def updat_fake_data():
    for user in User.query.all():
        print('为 %s 生成数据' %(user.username))
        for _ in range(random.randint(3, 7)):
            record = Record()
            record.date = fake.date_this_year()
            record.content = fake.paragraph(nb_sentences=random.randint(3, 6))
            user.records.append(record) # 关联 record 和 user
        db.session.commit()
        print('为 %s 生成数据' %(user.username))


if __name__ == '__main__':
    # 初始化数据库
    with app.app_context():
        db.create_all()
        # 从文件中初始化
        update_db_from_json()
        # updat_fake_data()            
    app.run(host='0.0.0.0', debug=False)
