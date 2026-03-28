"""
Route handlers for the weekly report application.

This module contains all route handlers and helper functions extracted from app.py.
Uses the register_routes pattern per D-01 (no Blueprints).
Per D-11: Upload files use UUID for unique filenames.
"""

import os
import uuid
from datetime import datetime

from flask import abort, flash, redirect, render_template, request, send_file, send_from_directory, session, url_for
from flask_security import current_user, login_required, login_user, logout_user
from flask_security.utils import hash_password, verify_password
from sqlalchemy import and_, case, func
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename

from exporters import ExporterFactory
from extensions import db
from forms import MyChangePasswordForm, MyForgotPasswordForm, MyLoginForm, MyRegisterForm, RecordFilterForm, ThemeForm
from models import Group, Record, Role, User, user_records, with_db_transaction
from utils import DateRange

# =============================================================================
# Helper Functions
# =============================================================================


def get_allowed_groups(user):
    """Get groups that the user is allowed to view."""
    permissions = User.all_permissions(user)
    if "view_all" in permissions:
        return Group.query.options(joinedload(Group.users)).all()
    if "view_group" in permissions:
        return User.managed_group(user)
    return []


def get_allowed_usernames(user):
    """Get usernames that the user is allowed to view (optimized to avoid N+1 queries)."""
    permissions = User.all_permissions(user)
    if "view_all" in permissions:
        # Only query username field, not full user objects
        return [u.username for u in User.query.with_entities(User.username).all()]
    if "view_group" in permissions:
        usernames = {user.username}
        # managed_group already uses eager loading
        for group in User.managed_group(user):
            for u in group.users:
                usernames.add(u.username)
        return list(usernames)
    return [user.username]


def can_edit_record(record, user):
    """Check if user can edit a specific record."""
    if not user.is_authenticated:
        return False
    permissions = User.all_permissions(user)
    if "view_all" in permissions:
        return True
    if record.user and record.user[0].id == user.id:
        return True
    return False


def _resolve_filter_usernames(params, current_user):
    """Resolve usernames from user and group filter parameters.

    Args:
        params: Request parameters (dict-like with get/getlist methods)
        current_user: Flask-Security current_user object

    Returns:
        List of usernames to filter records by
    """
    allowed_usernames = set(get_allowed_usernames(current_user))
    usernames = set()

    # Add selected user if valid
    selected_user = params.get("user")
    if selected_user in allowed_usernames:
        usernames.add(selected_user)

    # Add users from selected groups
    selected_groups = params.getlist("groups")
    allowed_groups = {g.name for g in get_allowed_groups(current_user)}
    valid_groups = [g for g in selected_groups if g in allowed_groups]

    if valid_groups:
        group_usernames = [
            u.username
            for u in User.query.join(User.groups).filter(Group.name.in_(valid_groups)).all()
            if u.username in allowed_usernames
        ]
        usernames.update(group_usernames)

    # Return deduplicated list or fallback
    return list(usernames) if usernames else list(allowed_usernames) or [current_user.username]


def build_record_query(params):
    """Build a query for records based on filter parameters."""
    query = db.session.query(Record).options(joinedload(Record.user)).join(user_records).join(User)

    tr = params.get("time_range")
    start_date = None
    end_date = None
    if tr:
        start_date, end_date = DateRange.get_range(tr)
        query = query.filter(Record.date >= start_date, Record.date <= end_date)

    usernames = _resolve_filter_usernames(params, current_user)
    query = query.filter(User.username.in_(usernames))

    return query, start_date, end_date, usernames


# =============================================================================
# Route Registration
# =============================================================================


def register_routes(app):
    """Register all routes with the Flask app.

    This function defines all route handlers and registers them with the app.
    Per D-01, we use simple registration without Blueprints.
    """
    from flask_ckeditor import CKEditorField, upload_fail, upload_success

    from forms import RecordForm

    # Patch RecordForm.body to use CKEditorField
    RecordForm.body = CKEditorField("内容", validators=[])

    @app.route("/")
    @login_required
    def home():
        this_week_start, this_week_end = DateRange.this_week()
        this_month_start, this_month_end = DateRange.this_month()

        base_query = Record.query.join(user_records).filter(user_records.c.user_id == current_user.id)

        total_count = base_query.count()

        this_week_count = base_query.filter(Record.date >= this_week_start, Record.date <= this_week_end).count()

        this_month_count = base_query.filter(Record.date >= this_month_start, Record.date <= this_month_end).count()

        recent_records = base_query.order_by(Record.date.desc()).limit(5).all()

        return render_template(
            "home.html",
            this_week_count=this_week_count,
            this_month_count=this_month_count,
            total_count=total_count,
            recent_records=recent_records,
        )

    @app.route("/register", methods=["GET", "POST"])
    @with_db_transaction
    def register():
        from flask_security import SQLAlchemyUserDatastore

        user_datastore = SQLAlchemyUserDatastore(db, User, Role)

        form = MyRegisterForm()
        if form.validate_on_submit():
            username = form.username.data
            # Check if username already exists
            if User.query.filter_by(username=username).first():
                flash("用户名已存在", "warning")
                return render_template("security/register_user.html", register_user_form=form)
            # Generate unique email
            email = f"{username}_{uuid.uuid4().hex[:8]}@local"
            # Create user
            user_datastore.create_user(email=email, username=username, password=hash_password(form.password.data))
            db.session.commit()
            flash("注册成功，请登录")
            return redirect(url_for("login"))
        return render_template("security/register_user.html", register_user_form=form)

    @app.route("/login", methods=("GET", "POST"))
    def login():
        from flask_security import SQLAlchemyUserDatastore

        user_datastore = SQLAlchemyUserDatastore(db, User, Role)

        form = MyLoginForm()
        if form.validate_on_submit():
            user = user_datastore.find_user(username=form.username.data)
            if user and verify_password(form.password.data, user.password):
                login_user(user, remember=form.remember.data)
                next_url = request.args.get("next")
                return redirect(next_url or url_for("home"))
            flash("用户名或密码不正确", "warning")
        return render_template("security/login_user.html", login_user_form=form)

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("home"))

    @app.route("/forgot_password", methods=("GET", "POST"))
    def forgot_password():
        # Only admins can reset any user's password
        is_admin = current_user.is_authenticated and current_user.is_admin
        if not is_admin:
            return render_template("security/forgot_password.html", forgot_password_form=None)
        form = MyForgotPasswordForm()
        if form.validate_on_submit():
            if User.change_user_password(form.username.data, form.new_password.data):
                return redirect(url_for("home"))
            else:
                flash(f"修改密码失败：{form.username.data}", "warning")
        return render_template("security/forgot_password.html", forgot_password_form=form)

    @app.route("/change_password", methods=("GET", "POST"))
    @login_required
    def change_password():
        form = MyChangePasswordForm()
        form.user = current_user
        if form.validate_on_submit():
            if User.change_user_password(current_user.username, form.new_password.data):
                logout_user()
                return redirect(url_for("login"))
            else:
                flash(f"修改密码失败：{current_user.username}", "warning")
        return render_template("security/change_password.html", change_password_form=form)

    @app.route("/create_records", methods=("GET", "POST"))
    @login_required
    @with_db_transaction
    def create_records():
        form = RecordForm()
        if form.validate_on_submit():
            record_date = form.date.data
            body = form.body.data
            record = Record()
            record.createtime = datetime.now()
            record.date = record_date
            record.content = body
            current_user.records.append(record)  # Link record and user
            db.session.add(record)
            db.session.commit()

            flash("己提交")

            return redirect(url_for("manage_records"))

        return render_template("create_records.html", form=form)

    @app.route("/edit_record/<int:record_id>", methods=["POST", "GET"])
    @login_required
    @with_db_transaction
    def edit_record(record_id):
        form = RecordForm()
        record = db.session.get(Record, record_id)
        if not record:
            abort(404)
        if not can_edit_record(record, current_user):
            abort(403)
        if form.validate_on_submit():
            record_date = form.date.data
            body = form.body.data
            record.createtime = datetime.now()
            record.date = record_date
            record.content = body
            db.session.commit()
            flash("己提交")
            return redirect(url_for("manage_records"))
        else:
            form.date.data = record.date
            form.body.data = record.content

        return render_template("create_records.html", form=form)

    @app.route("/delete_record/<int:record_id>", methods=["POST", "GET"])
    @login_required
    @with_db_transaction
    def delete_record(record_id):
        record = db.session.get(Record, record_id)
        if record and can_edit_record(record, current_user):
            db.session.delete(record)
            db.session.commit()
            flash("数据己删除")
        elif not record:
            abort(404)
        else:
            abort(403)
        return redirect(url_for("manage_records"))

    @app.route("/download_records", methods=["POST"])
    @login_required
    def download_records():
        query, start_date, end_date, _ = build_record_query(request.form)
        format = request.form.get("format", "xlsx")

        if format == "pdf":
            records = query.all()
            exporter = ExporterFactory.get_exporter("pdf")
            output = exporter.export(records, title="周报")

            if start_date and end_date:
                filename = f"周报_{start_date.strftime('%Y%m%d')}-{end_date.strftime('%Y%m%d')}.pdf"
            else:
                filename = f"周报_{datetime.now().strftime('%Y%m%d')}.pdf"

            return send_file(output, mimetype="application/pdf", as_attachment=True, download_name=filename)

        if format == "docx":
            records = query.all()
            exporter = ExporterFactory.get_exporter("docx")
            output = exporter.export(records, title="周报")

            if start_date and end_date:
                filename = f"周报_{start_date.strftime('%Y%m%d')}-{end_date.strftime('%Y%m%d')}.docx"
            else:
                filename = f"周报_{datetime.now().strftime('%Y%m%d')}.docx"

            return send_file(
                output,
                mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                as_attachment=True,
                download_name=filename,
            )

        # Excel export (default)
        records = query.all()
        exporter = ExporterFactory.get_exporter("xlsx")
        output = exporter.export(records, title="周报")

        if start_date and end_date:
            filename = f"软件开发组周报_{start_date.strftime('%Y%m%d')}-{end_date.strftime('%Y%m%d')}.xlsx"
        else:
            filename = f"软件开发组周报_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

        return send_file(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=filename,
        )

    @app.route("/manage_records", methods=("GET",))
    @login_required
    def manage_records():
        def build_edit_buttons(record_id):
            edit_url = url_for("edit_record", record_id=record_id)
            delete_url = url_for("delete_record", record_id=record_id)
            return f'''
    <p>
        <a class="btn btn-secondary btn-sm" href="{edit_url}"> <i class="bi bi-pencil-fill"></i> </a>
    </p>
    <p>
        <a class="btn btn-danger btn-sm" href="{delete_url}" onclick="return confirm(\'确定要删除这条记录吗？\');"> <i class="bi bi-trash-fill"></i> </a>
    </p>'''

        record_form = RecordFilterForm()

        uchoices = [(current_user.username, current_user.username)]
        for group in User.managed_group(current_user):
            record_form.groups.choices.append((group.name, group.description))
            for u in group.users:
                uchoices.append((u.username, u.username))
        record_form.user.choices = sorted(list(set(uchoices)))

        hide_groups = not record_form.groups.choices

        # Apply default filters if no URL parameters provided (FIND-01, FIND-02)
        filter_args = request.args.copy()
        if "user" not in filter_args:
            filter_args["user"] = current_user.username
        if "time_range" not in filter_args:
            filter_args["time_range"] = "this_week"

        query, _, _, current_filter_usernames = build_record_query(filter_args)
        query = query.order_by(Record.date.desc())

        this_week_start, this_week_end = DateRange.this_week()
        counts = query.with_entities(
            func.count(Record.id).label("total_count"),
            func.sum(case((and_(Record.date >= this_week_start, Record.date <= this_week_end), 1), else_=0)).label(
                "this_week_count"
            ),
        ).first()
        total_count = counts.total_count if counts else 0
        this_week_count = counts.this_week_count or 0

        page = request.args.get("page", 1, type=int)
        pagination = query.paginate(page=page, per_page=5, error_out=False)
        records = pagination.items

        titles = [("name", "用户"), ("content", "内容"), ("date", "日期"), ("edit", "操作")]
        data = []
        for msg in records:
            if not msg.user:
                continue
            record_id = msg.id
            data.append(
                {
                    "name": msg.user[0].username,
                    "content": msg.content,
                    "date": msg.date,
                    "edit": build_edit_buttons(record_id),
                }
            )

        return render_template(
            "manage_records.html",
            pagination=pagination,
            titles=titles,
            data=data,
            record_form=record_form,
            hide_groups=hide_groups,
            total_count=total_count,
            this_week_count=this_week_count,
            current_filter_usernames=current_filter_usernames,
        )

    @app.before_request
    def apply_user_theme():
        theme = session.get("theme", "default")
        app.config["BOOTSTRAP_BOOTSWATCH_THEME"] = None if theme == "default" else theme

    @app.route("/config", methods=["GET", "POST"])
    @login_required
    def config():
        form = ThemeForm()
        if form.validate_on_submit():
            session["theme"] = form.theme_name.data
            flash(f"主题已更改为 {form.theme_name.data}。")
        else:
            form.theme_name.data = session.get("theme", "lumen")

        return render_template("config.html", form=form)

    @app.route("/files/<filename>")
    @login_required
    def uploaded_files(filename):
        path = app.config["UPLOADED_PATH"]
        # URL-decode filename to handle Chinese characters
        from urllib.parse import unquote

        decoded_name = unquote(filename)

        # Try decoded name first (for Chinese filenames), then secure_filename
        if os.path.exists(os.path.join(path, decoded_name)):
            return send_from_directory(path, decoded_name)

        safe_name = secure_filename(filename)
        if safe_name and os.path.exists(os.path.join(path, safe_name)):
            return send_from_directory(path, safe_name)

        abort(404)

    @app.route("/upload", methods=["POST"])
    @login_required
    def upload():
        """Handle CKEditor file upload.

        Per D-11: Use UUID for unique filenames to prevent file overwrites.
        Handles Chinese filenames by preserving them (URL-encoded in the URL).
        """
        f = request.files.get("upload")
        if not f or not f.filename:
            return upload_fail(message="No file uploaded!")

        # Extract extension
        if "." in f.filename:
            original_name, extension = f.filename.rsplit(".", 1)
            extension = extension.lower()
        else:
            extension = ""

        if extension not in ["jpg", "gif", "png", "jpeg"]:
            return upload_fail(message="Image only!")

        path = app.config["UPLOADED_PATH"]
        os.makedirs(path, exist_ok=True)

        # Per D-11: Use UUID for unique filename
        # For Chinese filenames, secure_filename strips all chars, so we preserve original
        safe_name = secure_filename(f.filename)
        if safe_name and safe_name != f"{extension}":
            # Filename has valid ASCII chars, use secure version
            filename = f"{uuid.uuid4().hex}_{safe_name}"
        else:
            # Chinese or special chars - preserve original name with UUID prefix
            # Use URL encoding for the filename so it can be served correctly
            filename = f"{uuid.uuid4().hex}_{original_name}.{extension}"

        f.save(os.path.join(path, filename))
        url = url_for("uploaded_files", filename=filename)
        return upload_success(url=url)
