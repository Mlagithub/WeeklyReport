"""
WTForms form classes for the weekly report application.

This module contains all form definitions extracted from app.py.
Forms import from extensions and models as needed.
"""

from datetime import date

from flask_security.forms import ChangePasswordForm, LoginForm
from flask_wtf import FlaskForm
from wtforms import DateField, HiddenField, PasswordField, SelectField, SelectMultipleField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length

from utils import DateRange


class MyLoginForm(LoginForm):
    """Custom login form with hidden email field."""

    email = HiddenField("Hide Email Field")


class MyRegisterForm(FlaskForm):
    """User registration form."""

    username = StringField("用户名", validators=[DataRequired(), Length(min=2, max=255)])
    password = PasswordField("密码", validators=[DataRequired(), Length(min=8, max=18)])
    password_confirm = PasswordField(
        "确认密码", validators=[DataRequired(), EqualTo("password", message="两次输入的密码不一致")]
    )
    submit = SubmitField("注册")


class MyChangePasswordForm(ChangePasswordForm):
    """Password change form extending Flask-Security's ChangePasswordForm."""

    pass


class MyForgotPasswordForm(FlaskForm):
    """Password reset form for admins to reset user passwords."""

    email = HiddenField("Hide Email Field")
    username = StringField(
        "用户名",
        render_kw={"autocomplete": "username"},
        validators=[DataRequired(), Length(2, 255)],
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


class RecordFilterForm(FlaskForm):
    """Form for filtering records by user, groups, and time range."""

    user = SelectField("按用户", choices=[], default="")
    groups = SelectMultipleField("按小组", choices=[])
    time_range = SelectField("按日期", choices=[(key, value) for key, value in DateRange.TIME_RANGES.items()])
    submit = SubmitField("确定")


class RecordDownloadForm(FlaskForm):
    """Form for downloading records."""

    format = SelectField(
        "格式",
        choices=[
            ("xlsx", "Excel"),
            ("pdf", "PDF"),
            ("docx", "Word"),
        ],
        default="xlsx",
    )
    download_submit = SubmitField("下载")


class RecordForm(FlaskForm):
    """Form for creating/editing a weekly report record.

    Note: The body field will be patched to CKEditorField in routes.py
    when the form is used with the app, as CKEditorField requires
    the CKEditor app to be initialized.
    """

    date = DateField("日期", format="%Y-%m-%d", default=date.today, validators=[DataRequired()])
    body = DateField("内容", validators=[DataRequired()])  # Will be CKEditorField when used with app
    submit = SubmitField("提交")


class ThemeForm(FlaskForm):
    """Form for selecting Bootstrap Bootswatch theme."""

    choices = [
        ("default", "none"),
        ("cerulean", "Cerulean 5.3.1"),
        ("cosmo", "Cosmo 5.3.1"),
        ("cyborg", "Cyborg 5.3.1"),
        ("darkly", "Darkly 5.3.1"),
        ("flatly", "Flatly 5.3.1"),
        ("journal", "Journal 5.3.1"),
        ("litera", "Litera 5.3.1"),
        ("lumen", "Lumen 5.3.1"),
        ("lux", "Lux 5.3.1"),
        ("materia", "Materia 5.3.1"),
        ("minty", "Minty 5.3.1"),
        ("morph", "Morph 5.3.1"),
        ("pulse", "Pulse 5.3.1"),
        ("quartz", "Quartz 5.3.1"),
        ("sandstone", "Sandstone 5.3.1"),
        ("simplex", "Simplex 5.3.1"),
        ("sketchy", "Sketchy 5.3.1"),
        ("slate", "Slate 5.3.1"),
        ("solar", "Solar 5.3.1"),
        ("spacelab", "Spacelab 5.3.1"),
        ("superhero", "Superhero 5.3.1"),
        ("united", "United 5.3.1"),
        ("vapor", "Vapor 5.3.1"),
        ("yeti", "Yeti 5.3.1"),
        ("zephyr", "Zephyr 5.3.1"),
    ]
    theme_name = SelectField("", choices=choices, default="lumen")
    submit = SubmitField("更改主题")
