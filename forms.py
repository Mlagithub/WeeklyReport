"""
WTForms form classes for the weekly report application.

This module contains all form definitions extracted from app.py.
Forms import from extensions and models as needed.
"""

from datetime import date

from flask_security.forms import ChangePasswordForm, LoginForm
from flask_wtf import FlaskForm
from wtforms import DateField, HiddenField, PasswordField, SelectField, SelectMultipleField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp, ValidationError

from models import AITemplate
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


class AIConfigForm(FlaskForm):
    """Form for AI service configuration.

    Per CONFIG-01: AI service configuration storage.
    Per UI-SPEC.md: Field labels, placeholders, validation messages in Chinese.
    """

    api_url = StringField(
        "API URL",
        validators=[
            DataRequired(message="API URL不能为空"),
            Regexp(r'^https?://.+', message="API URL格式无效，必须以http://或https://开头")
        ],
        render_kw={"placeholder": "https://api.openai.com/v1"}
    )
    api_key = PasswordField(
        "API Key",
        validators=[DataRequired(message="API Key不能为空")],
        description="保存后仅显示最后4位字符"
    )
    model_name = StringField(
        "模型名称",
        validators=[DataRequired(message="模型名称不能为空")],
        render_kw={"placeholder": "gpt-4o-mini"}
    )
    test_submit = SubmitField("测试连接", render_kw={"class": "btn btn-outline-secondary mb-3"})
    submit = SubmitField("保存配置", render_kw={"class": "btn btn-primary"})


class TemplateForm(FlaskForm):
    """Form for AI prompt template CRUD operations.

    Per TEMPLATE-01: Template creation and editing.
    Per TEMPLATE-02: Placeholder support with validation hints.
    """

    name = StringField(
        "模板名称",
        validators=[DataRequired(message="模板名称不能为空")],
        render_kw={"placeholder": "例如：周报总结模板"}
    )
    content = TextAreaField(
        "模板内容",
        validators=[DataRequired(message="模板内容不能为空")],
        description="支持占位符：{time_range} {user_name} {records} {record_count} {date_range}"
    )
    time_range = SelectField(
        "时间范围",
        choices=[
            ("weekly", "周报"),
            ("monthly", "月报"),
            ("quarterly", "季度报"),
            ("yearly", "年报")
        ],
        validators=[DataRequired(message="请选择时间范围")]
    )
    template_id = HiddenField("模板ID")
    submit = SubmitField("保存模板", render_kw={"class": "btn btn-primary"})

    def validate_name(self, field):
        """Validate that template name is unique.

        Skips validation for existing templates (identified by template_id).
        """
        existing = AITemplate.query.filter_by(name=field.data).first()
        if existing:
            # If editing existing template, skip if name unchanged
            if self.template_id.data:
                if str(existing.id) == self.template_id.data:
                    return
            raise ValidationError("模板名称已存在")


class SummaryGenerationForm(FlaskForm):
    """Form for personal summary generation.

    Per SUMMARY-01: Time range selection.
    Per SUMMARY-02: Template selection (optional).
    Per SUMMARY-03: Custom prompt input (optional).
    """

    time_range = SelectField(
        "时间范围",
        choices=[
            ("this_week", "本周"),
            ("this_month", "本月"),
            ("this_quarter", "本季度"),
            ("this_year", "本年"),
        ],
        default="this_week",
        validators=[DataRequired(message="请选择时间范围")]
    )
    template_id = SelectField(
        "模板",
        choices=[],  # Populated dynamically from AITemplate
        description="可选，选择预设模板或使用默认"
    )
    custom_prompt = TextAreaField(
        "自定义提示词",
        description="可选，输入额外指示指导AI生成风格"
    )
    submit = SubmitField("生成总结", render_kw={"class": "btn btn-primary"})
