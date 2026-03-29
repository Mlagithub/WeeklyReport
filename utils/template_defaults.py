"""
Default template initialization utility.

Per TEMPLATE-03: Initialize default templates on first access.
"""

from extensions import db
from models import AITemplate

# Default templates for each time range type
DEFAULT_TEMPLATES = [
    {
        "name": "周报模板",
        "time_range": "weekly",
        "content": "请根据以下记录生成{time_range}工作总结。\n\n用户：{user_name}\n记录数：{record_count}\n日期范围：{date_range}\n\n记录内容：\n{records}\n\n请总结本周的主要工作成果和进展。"
    },
    {
        "name": "月报模板",
        "time_range": "monthly",
        "content": "请根据以下记录生成{time_range}工作总结。\n\n用户：{user_name}\n记录数：{record_count}\n日期范围：{date_range}\n\n记录内容：\n{records}\n\n请总结本月的主要工作成果、重点项目进展和下月计划。"
    },
    {
        "name": "季度报模板",
        "time_range": "quarterly",
        "content": "请根据以下记录生成{time_range}工作总结。\n\n用户：{user_name}\n记录数：{record_count}\n日期范围：{date_range}\n\n记录内容：\n{records}\n\n请总结本季度的主要工作成果、重点项目完成情况、遇到的挑战及解决方案。"
    },
    {
        "name": "年报模板",
        "time_range": "yearly",
        "content": "请根据以下记录生成{time_range}工作总结。\n\n用户：{user_name}\n记录数：{record_count}\n日期范围：{date_range}\n\n记录内容：\n{records}\n\n请总结本年度的主要工作成果、重点项目完成情况、个人成长与收获、以及下年度工作展望。"
    }
]


def initialize_default_templates():
    """Initialize default templates if none exist.

    Per TEMPLATE-03: Auto-create default templates on first access.

    Returns:
        bool: True if templates were initialized, False if already exist.
    """
    if AITemplate.query.count() == 0:
        templates = []
        for template_data in DEFAULT_TEMPLATES:
            template = AITemplate(
                name=template_data["name"],
                content=template_data["content"],
                time_range=template_data["time_range"]
            )
            templates.append(template)
        db.session.add_all(templates)
        db.session.commit()
        return True
    return False
