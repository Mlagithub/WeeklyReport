"""
Tests for summary_utils functions.

Per SUMMARY-01: fetch_user_records tests.
Per SUMMARY-02: assemble_prompt tests.
Per SUMMARY-04: generate_summary tests.
"""

import pytest
from datetime import date
from flask_security.utils import hash_password

from summary_utils import fetch_user_records, assemble_prompt, generate_summary
from models import Record, AITemplate, user_records, User
from extensions import db
from app import user_datastore


class TestFetchUserRecords:
    """Tests for fetch_user_records function."""

    def test_returns_records_for_user_in_time_range(self, client):
        """Test that fetch_user_records returns records within date range."""
        with client.application.app_context():
            # Create a user using user_datastore (Flask-Security pattern)
            user = user_datastore.create_user(
                username="testuser1",
                email="test1@example.com",
                password=hash_password("testpass")
            )
            db.session.commit()

            # Create records for the user
            record1 = Record(content="<p>Work item 1</p>", date=date(2026, 3, 25))
            record2 = Record(content="<p>Work item 2</p>", date=date(2026, 3, 26))
            record3 = Record(content="<p>Work item 3</p>", date=date(2026, 3, 20))  # Outside range
            db.session.add_all([record1, record2, record3])
            db.session.commit()

            # Associate records with user
            db.session.execute(user_records.insert().values(user_id=user.id, record_id=record1.id))
            db.session.execute(user_records.insert().values(user_id=user.id, record_id=record2.id))
            db.session.execute(user_records.insert().values(user_id=user.id, record_id=record3.id))
            db.session.commit()

            # Fetch records for this week (2026-03-24 to 2026-03-28)
            start_date = date(2026, 3, 24)
            end_date = date(2026, 3, 28)
            records = fetch_user_records(user.id, start_date, end_date)

            # Should return 2 records (record1 and record2 are in range)
            assert len(records) == 2
            assert records[0]['content'] == "Work item 1"
            assert records[1]['content'] == "Work item 2"

    def test_converts_html_content_to_plain_text(self, client):
        """Test that fetch_user_records converts HTML to plain text."""
        with client.application.app_context():
            user = user_datastore.create_user(
                username="testuser2",
                email="test2@example.com",
                password=hash_password("testpass")
            )
            db.session.commit()

            # Create record with HTML content
            record = Record(content="<p><strong>Bold text</strong> and <em>italic</em></p>", date=date(2026, 3, 25))
            db.session.add(record)
            db.session.commit()

            db.session.execute(user_records.insert().values(user_id=user.id, record_id=record.id))
            db.session.commit()

            records = fetch_user_records(user.id, date(2026, 3, 24), date(2026, 3, 28))

            # Should convert HTML to plain text (html_to_text strips HTML tags)
            assert len(records) == 1
            # html_to_text extracts text content without HTML tags
            assert "Bold text" in records[0]['content']

    def test_returns_empty_list_for_no_records(self, client):
        """Test that fetch_user_records returns empty list when no records exist."""
        with client.application.app_context():
            user = user_datastore.create_user(
                username="testuser3",
                email="test3@example.com",
                password=hash_password("testpass")
            )
            db.session.commit()

            # Fetch records for a time range with no records
            records = fetch_user_records(user.id, date(2026, 3, 24), date(2026, 3, 28))

            assert records == []


class TestAssemblePrompt:
    """Tests for assemble_prompt function."""

    def test_fills_all_placeholders_correctly(self, client):
        """Test that assemble_prompt fills template placeholders."""
        template_content = (
            "时间范围：{time_range}\n"
            "用户：{user_name}\n"
            "记录数：{record_count}\n"
            "日期范围：{date_range}\n"
            "记录内容：\n{records}"
        )
        records = [
            {'date': date(2026, 3, 25), 'content': "Task A"},
            {'date': date(2026, 3, 26), 'content': "Task B"},
        ]

        prompt = assemble_prompt(
            template_content=template_content,
            records=records,
            user_name="张三",
            time_range_key="this_week"
        )

        assert "本周" in prompt
        assert "张三" in prompt
        assert "记录数：2" in prompt
        assert "Task A" in prompt
        assert "Task B" in prompt

    def test_works_with_none_template(self, client):
        """Test that assemble_prompt uses default prompt when template is None."""
        records = [
            {'date': date(2026, 3, 25), 'content': "Work done"},
        ]

        prompt = assemble_prompt(
            template_content=None,
            records=records,
            user_name="李四",
            time_range_key="this_month"
        )

        # Should use default template
        assert "本月" in prompt
        assert "李四" in prompt
        assert "Work done" in prompt

    def test_prepends_custom_prompt_if_provided(self, client):
        """Test that assemble_prompt prepends custom prompt to assembled content."""
        records = [
            {'date': date(2026, 3, 25), 'content': "Some work"},
        ]

        custom_prompt = "请使用简洁风格总结"

        prompt = assemble_prompt(
            template_content=None,
            records=records,
            user_name="王五",
            time_range_key="this_week",
            custom_prompt=custom_prompt
        )

        # Custom prompt should be prepended
        assert prompt.startswith("请使用简洁风格总结")
        assert "王五" in prompt

    def test_formats_records_as_numbered_list(self, client):
        """Test that assemble_prompt formats records as numbered list."""
        records = [
            {'date': date(2026, 3, 25), 'content': "First task"},
            {'date': date(2026, 3, 26), 'content': "Second task"},
            {'date': date(2026, 3, 27), 'content': "Third task"},
        ]

        prompt = assemble_prompt(
            template_content=None,
            records=records,
            user_name="测试用户",
            time_range_key="this_week"
        )

        # Check numbered format
        assert "1. [2026-03-25] First task" in prompt
        assert "2. [2026-03-26] Second task" in prompt
        assert "3. [2026-03-27] Third task" in prompt


class TestGenerateSummary:
    """Tests for generate_summary function."""

    def test_returns_tuple_with_success_flag(self, client):
        """Test that generate_summary returns tuple (success, content, error)."""
        # This will need mocking for API calls
        pass

    def test_handles_empty_records_gracefully(self, client):
        """Test that generate_summary handles empty records list."""
        # Will need mocking
        pass

    def test_handles_api_errors_gracefully(self, client):
        """Test that generate_summary handles API errors."""
        # Will need mocking
        pass