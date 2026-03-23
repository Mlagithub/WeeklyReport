"""Tests for utility functions in utils.py."""

from datetime import date
from unittest.mock import patch, MagicMock

from utils import DateRange, html_to_text


class TestDateRange:
    """Tests for the DateRange utility class."""

    def test_this_week_returns_tuple(self):
        """Test that this_week returns a tuple of two dates."""
        result = DateRange.this_week()
        assert isinstance(result, tuple)
        assert len(result) == 2
        start, end = result
        assert isinstance(start, date)
        assert isinstance(end, date)
        assert start <= end

    @patch('utils.datetime')
    def test_this_week_start_is_monday(self, mock_datetime):
        """Test that this_week start is Monday of the current week."""
        # Mock Wednesday, March 25, 2026
        mock_date = MagicMock()
        mock_date.weekday.return_value = 2  # Wednesday
        mock_date.__sub__ = lambda self, delta: date(2026, 3, 23)  # Monday

        # Create a date object for the mocked return
        mock_datetime.today.return_value.date.return_value = date(2026, 3, 25)

        # Patch the get_today method
        with patch.object(DateRange, 'get_today', return_value=date(2026, 3, 25)):
            start, end = DateRange.this_week()
            # For Wednesday March 25, start should be Monday March 23
            assert start.weekday() == 0  # Monday

    def test_last_week_returns_tuple(self):
        """Test that last_week returns a tuple spanning 7 days."""
        result = DateRange.last_week()
        assert isinstance(result, tuple)
        assert len(result) == 2
        start, end = result
        assert isinstance(start, date)
        assert isinstance(end, date)
        # End should be 6 days after start (7 days total)
        delta = (end - start).days
        assert delta == 6

    def test_this_month_returns_tuple(self):
        """Test that this_month returns a tuple starting on the 1st."""
        result = DateRange.this_month()
        assert isinstance(result, tuple)
        assert len(result) == 2
        start, end = result
        assert isinstance(start, date)
        assert isinstance(end, date)
        assert start.day == 1
        assert start <= end

    def test_this_quarter_returns_tuple(self):
        """Test that this_quarter returns valid date range."""
        result = DateRange.this_quarter()
        assert isinstance(result, tuple)
        assert len(result) == 2
        start, end = result
        assert isinstance(start, date)
        assert isinstance(end, date)
        assert start <= end

    def test_this_year_returns_tuple(self):
        """Test that this_year returns a tuple starting on Jan 1."""
        result = DateRange.this_year()
        assert isinstance(result, tuple)
        assert len(result) == 2
        start, end = result
        assert isinstance(start, date)
        assert isinstance(end, date)
        assert start.month == 1
        assert start.day == 1
        assert start <= end

    def test_get_range_valid_key(self):
        """Test get_range with a valid key returns correct range."""
        result = DateRange.get_range('this_week')
        expected = DateRange.this_week()
        assert result == expected

    def test_get_range_unknown_key(self):
        """Test get_range with unknown key returns this_year as default."""
        result = DateRange.get_range('unknown_key')
        expected = DateRange.this_year()
        assert result == expected

    def test_last_n_days(self):
        """Test last_n_days returns tuple spanning n days."""
        n = 7
        start, end = DateRange.last_n_days(n)
        assert isinstance(start, date)
        assert isinstance(end, date)
        delta = (end - start).days
        assert delta == n


class TestHtmlToText:
    """Tests for the html_to_text function."""

    def test_empty_input(self):
        """Test that empty string or None returns empty string."""
        assert html_to_text('') == ''
        assert html_to_text(None) == ''

    def test_plain_paragraph(self):
        """Test that plain paragraph is converted correctly."""
        result = html_to_text('<p>Hello World</p>')
        assert 'Hello World' in result

    def test_unordered_list(self):
        """Test that unordered list is converted with bullet points."""
        result = html_to_text('<ul><li>Item 1</li><li>Item 2</li></ul>')
        assert '- Item 1' in result
        assert '- Item 2' in result

    def test_ordered_list(self):
        """Test that ordered list is converted with numbers."""
        result = html_to_text('<ol><li>First</li><li>Second</li></ol>')
        assert '1. First' in result
        assert '2. Second' in result

    def test_nested_list(self):
        """Test that nested lists have proper indentation."""
        html = '''<ul><li>Item 1<ul><li>Nested Item</li></ul></li></ul>'''
        result = html_to_text(html)
        assert '- Item 1' in result
        assert '    - Nested Item' in result

    def test_multiple_paragraphs(self):
        """Test that multiple paragraphs appear on separate lines."""
        result = html_to_text('<p>First paragraph</p><p>Second paragraph</p>')
        assert 'First paragraph' in result
        assert 'Second paragraph' in result
        # Each should be on its own line
        lines = result.split('\n')
        assert any('First paragraph' in line for line in lines)
        assert any('Second paragraph' in line for line in lines)

    def test_strong_tag(self):
        """Test that strong tag is converted to markdown bold."""
        result = html_to_text('<strong>bold text</strong>')
        assert '**bold text**' in result

    def test_mixed_content(self):
        """Test that mixed content (paragraphs and lists) converts correctly."""
        html = '''<p>Introduction</p><ul><li>Item 1</li></ul><p>Conclusion</p>'''
        result = html_to_text(html)
        assert 'Introduction' in result
        assert '- Item 1' in result
        assert 'Conclusion' in result