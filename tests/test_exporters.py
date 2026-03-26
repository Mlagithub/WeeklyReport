"""
Test scaffolding for exporters module.

These tests define the expected behavior for ExporterBase, ExporterFactory,
ImageResolver, and dependency imports. Tests are designed to FAIL initially
and will pass once implementation is complete in Wave 1.

Phase: 08-export-foundation
Plan: 00 (Test Scaffolding)
"""

import pytest
from io import BytesIO
from typing import List, Any


class TestExporterBase:
    """Test ExporterBase abstract class behavior."""

    def test_export_method_exists(self):
        """Verify ExporterBase has export(records, **options) method."""
        from exporters.base import ExporterBase
        assert hasattr(ExporterBase, 'export')
        assert callable(getattr(ExporterBase, 'export'))

    def test_file_extension_property(self):
        """Verify file_extension property exists and is abstract."""
        from exporters.base import ExporterBase
        assert hasattr(ExporterBase, 'file_extension')
        # Verify it's abstract by checking __isabstractmethod__
        assert getattr(ExporterBase.file_extension, 'fget').__isabstractmethod__

    def test_mime_type_property(self):
        """Verify mime_type property exists and is abstract."""
        from exporters.base import ExporterBase
        assert hasattr(ExporterBase, 'mime_type')
        # Verify it's abstract by checking __isabstractmethod__
        assert getattr(ExporterBase.mime_type, 'fget').__isabstractmethod__

    def test_cannot_instantiate_base(self):
        """Verify ExporterBase cannot be instantiated directly."""
        from exporters.base import ExporterBase
        with pytest.raises(TypeError):
            ExporterBase()


class TestExporterFactory:
    """Test ExporterFactory class behavior."""

    def test_register_exporter(self):
        """Verify register(format, exporter_class) class method exists."""
        from exporters import ExporterFactory, ExporterBase

        # Create a concrete exporter for testing
        class MockExporter(ExporterBase):
            @property
            def file_extension(self):
                return 'mock'

            @property
            def mime_type(self):
                return 'application/mock'

            def _generate(self, data, options):
                from io import BytesIO
                return BytesIO(b'mock')

        # Test that register method exists and works
        ExporterFactory.register('mock', MockExporter)
        assert 'mock' in ExporterFactory.supported_formats()

        # Clean up registry
        ExporterFactory._registry.pop('mock', None)

    def test_get_exporter_returns_instance(self):
        """Verify get_exporter(format) returns exporter instance."""
        from exporters import ExporterFactory, ExporterBase

        # Create a concrete exporter for testing
        class TestExporter(ExporterBase):
            @property
            def file_extension(self):
                return 'test'

            @property
            def mime_type(self):
                return 'application/test'

            def _generate(self, data, options):
                from io import BytesIO
                return BytesIO(b'test')

        ExporterFactory.register('test', TestExporter)
        exporter = ExporterFactory.get_exporter('test')

        assert isinstance(exporter, ExporterBase)
        assert isinstance(exporter, TestExporter)

        # Clean up registry
        ExporterFactory._registry.pop('test', None)

    def test_get_exporter_invalid_format_raises(self):
        """Verify ValueError raised for unsupported format."""
        from exporters import ExporterFactory

        # Clear registry to ensure no formats registered
        original_registry = ExporterFactory._registry.copy()
        ExporterFactory._registry.clear()

        try:
            with pytest.raises(ValueError) as exc_info:
                ExporterFactory.get_exporter('invalid')

            assert 'Unsupported export format' in str(exc_info.value)
            assert 'invalid' in str(exc_info.value)
        finally:
            # Restore registry
            ExporterFactory._registry.update(original_registry)

    def test_supported_formats_returns_list(self):
        """Verify supported_formats() returns list of format strings."""
        from exporters import ExporterFactory, ExporterBase

        # Create a concrete exporter for testing
        class FormatExporter(ExporterBase):
            @property
            def file_extension(self):
                return 'format'

            @property
            def mime_type(self):
                return 'application/format'

            def _generate(self, data, options):
                from io import BytesIO
                return BytesIO(b'format')

        ExporterFactory.register('format', FormatExporter)
        formats = ExporterFactory.supported_formats()

        assert isinstance(formats, list)
        assert 'format' in formats

        # Clean up registry
        ExporterFactory._registry.pop('format', None)


class TestImageResolver:
    """Test ImageResolver class behavior."""

    def test_resolve_url_files_prefix(self):
        """Verify /files/filename.jpg converts to absolute path."""
        from exporters.image_resolver import ImageResolver
        resolver = ImageResolver('/var/www/uploads')
        result = resolver.resolve_url('/files/test.jpg')
        assert result == '/var/www/uploads/test.jpg'

    def test_resolve_url_external_returns_none(self):
        """Verify external URLs return None."""
        from exporters.image_resolver import ImageResolver
        resolver = ImageResolver('/var/www/uploads')
        assert resolver.resolve_url('http://example.com/img.jpg') is None
        assert resolver.resolve_url('https://example.com/img.jpg') is None

    def test_get_image_bytes_returns_bytes(self):
        """Verify get_image_bytes(url) returns bytes or None."""
        import tempfile
        import os
        from exporters.image_resolver import ImageResolver

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test image file
            test_file = os.path.join(tmpdir, 'test.png')
            test_content = b'\x89PNG\r\n\x1a\n'  # PNG header bytes
            with open(test_file, 'wb') as f:
                f.write(test_content)

            resolver = ImageResolver(tmpdir)
            result = resolver.get_image_bytes('/files/test.png')
            assert result == test_content

            # Non-existent file returns None
            assert resolver.get_image_bytes('/files/missing.png') is None

    def test_image_exists_returns_bool(self):
        """Verify image_exists(url) returns boolean."""
        import tempfile
        import os
        from exporters.image_resolver import ImageResolver

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file
            test_file = os.path.join(tmpdir, 'exists.jpg')
            with open(test_file, 'wb') as f:
                f.write(b'test')

            resolver = ImageResolver(tmpdir)
            assert resolver.image_exists('/files/exists.jpg') is True
            assert resolver.image_exists('/files/missing.jpg') is False


class TestDependencies:
    """Test that required export dependencies are installed."""

    def test_python_docx_installed(self):
        """Verify python-docx is importable as docx."""
        import docx
        assert docx is not None

    def test_weasyprint_installed(self):
        """Verify weasyprint is importable."""
        import weasyprint
        assert weasyprint is not None

    def test_htmldocx_installed(self):
        """Verify htmldocx is importable."""
        from htmldocx import HtmlToDocx
        assert HtmlToDocx is not None


class TestPdfExporter:
    """Test PdfExporter class behavior.

    Tests for PDF export functionality implemented in Phase 09 Plan 01.
    """

    def test_file_extension(self):
        """Verify PdfExporter.file_extension returns 'pdf'."""
        from exporters.pdf import PdfExporter
        exporter = PdfExporter(uploads_path='/tmp')
        assert exporter.file_extension == 'pdf'

    def test_mime_type(self):
        """Verify PdfExporter.mime_type returns 'application/pdf'."""
        from exporters.pdf import PdfExporter
        exporter = PdfExporter(uploads_path='/tmp')
        assert exporter.mime_type == 'application/pdf'

    def test_export_returns_bytesio(self):
        """Verify export() returns BytesIO with PDF content."""
        from exporters.pdf import PdfExporter
        from unittest.mock import MagicMock

        # Create mock records
        record = MagicMock()
        record.content = '<p>Test content</p>'
        record.date.strftime = lambda fmt: '2026-03-26'

        exporter = PdfExporter(uploads_path='/tmp')
        result = exporter.export([record], title='Test Report')

        assert isinstance(result, BytesIO)
        # Verify PDF header
        result.seek(0)
        header = result.read(5)
        assert header == b'%PDF-'

    def test_image_embedding(self):
        """Verify url_fetcher resolves /files/ URLs for image embedding."""
        import tempfile
        import os
        from exporters.pdf import PdfExporter
        from unittest.mock import MagicMock

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test image file
            test_image = os.path.join(tmpdir, 'test.png')
            with open(test_image, 'wb') as f:
                f.write(b'\x89PNG\r\n\x1a\n')  # PNG header

            # Create mock record with image
            record = MagicMock()
            record.content = f'<img src="/files/test.png">'
            record.date.strftime = lambda fmt: '2026-03-26'

            exporter = PdfExporter(uploads_path=tmpdir)

            # Test url_fetcher directly
            result = exporter._resolve_image_url('/files/test.png')
            assert result['mime_type'] == 'image/png'
            assert result['string'] == b'\x89PNG\r\n\x1a\n'

    def test_headers_footers(self):
        """Verify CSS Paged Media generates headers with title and footers with page numbers."""
        from exporters.pdf import PdfExporter
        from unittest.mock import MagicMock

        record = MagicMock()
        record.content = '<p>Content</p>'
        record.date.strftime = lambda fmt: '2026-03-26'

        exporter = PdfExporter(uploads_path='/tmp')
        html = exporter._build_html([record], title='Test Title', include_date=True)

        # Verify CSS Paged Media elements
        assert '@page' in html
        assert '@top-center' in html
        assert '@bottom-left' in html
        assert '@bottom-right' in html
        assert 'counter(page)' in html
        assert 'running(header)' in html
        assert 'Test Title' in html
        assert 'Generated:' in html