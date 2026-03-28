"""PDF exporter using WeasyPrint with CSS Paged Media support.

This module provides the PdfExporter class for generating PDF documents
from weekly report records with embedded images and professional headers/footers.
"""

import os
from datetime import datetime
from io import BytesIO
from typing import Any
from urllib.parse import unquote

from weasyprint import HTML, default_url_fetcher

from .base import ExporterBase
from .image_resolver import ImageResolver


class PdfExporter(ExporterBase):
    """PDF exporter using WeasyPrint with CSS Paged Media support.

    Generates PDF documents from weekly report records with:
    - Embedded images from /files/ URLs
    - Headers with document title
    - Footers with page numbers and date

    Attributes:
        _uploads_path: Path to uploads directory (injected or from Flask config)
        _image_resolver: Lazy-loaded ImageResolver instance
    """

    def __init__(self, uploads_path: str | None = None):
        """Initialize with optional uploads path for dependency injection.

        Args:
            uploads_path: Path to uploads directory. If None, will be
                         initialized from Flask current_app.config when needed.
        """
        self._uploads_path = uploads_path
        self._image_resolver: ImageResolver | None = None

    @property
    def uploads_path(self) -> str:
        """Get uploads path, initializing from Flask config if needed."""
        if self._uploads_path is None:
            from flask import current_app

            self._uploads_path = current_app.config["UPLOADED_PATH"]
        return self._uploads_path

    @property
    def image_resolver(self) -> ImageResolver:
        """Get image resolver instance (lazy initialization)."""
        if self._image_resolver is None:
            self._image_resolver = ImageResolver(self.uploads_path)
        return self._image_resolver

    @property
    def file_extension(self) -> str:
        """Return file extension without dot."""
        return "pdf"

    @property
    def mime_type(self) -> str:
        """Return MIME type for send_file()."""
        return "application/pdf"

    def _generate(self, records: list[Any], options: dict) -> BytesIO:
        """Generate PDF from records using WeasyPrint.

        Args:
            records: List of Record objects with content and date
            options: Export options (title, include_date, etc.)

        Returns:
            BytesIO buffer containing PDF
        """
        title = options.get("title", "Weekly Report")
        include_date = options.get("include_date", True)

        # Build HTML content with CSS Paged Media
        html_content = self._build_html(records, title, include_date)

        # Create custom URL fetcher for image resolution
        def url_fetcher(url: str) -> dict:
            return self._resolve_image_url(url)

        # Generate PDF - use fake base_url to ensure url_fetcher is called for relative URLs
        html = HTML(string=html_content, base_url="http://localhost/", url_fetcher=url_fetcher)
        output = BytesIO()
        html.write_pdf(output)
        output.seek(0)
        return output

    def _build_html(self, records: list[Any], title: str, include_date: bool) -> str:
        """Build HTML document with CSS Paged Media stylesheet.

        Args:
            records: List of Record objects
            title: Document title for header
            include_date: Whether to include date in footer

        Returns:
            Complete HTML document string
        """
        date_str = datetime.now().strftime("%Y-%m-%d") if include_date else ""

        # CSS Paged Media stylesheet for headers/footers
        css = """
        <style>
        @page {
            size: A4;
            margin: 2.5cm 2cm;

            @top-center {
                content: element(header);
            }

            @bottom-left {
                content: element(footer-left);
            }

            @bottom-right {
                content: "Page " counter(page);
                font-size: 9pt;
            }
        }

        #header {
            position: running(header);
            text-align: center;
            font-size: 12pt;
            font-weight: bold;
            border-bottom: 1px solid #333;
            padding-bottom: 5px;
        }

        #footer-left {
            position: running(footer-left);
            font-size: 9pt;
            color: #666;
        }

        body {
            font-family: "Noto Sans CJK SC", "Noto Sans SC", "WenQuanYi Micro Hei", "Microsoft YaHei", Arial, sans-serif;
            line-height: 1.6;
        }

        h1, h2, h3 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f5f5f5; }
        img { max-width: 100%; height: auto; }
        .record { margin-bottom: 1em; }
        .date { color: #666; margin-bottom: 0.5em; }
        hr { border: none; border-top: 1px solid #ddd; margin: 1.5em 0; }
        </style>
        """

        # Build content sections
        content_sections = []
        for record in records:
            if record.content:
                # Get user names for this record
                user_names = ", ".join(u.username for u in record.user) if record.user else "未知用户"
                content_sections.append(f"""
                <div class="record">
                    <p class="date"><strong>{user_names}</strong> — <small>{record.date.strftime("%Y-%m-%d")}</small></p>
                    {record.content}
                </div>
                <hr>
                """)

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            {css}
        </head>
        <body>
            <div id="header">{title}</div>
            <div id="footer-left">Generated: {date_str}</div>

            {"".join(content_sections)}
        </body>
        </html>
        """

    def _resolve_image_url(self, url: str) -> dict:
        """Resolve /files/ URLs to local image data.

        Custom URL fetcher for WeasyPrint that intercepts /files/ URLs
        and returns image data from the uploads directory.

        Args:
            url: Image URL from HTML src attribute
                 (e.g., '/files/abc.jpg' or 'http://localhost/files/abc.jpg')

        Returns:
            Dict with 'string' (bytes) and 'mime_type' for images,
            or a 1x1 transparent placeholder for missing local images
        """
        # Extract the path from various URL formats
        if url.startswith("http://localhost/files/"):
            url = url[16:]  # Remove 'http://localhost' prefix, keep '/files/...'
        elif url.startswith("file:///files/"):
            url = url[7:]  # Remove 'file://' prefix, keep '/files/...'

        if url.startswith("/files/"):
            # URL-decode the filename (handles Chinese characters)
            encoded_filename = url[7:]  # Remove '/files/' prefix
            filename = unquote(encoded_filename)

            local_path = os.path.join(self.uploads_path, filename)

            if os.path.exists(local_path):
                with open(local_path, "rb") as f:
                    image_data = f.read()

                # Determine MIME type from extension
                ext = filename.rsplit(".", 1)[-1].lower()
                mime_types = {
                    "jpg": "image/jpeg",
                    "jpeg": "image/jpeg",
                    "png": "image/png",
                    "gif": "image/gif",
                }
                mime_type = mime_types.get(ext, "application/octet-stream")

                return {"string": image_data, "mime_type": mime_type}
            else:
                # Missing local image - return 1x1 transparent PNG placeholder
                transparent_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0bIDATx\x9cc`\x00\x02\x00\x00\x05\x00\x01z^\xab?\x00\x00\x00\x00IEND\xaeB`\x82"
                return {"string": transparent_png, "mime_type": "image/png"}

        # For external URLs, use default fetcher
        if url.startswith(("http://", "https://")):
            return default_url_fetcher(url)

        # Unknown URL scheme - return placeholder
        transparent_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0bIDATx\x9cc`\x00\x02\x00\x00\x05\x00\x01z^\xab?\x00\x00\x00\x00IEND\xaeB`\x82"
        return {"string": transparent_png, "mime_type": "image/png"}
