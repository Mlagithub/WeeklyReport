"""Image URL resolver for CKEditor uploaded images.

This module provides the ImageResolver class for converting CKEditor
image URLs (e.g., /files/uuid_filename.jpg) to filesystem paths
for embedding in exported documents.

CKEditor Image Flow:
    1. User uploads via /upload route
    2. Saved to uploads/ with UUID prefix: {uuid}_{original_filename}
    3. Referenced in HTML as: <img src="/files/{uuid}_{filename}">
    4. This resolver converts /files/ URLs to absolute paths
"""

import os
from urllib.parse import unquote


class ImageResolver:
    """Resolve CKEditor image URLs to filesystem paths.

    CKEditor uploads images via /upload route, stores in uploads/
    directory with UUID-prefixed filenames, and references them
    via /files/<filename> route.

    This class converts web URLs to absolute paths for embedding
    in exported documents (PDF, DOCX).

    Attributes:
        uploads_path: Absolute path to uploads directory

    Example:
        resolver = ImageResolver('/path/to/uploads')
        path = resolver.resolve_url('/files/abc123_photo.jpg')
        # Returns: '/path/to/uploads/abc123_photo.jpg'
    """

    def __init__(self, uploads_path: str):
        """Initialize with uploads directory path.

        Args:
            uploads_path: Absolute path to uploads directory
                         (typically from app.config['UPLOADED_PATH'])
        """
        self.uploads_path = uploads_path

    def resolve_url(self, url: str) -> str | None:
        """Convert /files/<filename> URL to absolute filesystem path.

        Args:
            url: Image URL from HTML src attribute
                 (e.g., '/files/abc123_photo.jpg' or URL-encoded '/files/%E4%B8%AD%E6%96%87.png')

        Returns:
            Absolute filesystem path if local image, None if external/invalid

        Example:
            >>> resolver = ImageResolver('/var/www/uploads')
            >>> resolver.resolve_url('/files/test.jpg')
            '/var/www/uploads/test.jpg'
            >>> resolver.resolve_url('https://example.com/image.jpg')
            None
        """
        if not url:
            return None

        # Handle /files/ prefix for local uploads
        if url.startswith('/files/'):
            encoded_filename = url[7:]  # Remove '/files/' prefix (7 characters)
            # URL-decode to handle Chinese characters and special chars
            filename = unquote(encoded_filename)
            return os.path.join(self.uploads_path, filename)

        # External URLs return None (not embedded)
        if url.startswith(('http://', 'https://')):
            return None

        return None

    def get_image_bytes(self, url: str) -> bytes | None:
        """Read image file contents for embedding.

        Args:
            url: Image URL from HTML src attribute

        Returns:
            Image bytes if file exists, None if missing or external

        Example:
            >>> resolver = ImageResolver('/path/to/uploads')
            >>> data = resolver.get_image_bytes('/files/photo.jpg')
            >>> if data:
            ...     # Embed in document
        """
        local_path = self.resolve_url(url)
        if local_path and os.path.exists(local_path):
            with open(local_path, 'rb') as f:
                return f.read()
        return None

    def resolve_for_weasyprint(self, url: str) -> str:
        """Convert URL to format suitable for WeasyPrint base_url.

        WeasyPrint needs file:// URLs for local images when using
        relative URLs in HTML.

        Args:
            url: Image URL from HTML src attribute

        Returns:
            file:// URL for local images that exist, original URL otherwise

        Example:
            >>> resolver = ImageResolver('/path/to/uploads')
            >>> resolver.resolve_for_weasyprint('/files/photo.jpg')
            'file:///path/to/uploads/photo.jpg'
        """
        local_path = self.resolve_url(url)
        if local_path and os.path.exists(local_path):
            return f"file://{local_path}"
        return url

    def image_exists(self, url: str) -> bool:
        """Check if image file exists locally.

        Args:
            url: Image URL from HTML src attribute

        Returns:
            True if file exists at resolved path, False otherwise

        Example:
            >>> resolver = ImageResolver('/path/to/uploads')
            >>> resolver.image_exists('/files/existing.jpg')
            True
            >>> resolver.image_exists('/files/missing.jpg')
            False
        """
        local_path = self.resolve_url(url)
        return local_path is not None and os.path.exists(local_path)
