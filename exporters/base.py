"""Abstract base class for document exporters.

This module defines the template method pattern for export operations.
All format-specific exporters (PDF, DOCX, Excel) inherit from ExporterBase.
"""

from abc import ABC, abstractmethod
from io import BytesIO
from typing import Any


class ExporterBase(ABC):
    """Abstract base class for document exporters.

    Implements template method pattern for common export flow.
    Subclasses must implement _generate(), file_extension, and mime_type.
    """

    def export(self, records: list[Any], **options) -> BytesIO:
        """Template method defining export flow.

        Args:
            records: List of Record objects to export
            **options: Format-specific options (filename, title, etc.)

        Returns:
            BytesIO buffer containing the generated document
        """
        data = self._prepare_data(records, options)
        output = self._generate(data, options)
        return output

    @abstractmethod
    def _generate(self, data: list[Any], options: dict) -> BytesIO:
        """Format-specific generation logic.

        Must be implemented by subclasses.

        Args:
            data: Prepared data (from _prepare_data)
            options: Format-specific options

        Returns:
            BytesIO buffer containing the generated document
        """
        pass

    def _prepare_data(self, records: list[Any], options: dict) -> list[Any]:
        """Common data preparation hook.

        Override in subclasses for format-specific preprocessing.
        Default implementation returns records unchanged.

        Args:
            records: Raw Record objects
            options: Export options

        Returns:
            Prepared data for _generate()
        """
        return records

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Return file extension without dot.

        Returns:
            File extension (e.g., 'pdf', 'docx', 'xlsx')
        """
        pass

    @property
    @abstractmethod
    def mime_type(self) -> str:
        """Return MIME type for send_file().

        Returns:
            MIME type string (e.g., 'application/pdf')
        """
        pass
