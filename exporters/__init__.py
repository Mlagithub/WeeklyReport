"""Exporters module - format-specific document exporters.

This module provides the ExporterFactory for creating format-specific
exporters and exports the base class for subclassing.

Usage:
    from exporters import ExporterFactory, ExporterBase

    # Get an exporter for a specific format
    exporter = ExporterFactory.get_exporter('pdf')
    output = exporter.export(records, title='Weekly Report')

    # Register a custom exporter (done in exporter modules)
    # ExporterFactory.register('pdf', PdfExporter)
"""

from typing import Dict, Type, List

from .base import ExporterBase
from .image_resolver import ImageResolver


class ExporterFactory:
    """Factory for creating format-specific exporters.

    Uses registry pattern to map format identifiers to exporter classes.
    Exporters are registered by each format module on import.

    Usage:
        exporter = ExporterFactory.get_exporter('pdf')
        output = exporter.export(records, title='Report')
    """

    _registry: Dict[str, Type[ExporterBase]] = {}

    @classmethod
    def register(cls, format: str, exporter_class: Type[ExporterBase]) -> None:
        """Register an exporter class for a format.

        Args:
            format: Format identifier (e.g., 'pdf', 'docx', 'xlsx')
            exporter_class: Exporter class (must inherit from ExporterBase)

        Example:
            ExporterFactory.register('pdf', PdfExporter)
        """
        cls._registry[format.lower()] = exporter_class

    @classmethod
    def get_exporter(cls, format: str) -> ExporterBase:
        """Get an exporter instance for the specified format.

        Args:
            format: Format identifier ('pdf', 'docx', 'xlsx')

        Returns:
            Exporter instance for the requested format

        Raises:
            ValueError: If format is not supported

        Example:
            exporter = ExporterFactory.get_exporter('pdf')
        """
        format_lower = format.lower()
        if format_lower not in cls._registry:
            supported = ', '.join(cls.supported_formats()) or 'none'
            raise ValueError(
                f"Unsupported export format: {format}. "
                f"Supported formats: {supported}"
            )
        return cls._registry[format_lower]()

    @classmethod
    def supported_formats(cls) -> List[str]:
        """Return list of supported format identifiers.

        Returns:
            List of registered format strings (e.g., ['pdf', 'docx', 'xlsx'])
        """
        return list(cls._registry.keys())


# Export public API
__all__ = ['ExporterFactory', 'ExporterBase', 'ImageResolver']


# Register exporters as they are implemented (Phases 9-11)
from .pdf import PdfExporter
# from .docx import DocxExporter
# from .excel import ExcelExporter
ExporterFactory.register('pdf', PdfExporter)
# ExporterFactory.register('docx', DocxExporter)
# ExporterFactory.register('xlsx', ExcelExporter)