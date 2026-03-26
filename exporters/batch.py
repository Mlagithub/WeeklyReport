"""Batch export utilities for generating ZIP archives of reports.

This module provides functions for batch exporting multiple users' reports
as a single ZIP file, leveraging the ExporterFactory for individual reports.

Usage:
    from exporters.batch import create_batch_zip, group_records_by_user

    # Group records by user
    records_by_user = group_records_by_user(records)

    # Create ZIP file
    zip_buffer = create_batch_zip(records_by_user, format='pdf')
"""

from io import BytesIO
from zipfile import ZipFile
from typing import Dict, List, Any

from . import ExporterFactory


def group_records_by_user(records: List[Any]) -> Dict[str, List[Any]]:
    """Group records by username.

    Args:
        records: List of Record objects with user relationship

    Returns:
        Dictionary mapping username to list of Record objects
    """
    records_by_user = {}
    for record in records:
        for user in record.user:
            if user.username not in records_by_user:
                records_by_user[user.username] = []
            records_by_user[user.username].append(record)
    return records_by_user


def create_batch_zip(records_by_user: Dict[str, List[Any]], format: str = 'pdf') -> BytesIO:
    """Create a ZIP archive containing individual reports for each user.

    Args:
        records_by_user: Dictionary mapping username to list of Record objects
        format: Export format ('pdf', 'docx', 'xlsx')

    Returns:
        BytesIO buffer containing the ZIP archive
    """
    zip_buffer = BytesIO()
    exporter = ExporterFactory.get_exporter(format)

    with ZipFile(zip_buffer, 'w') as zf:
        for username, user_records in records_by_user.items():
            # Generate individual report
            report_buffer = exporter.export(user_records, title=f'{username} 周报')

            # Create filename with date range
            if user_records:
                # Sort records by date (using strftime for comparison to handle mocks in tests)
                sorted_records = sorted(user_records, key=lambda r: r.date.strftime('%Y%m%d'))
                start_date = sorted_records[0].date.strftime('%Y%m%d')
                end_date = sorted_records[-1].date.strftime('%Y%m%d')
                date_range_str = f"{start_date}-{end_date}"
            else:
                date_range_str = 'nodate'

            filename = f'{username}_{date_range_str}.{exporter.file_extension}'

            # Add to ZIP
            zf.writestr(filename, report_buffer.getvalue())

    zip_buffer.seek(0)
    return zip_buffer