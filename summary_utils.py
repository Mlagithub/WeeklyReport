"""
Summary generation utility functions.

Per SUMMARY-01: Fetch user records for time range.
Per SUMMARY-02: Assemble prompt from template.
Per SUMMARY-03: Combine with custom prompt.
Per SUMMARY-04: Call AI API and return result.
Per FILTER-SUM-01: Fetch filtered records for multiple users.
Per FILTER-SUM-02: Assemble prompt with multi-user grouping.
"""

from datetime import date

from ai_utils import call_ai_api
from models import AITemplate, Record, User, user_records
from utils import DateRange, html_to_text


def fetch_user_records(user_id: int, start_date: date, end_date: date) -> list[dict]:
    """Fetch user records within date range for summary generation.

    Per SUMMARY-01: Query user's records for selected time range.

    Args:
        user_id: ID of the user whose records to fetch
        start_date: Start date of range
        end_date: End date of range

    Returns:
        List of dicts with: {'date': date, 'content': str (plain text)}
    """
    records = (
        Record.query
        .join(user_records)
        .filter(user_records.c.user_id == user_id)
        .filter(Record.date >= start_date)
        .filter(Record.date <= end_date)
        .order_by(Record.date)
        .all()
    )

    return [
        {'date': r.date, 'content': html_to_text(r.content or '')}
        for r in records
    ]


def assemble_prompt(
    template_content: str | None,
    records: list[dict],
    user_name: str,
    time_range_key: str,
    custom_prompt: str | None = None
) -> str:
    """Assemble prompt for AI summary generation.

    Per SUMMARY-02: Fill template placeholders.
    Per SUMMARY-03: Combine with custom prompt if provided.

    Args:
        template_content: Template string with placeholders, or None for default
        records: List of {'date': date, 'content': str} dicts
        user_name: Username for placeholder
        time_range_key: Key like 'this_week', 'this_month', etc.
        custom_prompt: Optional additional prompt text

    Returns:
        Complete prompt string ready for API call
    """
    # Get Chinese time range name
    time_range_name = DateRange.TIME_RANGES.get(time_range_key, time_range_key)

    # Get date range string
    start_date, end_date = DateRange.get_range(time_range_key)
    date_range_str = f"{start_date.strftime('%Y-%m-%d')} 至 {end_date.strftime('%Y-%m-%d')}"

    # Format records as numbered list
    record_count = len(records)
    records_text = ""
    if records:
        for i, r in enumerate(records, 1):
            date_str = r['date'].strftime('%Y-%m-%d')
            records_text += f"{i}. [{date_str}] {r['content']}\n"
    else:
        records_text = "无记录"

    # Use default template if none provided
    if template_content is None:
        template_content = (
            "请根据以下记录生成{time_range}工作总结。\n\n"
            "用户：{user_name}\n"
            "记录数：{record_count}\n"
            "日期范围：{date_range}\n\n"
            "记录内容：\n{records}\n\n"
            "请总结主要工作成果和进展。"
        )

    # Fill placeholders
    prompt = template_content.format(
        time_range=time_range_name,
        user_name=user_name,
        records=records_text,
        record_count=record_count,
        date_range=date_range_str
    )

    # Prepend custom prompt if provided
    if custom_prompt:
        prompt = f"{custom_prompt}\n\n{prompt}"

    return prompt


def generate_summary(
    user_id: int,
    user_name: str,
    time_range_key: str,
    template_id: int | None = None,
    custom_prompt: str | None = None
) -> tuple[bool, str | None, str | None]:
    """Generate personal work summary using AI.

    Per SUMMARY-01: Orchestrates summary generation.
    Per SUMMARY-02: Uses template if provided.
    Per SUMMARY-03: Uses custom prompt if provided.
    Per SUMMARY-04: Returns processed HTML content.

    Args:
        user_id: User ID for record query and API audit
        user_name: Username for prompt placeholder
        time_range_key: Time range key ('this_week', 'this_month', etc.)
        template_id: Optional template ID to use
        custom_prompt: Optional custom prompt text

    Returns:
        tuple: (success: bool, content: str | None, error: str | None)
        - content is HTML-ready for display
        - error is Chinese message if failed
    """
    # Get date range
    start_date, end_date = DateRange.get_range(time_range_key)

    # Fetch user records
    records = fetch_user_records(user_id, start_date, end_date)

    # Get template content if specified
    template_content = None
    if template_id:
        template = AITemplate.query.get(template_id)
        if template:
            template_content = template.content

    # Assemble prompt
    prompt = assemble_prompt(
        template_content=template_content,
        records=records,
        user_name=user_name,
        time_range_key=time_range_key,
        custom_prompt=custom_prompt
    )

    # Call AI API
    success, content, error = call_ai_api(
        prompt=prompt,
        user_id=user_id,
        function_type="summary"
    )

    return success, content, error


def fetch_filtered_records(
    user_ids: list[int],
    start_date: date,
    end_date: date
) -> dict[int, list[dict]]:
    """Fetch records for multiple users within date range.

    Per FILTER-SUM-01: Query records for filtered users.

    Args:
        user_ids: List of user IDs to fetch records for
        start_date: Start date of range
        end_date: End date of range

    Returns:
        Dict mapping user_id to list of {'date': date, 'content': str}
    """
    import logging
    logger = logging.getLogger(__name__)

    if not user_ids:
        return {}

    logger.info(f"fetch_filtered_records: user_ids={user_ids}, date_range={start_date} to {end_date}")

    records = (
        Record.query
        .join(user_records)
        .filter(user_records.c.user_id.in_(user_ids))
        .filter(Record.date >= start_date)
        .filter(Record.date <= end_date)
        .order_by(Record.date)
        .all()
    )

    logger.info(f"Query returned {len(records)} records")

    # Group by user
    result = {}
    for r in records:
        # Find the user_id for this record via user_records
        user_id = None
        for ur in r.user:  # Record.user is the backref from User.records
            if ur.id in user_ids:
                user_id = ur.id
                break
        if user_id is None:
            continue

        if user_id not in result:
            result[user_id] = []
        result[user_id].append({
            'date': r.date,
            'content': html_to_text(r.content or '')
        })

    return result


def assemble_filtered_prompt(
    records_by_user: dict[int, list[dict]],
    user_names: dict[int, str],
    time_range_key: str,
    group_names: list[str] | None = None,
    custom_prompt: str | None = None
) -> str:
    """Assemble prompt for filtered summary with multi-user grouping.

    Per FILTER-SUM-02: Group records by user in prompt.

    Args:
        records_by_user: Dict mapping user_id to records list
        user_names: Dict mapping user_id to username
        time_range_key: Time range key like 'this_week'
        group_names: Optional list of group names for filter criteria
        custom_prompt: Optional additional prompt text

    Returns:
        Complete prompt string ready for API call
    """
    # Get Chinese time range name
    time_range_name = DateRange.TIME_RANGES.get(time_range_key, time_range_key)

    # Get date range string
    start_date, end_date = DateRange.get_range(time_range_key)
    date_range_str = f"{start_date.strftime('%Y-%m-%d')} 至 {end_date.strftime('%Y-%m-%d')}"

    # Build filter criteria section
    filter_criteria = f"时间范围：{time_range_name} ({date_range_str})"
    if group_names:
        filter_criteria += f"\n筛选组别：{', '.join(group_names)}"
    user_list = [user_names.get(uid, f"用户{uid}") for uid in records_by_user.keys()]
    filter_criteria += f"\n筛选用户：{', '.join(user_list)}"

    # Build records section grouped by user
    total_records = sum(len(r) for r in records_by_user.values())
    records_text = f"共 {total_records} 条记录，按用户分组如下：\n\n"

    for user_id, records in records_by_user.items():
        user_name = user_names.get(user_id, f"用户{user_id}")
        records_text += f"【{user_name}】({len(records)}条)\n"
        for i, r in enumerate(records, 1):
            date_str = r['date'].strftime('%Y-%m-%d')
            records_text += f"  {i}. [{date_str}] {r['content']}\n"
        records_text += "\n"

    # Default filtered summary template
    template_content = (
        "请根据以下筛选记录生成团队工作总结。\n\n"
        "{filter_criteria}\n\n"
        "{records_text}"
        "请按用户分组总结主要工作成果和进展，突出团队协作和各自贡献。"
    )

    prompt = template_content.format(
        filter_criteria=filter_criteria,
        records_text=records_text
    )

    # Prepend custom prompt if provided
    if custom_prompt:
        prompt = f"{custom_prompt}\n\n{prompt}"

    return prompt


def generate_filtered_summary(
    user_id: int,
    user_ids: list[int],
    time_range_key: str,
    group_names: list[str] | None = None,
    custom_prompt: str | None = None
) -> tuple[bool, str | None, str | None]:
    """Generate filtered summary using AI for team leaders.

    Per FILTER-SUM-01: Orchestrates filtered summary generation.
    Per FILTER-SUM-02: Returns grouped summary content.

    Args:
        user_id: Requesting user ID for audit
        user_ids: List of user IDs to include in summary
        time_range_key: Time range key
        group_names: Optional group names for display
        custom_prompt: Optional custom prompt

    Returns:
        tuple: (success: bool, content: str | None, error: str | None)
    """
    import logging
    logger = logging.getLogger(__name__)

    if not user_ids:
        return (False, None, "没有选中任何用户记录")

    # Get date range
    start_date, end_date = DateRange.get_range(time_range_key)
    logger.info(f"generate_filtered_summary: user_ids={user_ids}, date_range={start_date} to {end_date}")

    # Fetch records
    records_by_user = fetch_filtered_records(user_ids, start_date, end_date)
    logger.info(f"fetch_filtered_records returned: {len(records_by_user)} users with records, total records: {sum(len(r) for r in records_by_user.values())}")

    if not records_by_user or all(len(r) == 0 for r in records_by_user.values()):
        return (False, None, "筛选范围内没有记录数据")

    # Get user names
    users = User.query.filter(User.id.in_(user_ids)).all()
    user_names = {u.id: u.username for u in users}

    # Assemble prompt
    prompt = assemble_filtered_prompt(
        records_by_user=records_by_user,
        user_names=user_names,
        time_range_key=time_range_key,
        group_names=group_names,
        custom_prompt=custom_prompt
    )

    # Call AI API
    success, content, error = call_ai_api(
        prompt=prompt,
        user_id=user_id,
        function_type="filtered_summary"
    )

    return success, content, error
