# Phase 15: API Integration Layer - Context

**Gathered:** 2026-03-28
**Status:** Ready for planning
**Mode:** Auto-generated (infrastructure phase)

<domain>
## Phase Boundary

Implement reliable AI API integration layer with error handling, timeout management, and response processing. This is infrastructure that Phase 17-18 will consume.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — pure infrastructure phase. Use established patterns from Phase 14 (ai_utils.py) and standard OpenAI API integration approaches.

Key requirements:
- OpenAI-compatible API calls (API-01)
- Friendly Chinese error messages (API-02)
- 30-second timeout with proper notification (API-03)
- Markdown to HTML conversion if needed (API-04)
- Audit logging without sensitive content (SEC-02)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ai_utils.py` — test_ai_connection function pattern
- `models.py` — AIConfig model for API credentials
- `routes.py` — AI route patterns

### Integration Points
- `ai_utils.py` — extend with call_ai_api function
- API calls use stored config from AIConfig model
- Error messages displayed to users via flash

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase. Follow OpenAI API documentation and Python best practices.

</specifics>

<deferred>
## Deferred Ideas

None — infrastructure phase.

</deferred>