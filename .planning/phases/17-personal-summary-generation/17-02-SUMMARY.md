---
phase: 17-personal-summary-generation
plan: 02
subsystem: routes, templates
tags: [ai-summary, ajax, ui, javascript]
dependencies:
  requires: [17-01]
  provides: [generate-summary-route, ai-summary-card]
  affects: [routes.py, home.html]
tech_stack:
  added: [fetch-API, clipboard-API, JSON-response]
  patterns: [AJAX-POST, loading-states, button-disabling]
key_files:
  created: []
  modified:
    - routes.py (generate_summary_route, home route update)
    - templates/home.html (AI Summary card, JavaScript)
    - summary_utils.py (created as dependency fix)
decisions:
  - D-01: AJAX POST endpoint for summary generation (no page reload)
  - D-02: Client-side loading states (UI-01, UI-02)
  - D-03: JSON response with success/content/error fields
metrics:
  duration: ~15 minutes
  tasks: 5 (4 planned + 1 dependency fix)
  files: 3 modified
  commits: 5
---

# Phase 17 Plan 02: Personal Summary Route & UI Summary

## One-liner
Implemented AJAX route and home page UI for personal summary generation with loading states, error handling, and copy functionality.

## What Was Done

### Task 1: /generate-summary route (routes.py)
- Added POST endpoint accepting time_range, template_id, custom_prompt
- Returns JSON with success, content, error fields
- No @with_db_transaction decorator (read-only + external API call)
- Imports: SummaryGenerationForm, generate_summary

### Task 2: AI Summary card (home.html)
- Added between stats row and recent submissions row
- Time range dropdown with 4 options (SUMMARY-01)
- Template dropdown populated from summary_templates (SUMMARY-02)
- Custom prompt input field (SUMMARY-03)
- Generate button with sparkle icon
- Loading spinner hidden by default
- Result display area with copy and regenerate buttons
- Error alert area

### Task 3: JavaScript interaction
- generateSummary() sends POST to /generate-summary
- setLoading() handles UI-01 (loading indicator) and UI-02 (button disabling)
- showError() displays Chinese error messages from API
- showResult() displays HTML content from AI
- Copy functionality using Clipboard API
- Regenerate uses same parameters

### Task 4: home route update
- Added summary_templates query (AITemplate.query.order_by)
- Passed summary_templates to render_template

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking Issue] Missing dependency from Plan 17-01**
- **Found during:** Initial context load
- **Issue:** Plan 17-02 depends on Plan 17-01, but summary_utils.py and SummaryGenerationForm did not exist
- **Fix:** Created summary_utils.py with fetch_user_records, assemble_prompt, generate_summary functions; SummaryGenerationForm was already in forms.py
- **Files modified:** summary_utils.py (created), forms.py (already had form)
- **Commit:** bf0ecd6

## Verification

- /generate-summary POST route exists in routes.py
- Route returns JSON with success, content, error fields
- home.html has AI Summary card with all UI elements
- JavaScript handles button clicks, loading states, copy
- home route passes summary_templates to template

## Commits

1. bf0ecd6 - fix(17-02): add missing dependency from 17-01 - summary_utils.py
2. 28dd0dd - feat(17-02): add /generate-summary route for AJAX summary generation
3. 28f775a - feat(17-02): add AI Summary card UI to home page
4. 44b5c8f - feat(17-02): add JavaScript for summary generation interaction
5. 035c6b2 - feat(17-02): pass summary_templates to home page for dropdown

## Self-Check: PASSED

- All files created/modified exist
- All commits exist in git log
- Route and UI elements verified via grep