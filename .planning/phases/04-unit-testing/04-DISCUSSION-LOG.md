# Phase 4: Unit Testing - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-23
**Phase:** 04-unit-testing
**Areas discussed:** Test Framework, Test Scope, Test Database, Coverage Target

---

## Test Framework

| Option | Description | Selected |
|--------|-------------|----------|
| pytest (Recommended) | Industry standard for Flask. Fixtures, parametrize, coverage plugin, detailed assertions. | ✓ |
| unittest | Python built-in. No dependencies, but more verbose. Good if you want zero external test deps. | |
| unittest2 | Minimal test runner on top of unittest. Simpler assertions, but less ecosystem. | |

**User's choice:** pytest
**Notes:** Standard choice, good ecosystem support

---

## Test Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Core only (Recommended) | User auth (login/register) + Record CRUD (create/edit/delete). Meets success criteria exactly. | |
| Core + Utilities | Core + DateRange, html_to_text, permission methods. More comprehensive but more work. | |
| Full Coverage | All routes, all models, all utils. Most thorough but significant effort. | ✓ |

**User's choice:** Full Coverage
**Notes:** User wants comprehensive testing of all routes, models, and utilities

---

## Test Database

| Option | Description | Selected |
|--------|-------------|----------|
| In-memory SQLite (Recommended) | Fast, isolated, no cleanup. Tests run in parallel safely. Standard for Flask unit tests. | ✓ |
| File-based test.db | Persists between runs for debugging. Slower, requires manual cleanup. | |
| Production-like | Use actual SQLite file with test data. Closest to production but slower. | |

**User's choice:** In-memory SQLite
**Notes:** Standard approach for Flask testing

---

## Coverage Target

| Option | Description | Selected |
|--------|-------------|----------|
| No target (Recommended) | No minimum percentage. Just verify core paths work. Lower pressure. | ✓ |
| 80% minimum | Standard industry minimum. CI can enforce this. | |
| 90% minimum | High coverage. Significant effort to achieve. | |

**User's choice:** No target
**Notes:** Focus on verifying functionality rather than chasing metrics

---

## Claude's Discretion

- Test file organization structure
- Specific test case naming and boundary conditions
- Fixture implementation details

## Deferred Ideas

None — discussion stayed within phase scope