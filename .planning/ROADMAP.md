# Roadmap: 周报管理系统稳定性修复

## Overview

本项目旨在解决 Flask 周报管理系统运行约一周后导致系统 IO 过载的问题。通过替换生产级 WSGI 服务器、完善数据库会话管理、优化 SQLite 并发性能、添加单元测试和代码重构，确保系统长期稳定运行。

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Production WSGI Server** - 替换 Flask 开发服务器为生产级 WSGI 服务器
- [ ] **Phase 2: Session Management** - 实现数据库会话清理和错误处理机制
- [ ] **Phase 3: SQLite Optimization** - 启用 WAL 模式优化并发性能
- [ ] **Phase 4: Unit Testing** - 添加核心功能单元测试
- [ ] **Phase 5: Code Refactoring** - 代码结构优化（可选）

## Phase Details

### Phase 1: Production WSGI Server
**Goal**: 应用使用生产级 WSGI 服务器运行，解决 Flask 开发服务器的稳定性问题
**Depends on**: Nothing (first phase)
**Requirements**: STAB-01
**Success Criteria** (what must be TRUE):
  1. Application runs on production-grade WSGI server (not Flask dev server with debug=True)
  2. Application handles concurrent requests without stability issues
  3. Server logs are captured for debugging and monitoring
**Plans:** 3 plans

Plans:
- [ ] 01-PLAN.md — Install Gunicorn and create systemd service
- [ ] 02-PLAN.md — Configure Flask logging and logrotate
- [ ] 03-PLAN.md — Deploy and verify production server

### Phase 2: Session Management
**Goal**: 数据库连接正确管理，防止连接泄漏和事务错误
**Depends on**: Phase 1
**Requirements**: STAB-02, STAB-04
**Success Criteria** (what must be TRUE):
  1. Database sessions are properly closed after each request (no connection leaks)
  2. Database errors are caught and logged with meaningful messages
  3. Failed transactions are properly rolled back
  4. Application continues to function after database errors (no crashes)
**Plans:** 1 plan

Plans:
- [ ] 02-PLAN.md — Create @with_db_transaction decorator and apply to write operations

### Phase 3: SQLite Optimization
**Goal**: SQLite 数据库并发性能优化，避免写入锁定问题
**Depends on**: Phase 2
**Requirements**: STAB-03
**Success Criteria** (what must be TRUE):
  1. SQLite WAL mode is enabled and verified
  2. Concurrent read/write operations no longer cause database locks
  3. Database performance remains stable under normal usage (10-50 users)
**Plans:** 1 plan

Plans:
- [ ] 03-PLAN.md — Enable SQLite WAL mode via SQLAlchemy event listener

### Phase 4: Unit Testing
**Goal**: 核心功能有单元测试覆盖，验证稳定性修复有效性
**Depends on**: Phase 3
**Requirements**: TEST-01
**Success Criteria** (what must be TRUE):
  1. Core user authentication functions have unit tests
  2. Core report CRUD operations have unit tests
  3. Tests can be run with a single command (e.g., pytest)
**Plans:** 3 plans

Plans:
- [ ] 04-01-PLAN.md — Test infrastructure and utility function tests
- [ ] 04-02-PLAN.md — User permission and authorization function tests
- [ ] 04-03-PLAN.md — Authentication and CRUD route integration tests

### Phase 5: Code Refactoring
**Goal**: 代码结构更清晰易维护
**Depends on**: Phase 4
**Requirements**: REFAC-01
**Success Criteria** (what must be TRUE):
  1. Code is organized into logical modules (separation of concerns)
  2. Configuration is centralized and manageable via environment variables or config file
  3. All existing functionality continues to work after refactoring
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Production WSGI Server | 0/3 | Ready to execute | - |
| 2. Session Management | 0/1 | Ready to execute | - |
| 3. SQLite Optimization | 0/1 | Ready to execute | - |
| 4. Unit Testing | 0/3 | Ready to execute | - |
| 5. Code Refactoring | 0/TBD | Not started | - |