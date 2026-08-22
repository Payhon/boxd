# Phase 4 load / recovery harness

The load validator covers 1/4/16/64 Boxes for `exec`, `SSE`, `browser`, and
`preview`, with P50/P95/P99, error rate, CPU, RSS, FD, and disk-ceiling fields.
The recovery validator covers graceful stop, SIGTERM, worker SIGKILL, daemon
restart, disk full, interrupted runtime pull, SQLite backup/restore, and the
migration journal. Both are Python-stdlib only and reject secret-like values.

Fixture mode is explicitly `blocked`: it proves only matrix and schema shape.
Real evidence requires boxd, a signed runtime, and native HVF or KVM; fixtures
must never be promoted to performance or recovery passes.
