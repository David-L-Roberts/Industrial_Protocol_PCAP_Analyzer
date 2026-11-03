# 02: Live TimescaleDB Batch Persistence & Session Cleanup Slice

**What to build:** End-to-end live database persistence integration tests exercising PostgreSQL binary `COPY` and SQL operations against the deployed TimescaleDB schema. Tests verify creating a `TestSession`, batch-inserting `DeviceEndpointPair` and `TagDefinition` metadata, streaming `ProtocolDecodeOutput` batches into the `red_transactions`, `tag_values`, `captured_command_events`, and `modbus_raw_unmapped` hypertables, updating $T_0$ Initial States on `tag_definitions`, transitioning session status, and cleaning up session data via `delete_test_session`.

**Blocked by:** 01: Integration Test Harness, `.env` Configuration & Live Infrastructure Smoke Slice

**Status:** ready-for-agent

- [ ] Persists a `TestSession`, `DeviceEndpointPair` records, and `TagDefinition` records to the live TimescaleDB instance and verifies stored column values via SQL queries.
- [ ] Writes `ProtocolDecodeOutput` batches via binary `COPY` into `red_transactions`, `tag_values`, `captured_command_events`, and `modbus_raw_unmapped` hypertables without type or constraint errors.
- [ ] Updates $T_0$ Initial States (`initial_unscaled_numeric_value`, `initial_scaled_numeric_value`, `initial_boolean_value`, `initial_raw_hex`) on `tag_definitions` and transitions the `TestSession` status to `COMPLETED` or `FAILED`.
- [ ] Automatically cleans up each test's `TestSession` and all cascading hypertable rows in `DisposeAsync` using `SELECT delete_test_session(@sessionId)` unless `KEEP_TEST_DATA=true` is set.

