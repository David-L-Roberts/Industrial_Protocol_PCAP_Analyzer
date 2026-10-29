# 07: TimescaleDB High-Speed Batch Sink & MinIO PCAP Archiver

**What to build:** The persistence and storage adapters in `Analyzer.Infrastructure`. `TimescaleDbBatchSink` initializes `test_sessions`, `device_pairs`, and `tag_definitions`, streams decoded outputs in 5,000-row batches into the four TimescaleDB hypertables (`red_transactions`, `tag_values`, `captured_command_events`, `modbus_raw_unmapped`) using `NpgsqlBinaryImporter` binary `COPY`, persists $T_0$ initial baseline values onto `tag_definitions`, and transitions session status (`PROCESSING` -> `COMPLETED` / `FAILED`). `MinioPcapStorageService` archives raw PCAP files to S3-compatible MinIO object storage and records the `s3_object_key`.

**Blocked by:** 01: Core Pipeline, Virtual Clock RED Engine & Tag Resolution Engine

**Status:** ready-for-agent

- [x] Implements `IDataSink.InitializeSessionAsync` to insert session metadata, device pairs, and tag definitions inside a transaction.
- [x] Implements `IDataSink.WriteBatchAsync` using `NpgsqlBinaryImporter` (`COPY ... FROM STDIN (FORMAT BINARY)`) in bounded batches (default 5,000 rows) for `red_transactions`, `tag_values`, `captured_command_events`, and `modbus_raw_unmapped`.
- [x] Implements `IDataSink.UpdateTagInitialStatesAsync` and `CompleteSessionAsync` to persist captured $T_0$ initial tag values (`initial_unscaled_numeric_value`, `initial_scaled_numeric_value`, `initial_boolean_value`, `initial_raw_hex`) and update `test_sessions.status`.
- [x] Implements `MinioPcapStorageService` to upload raw PCAP files to a configured S3/MinIO bucket and return the `s3_object_key`.
- [x] Verified by unit tests validating batch buffering, column mapping, and storage key generation without requiring a live database in the unit test suite.

