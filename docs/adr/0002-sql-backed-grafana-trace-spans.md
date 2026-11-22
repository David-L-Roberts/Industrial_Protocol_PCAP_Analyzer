# ADR 0002: SQL-Backed Trace & Span Metadata for Grafana Visualizations

- **Status:** Proposed
- **Date:** 2026-11-20

## Context

The Industrial Protocol PCAP Analyzer needs Tempo-style trace waterfall and device topology visualizations in Grafana for Modbus TCP and DNP3 FAT/SAT captures while storing all transaction metadata in TimescaleDB and preserving strict architectural rules (zero external dependencies in `Analyzer.Core`, Virtual Clock timing, deterministic unit testing, and cross-platform `.NET 8.0`).

## Decision

1. **Direct SQL → Grafana Traces & Node Graph Panels (No Tempo Server Container):**
   - Store OpenTelemetry / W3C-compatible span metadata directly in TimescaleDB and query it via PostgreSQL views (`v_grafana_traces`, `v_grafana_node_graph_nodes`, `v_grafana_node_graph_edges`) from Grafana's built-in Traces and Node Graph panels.
   - Keep `trace_id` (32 lowercase hex chars), `span_id` (16 lowercase hex chars), `span_kind`, `status_code`, `attributes` (JSONB), and `events` (JSONB) aligned with OpenTelemetry semantics so an optional OTLP exporter to Grafana Tempo can be added later without changing the core domain model or SQL schema.

2. **Dedicated `trace_spans` Hypertable + Cross-Table Correlation Columns:**
   - Persist spans in a dedicated `trace_spans` hypertable (partitioned on `start_time`, 1-day chunks, `ON DELETE CASCADE` to `test_sessions` and `device_pairs`) rather than overloading `red_transactions`, because multi-step DNP3 sequences, Master Confirms, Unsolicited Responses, Direct Operate No-Ack commands, and Orphan Responses do not map 1:1 to RED request/response rows.
   - Add nullable `trace_id` and `span_id` columns to `red_transactions`, `captured_command_events`, and `tag_values` to enable direct 1-click Grafana drilldown from any metric, control command, or telemetry reading into its trace waterfall.

3. **Streaming-Safe Natural Root Hierarchy for Multi-Step DNP3 Sequences:**
   - Emit 1 span per request/response exchange (`start_time = request_ts`, `end_time = response_ts`).
   - For DNP3 Select-Before-Operate (SBO), `Select` (`FC 0x03`) is the root span (`parent_span_id = NULL`) and the matching `Operate` (`FC 0x04`) attaches as a child span within a configurable Virtual-Clock `sbo_window_ms` (default `10,000` ms).
   - For DNP3 Application Confirm (`FC 0x00`), the confirm (or a `ConfirmTimeout` error span when `CON = 1` goes unconfirmed past `timeout_threshold_ms`) attaches as a child span of the solicited (`FC 0x81`) or unsolicited (`FC 0x82`) response span it confirms.
   - Pre-allocating `(TraceId, SpanId)` when requests register guarantees that request-side writes/commands and response-side telemetry share exact IDs in a single streaming pass with zero retroactive SQL `UPDATE`s across batches.

4. **Deterministic W3C Identifiers:**
   - Generate `TraceId` and `SpanId` value objects deterministically via BCL `SHA256` from `(SessionId, DevicePairId, FrameNumber, Role)` inside `Analyzer.Core`, eliminating RNG flakiness in unit tests and keeping re-runs reproducible without adding OpenTelemetry SDK dependencies to `Analyzer.Core`.

## Considered Options

- **Adding a Grafana Tempo container + OTLP ingestion:** Rejected for now because Tempo does not read from PostgreSQL, adds operational complexity (extra container, MinIO bucket lifecycle, and historical PCAP timestamp/block retention caveats), and duplicates storage already managed in TimescaleDB.
- **Extending `red_transactions` as a single unified table:** Rejected because storing Confirm, Unsolicited, Direct-No-Ack, and Orphan spans inside `red_transactions` would distort existing RED KPI queries and require retrofitting filters across existing dashboards.
- **Synthetic SBO wrapper parent span:** Rejected because buffering `Select` until `Operate` arrives (or SBO timeout expires) breaks single-pass streaming immutability and complicates batch flushing.

## Consequences

- Grafana renders interactive Tempo-style waterfalls, span tags/logs, and device topology Node Graphs directly from TimescaleDB with zero extra Docker services and full fidelity for historical PCAP Virtual-Clock timestamps.
- `IProtocolDecoder.FlushExpiredTimeouts` returns `TimeoutFlushOutput` (both timed-out RED transactions and timed-out spans, including DNP3 `ConfirmTimeout` spans), and `VirtualClockRedEngine` carries an optional `PendingSpanContext` on pending requests so shared-engine timeout sweeps remain protocol-agnostic.
- Adding `trace_id` and `span_id` to `tag_values` increases per-row storage slightly on high-volume telemetry tables; operators can opt out per session via `store_trace_spans: false` or CLI `--no-traces`.
- Existing databases upgrade cleanly via idempotent `docker/sql/002_add_trace_spans.sql`, though previously ingested sessions require PCAP re-ingestion to populate `trace_spans`.
