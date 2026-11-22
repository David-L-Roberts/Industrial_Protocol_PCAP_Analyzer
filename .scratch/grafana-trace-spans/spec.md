# Feature Specification: SQL-Backed Trace & Span Metadata for Grafana Visualizations

- **Status:** `ready-for-agent`
- **Feature Slug:** `grafana-trace-spans`
- **Date:** 2026-11-20
- **Related ADR:** `docs/adr/0002-sql-backed-grafana-trace-spans.md`
- **Baseline Specification:** `SPECIFICATION.md` (not modified until implementation)

---

## 1. Problem Statement

The Industrial Protocol PCAP Analyzer currently persists Modbus TCP and DNP3 traffic into TimescaleDB as isolated `red_transactions`, `tag_values`, `captured_command_events`, and `modbus_raw_unmapped` rows. During Factory Acceptance Testing (FAT) and Site Acceptance Testing (SAT), engineers investigating latency spikes, device polling contention, DNP3 Select-Before-Operate (SBO) control sequences, missing Master Confirmations (`CON=1`), or anomalous tag value transitions cannot:

1. View industrial message exchanges as **Tempo-style trace waterfalls** (start time, duration, parent/child protocol handshakes, span attributes, and span timeline events) inside Grafana.
2. Visualize **device-to-device communication topology** (e.g., `SCADA_Master → SEL_RTAC → Feeder1_Relay`) with per-link request rates, latencies, and error proportions in Grafana's **Node Graph** panel.
3. Jump directly from a RED error, a slow transaction, a captured control command, or an anomalous tag reading straight into the exact trace waterfall that produced it.
4. Inspect non-RED protocol exchanges that matter for field troubleshooting—specifically DNP3 Unsolicited Responses (`FC 0x82`) and their Master Confirms (`FC 0x00`), DNP3 Direct Operate No-Ack (`FC 0x06`), and unpaired Orphan Responses.

---

## 2. Solution Overview

Extend the ingestion pipeline, protocol decoders, TimescaleDB schema, CLI, and Grafana provisioning to generate and persist **OpenTelemetry / W3C-compatible trace and span metadata** directly in TimescaleDB, and visualize it natively in Grafana using:

1. **Direct SQL → Grafana Traces & Node Graph panels** (no separate Grafana Tempo container required), while keeping the persisted schema and W3C ID format cleanly OTel-compatible so an optional OTLP/Tempo export adapter can be added later without changing the core data model.
2. **A dedicated `trace_spans` hypertable** plus nullable `trace_id` and `span_id` correlation columns on `red_transactions`, `captured_command_events`, and `tag_values` for 1-click drilldown from any metric, command, or telemetry point.
3. **Streaming-safe, protocol-native multi-step traces** driven exclusively by the Virtual Clock:
   - Every request/response exchange emits a span covering `[request_timestamp, response_timestamp]`.
   - DNP3 **Select-Before-Operate (SBO)** links `Operate` (`FC 0x04`) as a child span of its matching `Select` (`FC 0x03`) root span within a configurable `sbo_window_ms` (default `10,000` ms).
   - DNP3 **Application Confirm (`FC 0x00`)** attaches as a child span of the solicited (`FC 0x81`) or unsolicited (`FC 0x82`) response span that requested confirmation (`CON = 1`); missing confirms past `timeout_threshold_ms` emit a child `ConfirmTimeout` error span.
   - Full protocol visibility includes `Timeout`, `TimeoutAtEof`, `Malformed`, DNP3 Unsolicited (`FC 0x82`), DNP3 Direct Operate No-Ack (`FC 0x06`), and `OrphanResponse` frames.
4. **Optional human-readable device names** (`client_name`, `server_name`) on `session_manifest.json` and `device_pairs` so Grafana Trace View and Node Graph show clean plant device identities (falling back to IP + protocol address when omitted).
5. **Enabled-by-default tracing with opt-out toggle** (`store_trace_spans: true` in `session_manifest.json`, overridable via CLI `--no-traces`).
6. **PostgreSQL helper views** (`v_grafana_traces`, `v_grafana_node_graph_nodes`, `v_grafana_node_graph_edges`) plus a new provisioned **Trace & Topology Explorer** Grafana dashboard linked via 1-click Data Links from the existing `industrial_protocol_analyzer.json` dashboard.

---

## 3. User Stories

1. As a FAT/SAT test engineer, I want every Modbus TCP and DNP3 request/response transaction stored as an OTel-compatible span in TimescaleDB, so that I can inspect its exact start time, duration, frames, and metadata in Grafana's Trace View without deploying a separate Tempo server.
2. As a FAT/SAT test engineer, I want to see a device-to-device topology map in Grafana's Node Graph panel showing request volume, latency, and error ratio per link, so that I can quickly pinpoint failing or overloaded relays/outstations.
3. As a FAT/SAT test engineer, I want to assign optional human-readable `client_name` and `server_name` labels to device pairs in `session_manifest.json`, so that Grafana Trace View and Node Graph display meaningful names like `SCADA_Master`, `SEL_RTAC`, and `Feeder1_Relay` instead of raw IPs.
4. As a FAT/SAT test engineer, I want existing manifests without `client_name`, `server_name`, `store_trace_spans`, or `sbo_window_ms` to keep working unchanged with sensible defaults, so that upgrading does not break existing test configurations.
5. As a SCADA/RTAC engineer, I want DNP3 Select (`FC 0x03`) and Operate (`FC 0x04`) targeting the same point within the configured `sbo_window_ms` to share a `trace_id` with `Operate` nested as a child of `Select`, so that I can verify full Select-Before-Operate timing and outcomes in a single waterfall.
6. As a SCADA/RTAC engineer, I want DNP3 Master Application Confirms (`FC 0x00`) to attach as child spans to the solicited (`FC 0x81`) or unsolicited (`FC 0x82`) response that set `CON = 1`, so that I can measure Master confirmation latency.
7. As a SCADA/RTAC engineer, I want a missing Master Confirm (`CON = 1` unconfirmed beyond `timeout_threshold_ms` or at EOF) to emit an error child `ConfirmTimeout` span, so that I can diagnose Outstation retry storms and event buffer overflows.
8. As a SCADA/RTAC engineer, I want DNP3 Unsolicited Responses (`FC 0x82`), DNP3 Direct Operate No-Ack commands (`FC 0x06`), Malformed frames, Timeouts, and unpaired Orphan Responses to appear as spans with clear `origin_kind` classifications, so that no wire activity is invisible during root-cause analysis.
9. As a FAT/SAT engineer, I want clicking a RED error or slow transaction in the existing dashboard to open the Trace & Topology Explorer filtered to that exact `trace_id`, so that I can move seamlessly from KPI anomalies to packet-level span waterfalls.
10. As a FAT/SAT engineer, I want `tag_values` and `captured_command_events` rows to carry `trace_id` and `span_id`, so that I can trace any suspicious tag value change, quality flag drop, or control write directly back to its protocol exchange.
11. As a FAT/SAT engineer, I want each span to carry low-cardinality `operation_name` values alongside rich JSONB `attributes` (addresses, register ranges, unit/DNP3 IDs, IPs/ports, IIN flags, payload byte lengths, tag/change counts) and compact JSONB `events` (frame milestones, exceptions, commands, and capped tag-value changes), so that I can inspect full transaction context inside Grafana's Trace View.
12. As a FAT/SAT engineer, I want to view a time-window waterfall of all spans across device pairs in a capture slice (e.g., 1s or 5s bucket) in Grafana's Trace View, so that I can observe concurrent polling bursts and bus contention side by side.
13. As a test automation engineer, I want `trace_id` and `span_id` to be deterministically derived W3C hex values (32-hex / 16-hex), so that re-ingesting the same PCAP yields reproducible IDs and unit tests never suffer from random ID flakiness.
14. As a CLI operator processing very large captures where trace persistence is not needed, I want to disable tracing via `store_trace_spans: false` in the manifest or `--no-traces` on the CLI, so that I can opt out of `trace_spans` writes and leave `trace_id`/`span_id` `NULL` on correlated tables.
15. As an operator upgrading an existing TimescaleDB volume, I want an idempotent incremental SQL migration (`002_add_trace_spans.sql`) that preserves all previously ingested sessions and keeps `delete_test_session(UUID)` cascading cleanly across `trace_spans`.
16. As a maintainer, I want all tracing logic in `Analyzer.Core` and protocol decoders to follow the 6 non-negotiable architectural rules (zero external DB/tshark/OTel-SDK dependencies in `Analyzer.Core`, Virtual Clock only, strong domain typing, `net8.0` zero-warning builds, and unit testability without external binaries).

---

## 4. Architectural Rules Compliance

Every component of this extension must strictly uphold the rules in `AGENTS.md` and `SPECIFICATION.md`:

1. **Priority Order:** Maintainability, Observability, Testability, and Extensibility over micro-optimizations.
2. **Clean / Hexagonal Architecture:**
   - `Analyzer.Core` has **zero** NuGet dependencies on `Npgsql`, `tshark`, `OpenTelemetry` SDK packages, or UI frameworks. All trace/span types, deterministic ID generation (using `System.Security.Cryptography.SHA256` from the BCL), and correlation logic live in pure C# inside `Analyzer.Core` and the pure decoders.
   - `Analyzer.Decoders.Modbus` and `Analyzer.Decoders.Dnp3` remain pure domain services over `DissectedFrame` / `ReadOnlySpan<byte>`.
3. **Unit Testability Without External Binaries:** All trace generation, SBO linking, Confirm matching, Confirm-Timeout expiration, Orphan detection, and batch sink tests run without `tshark` or a live database.
4. **Virtual Clock Enforcement:** Span `StartTime`, `EndTime`, `DurationMs`, `sbo_window_ms` expiration, and `CON=1` confirm timeout evaluation are driven **exclusively** by `DissectedFrame.TimestampUtc`. `DateTime.Now` and `DateTime.UtcNow` are forbidden in domain/decoder paths.
5. **Cross-Platform `.NET 8.0`:** Compiles with zero warnings (`TreatWarningsAsErrors=true`, nullable enabled) on `win-x64` and `linux-x64`.
6. **Strong Domain Typing:** `TraceId`, `SpanId`, `SpanKind`, `SpanStatusCode`, `SpanOriginKind`, `SpanEventKind`, and `SpanCorrelationRole` are modeled as C# value objects and enums in `Analyzer.Core.Domain`. Wire/database strings are produced only at the persistence seam (`PersistenceWireFormat` / `TimescaleDbTables`).

---

## 5. Database Schema & Migration (`docker/sql/002_add_trace_spans.sql`)

### 5.1 Migration Packaging
- Add an **idempotent** incremental migration script `docker/sql/002_add_trace_spans.sql`.
- Update `docker-compose.yml` to mount `./docker/sql:/docker-entrypoint-initdb.d:ro` (instead of mounting only `001_init_timescaledb.sql`) so fresh TimescaleDB volumes automatically run `001_init_timescaledb.sql` followed by `002_add_trace_spans.sql` in lexical order, while existing volumes can execute `002_add_trace_spans.sql` directly via `psql` without dropping existing sessions.
- Existing sessions ingested prior to migration are **not** retroactively backfilled; their `trace_id`/`span_id` columns remain `NULL`.
- `delete_test_session(UUID)` continues to work without signature changes because `trace_spans` references `test_sessions(id) ON DELETE CASCADE` and uses uncompressed 1-day hypertable chunks by default.

### 5.2 Table Alterations (Backward-Compatible, Idempotent)

```sql
-- 1. test_sessions: trace toggle & DNP3 SBO correlation window
ALTER TABLE test_sessions
    ADD COLUMN IF NOT EXISTS store_trace_spans BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS sbo_window_ms INT NOT NULL DEFAULT 10000;

-- 2. device_pairs: optional human-readable endpoint names for Trace View & Node Graph
ALTER TABLE device_pairs
    ADD COLUMN IF NOT EXISTS client_name VARCHAR(100),
    ADD COLUMN IF NOT EXISTS server_name VARCHAR(100);

-- 3. Cross-table trace/span correlation columns (nullable when store_trace_spans = FALSE or legacy sessions)
ALTER TABLE red_transactions
    ADD COLUMN IF NOT EXISTS trace_id VARCHAR(32),
    ADD COLUMN IF NOT EXISTS span_id VARCHAR(16);

ALTER TABLE captured_command_events
    ADD COLUMN IF NOT EXISTS trace_id VARCHAR(32),
    ADD COLUMN IF NOT EXISTS span_id VARCHAR(16);

ALTER TABLE tag_values
    ADD COLUMN IF NOT EXISTS trace_id VARCHAR(32),
    ADD COLUMN IF NOT EXISTS span_id VARCHAR(16);

CREATE INDEX IF NOT EXISTS idx_red_tx_trace
    ON red_transactions (session_id, trace_id)
    WHERE trace_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cmd_events_trace
    ON captured_command_events (session_id, trace_id)
    WHERE trace_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tag_vals_trace
    ON tag_values (session_id, trace_id)
    WHERE trace_id IS NOT NULL;
```

### 5.3 New Hypertable: `trace_spans`

```sql
CREATE TABLE IF NOT EXISTS trace_spans (
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    duration_ms DOUBLE PRECISION NOT NULL,
    session_id UUID NOT NULL REFERENCES test_sessions(id) ON DELETE CASCADE,
    device_pair_id UUID NOT NULL REFERENCES device_pairs(id) ON DELETE CASCADE,
    trace_id VARCHAR(32) NOT NULL,               -- W3C 32 lowercase hex chars (128-bit)
    span_id VARCHAR(16) NOT NULL,                -- W3C 16 lowercase hex chars (64-bit)
    parent_span_id VARCHAR(16),                  -- Nullable; NULL for root spans
    service_name VARCHAR(128) NOT NULL,          -- Resolved server_name (or client_name for unsolicited)
    operation_name VARCHAR(128) NOT NULL,        -- Low-cardinality operation, e.g. 'Modbus FC03 ReadHoldingRegisters'
    span_kind VARCHAR(20) NOT NULL,              -- 'CLIENT', 'SERVER', 'PRODUCER', 'CONSUMER', 'INTERNAL'
    origin_kind VARCHAR(32) NOT NULL,            -- 'REQUEST_RESPONSE', 'TIMEOUT', 'TIMEOUT_AT_EOF', 'MALFORMED',
                                                 -- 'UNSOLICITED', 'DIRECT_NO_ACK', 'CONFIRM', 'CONFIRM_TIMEOUT', 'ORPHAN_RESPONSE'
    status_code VARCHAR(16) NOT NULL,            -- 'UNSET', 'OK', 'ERROR'
    status_message VARCHAR(128),                 -- e.g. 'MODBUS_EX_02', 'TIMEOUT', 'DNP3_IIN_PARAM_ERR', 'CONFIRM_TIMEOUT'
    protocol VARCHAR(50) NOT NULL,               -- 'ModbusTCP', 'DNP3'
    client_endpoint VARCHAR(128) NOT NULL,       -- Resolved client device node identity (for Node Graph source)
    server_endpoint VARCHAR(128) NOT NULL,       -- Resolved server device node identity (for Node Graph target)
    direction VARCHAR(20) NOT NULL,              -- 'CLIENT_TO_SERVER', 'SERVER_TO_CLIENT'
    request_frame_number BIGINT,                 -- Nullable (e.g. OrphanResponse, Unsolicited)
    response_frame_number BIGINT,                -- Nullable (e.g. Timeout, DirectNoAck)
    transaction_id VARCHAR(50),                  -- Modbus MBAP TxID or DNP3 App Sequence
    function_code SMALLINT,                      -- Primary protocol function code
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    events JSONB NOT NULL DEFAULT '[]'::jsonb
);

SELECT create_hypertable(
    'trace_spans',
    'start_time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

CREATE INDEX IF NOT EXISTS idx_trace_spans_session_time
    ON trace_spans (session_id, start_time DESC);

CREATE INDEX IF NOT EXISTS idx_trace_spans_session_trace
    ON trace_spans (session_id, trace_id, start_time ASC);

CREATE INDEX IF NOT EXISTS idx_trace_spans_session_errors
    ON trace_spans (session_id, start_time DESC)
    WHERE status_code = 'ERROR';

CREATE INDEX IF NOT EXISTS idx_trace_spans_device_pair
    ON trace_spans (device_pair_id, start_time DESC);
```

### 5.4 Grafana SQL Views

#### A. `v_grafana_traces` (Grafana Traces Panel DataFrame Contract)
Projects `trace_spans` into the exact column schema expected by Grafana's built-in **Traces** visualization (`format: table`), while exposing `session_id`, `device_pair_id`, `origin_kind`, and `start_time_utc` for `WHERE` filtering:

```sql
CREATE OR REPLACE VIEW v_grafana_traces AS
SELECT
    s.session_id,
    s.device_pair_id,
    s.start_time AS start_time_utc,
    s.origin_kind,
    s.protocol,
    s.trace_id AS "traceID",
    s.span_id AS "spanID",
    COALESCE(s.parent_span_id, '') AS "parentSpanID",
    s.operation_name AS "operationName",
    s.service_name AS "serviceName",
    (EXTRACT(EPOCH FROM s.start_time) * 1000.0) AS "startTime",
    s.duration_ms AS "duration",
    CASE s.status_code
        WHEN 'OK' THEN 1
        WHEN 'ERROR' THEN 2
        ELSE 0
    END AS "statusCode",
    COALESCE(s.status_message, '') AS "statusMessage",
    jsonb_build_array(
        jsonb_build_object('key', 'protocol', 'value', s.protocol),
        jsonb_build_object('key', 'device.pair.name', 'value', dp.name),
        jsonb_build_object('key', 'endpoint.client', 'value', s.client_endpoint),
        jsonb_build_object('key', 'endpoint.server', 'value', s.server_endpoint),
        jsonb_build_object('key', 'span.kind', 'value', s.span_kind),
        jsonb_build_object('key', 'span.origin_kind', 'value', s.origin_kind)
    ) AS "serviceTags",
    COALESCE(
        (
            SELECT jsonb_agg(jsonb_build_object('key', kv.key, 'value', kv.value))
            FROM jsonb_each(s.attributes) AS kv(key, value)
        ),
        '[]'::jsonb
    ) AS "tags",
    s.events AS "logs"
FROM trace_spans s
JOIN device_pairs dp ON dp.id = s.device_pair_id;
```

> **Time-Window Waterfall Query Pattern:** To inspect all concurrent spans across a capture slice (e.g., 5-second window) in Grafana's Traces panel, dashboard queries alias `"traceID"` to a synthetic window key (`md5(session_id::text || ':' || time_bucket(INTERVAL '5 seconds', start_time_utc)::text)`) while keeping `"spanID"` and `"parentSpanID"` unchanged.

#### B. `v_grafana_node_graph_nodes` and `v_grafana_node_graph_edges`
Projects device-to-device topology and per-link RED statistics for Grafana's **Node Graph** panel:

- **`v_grafana_node_graph_nodes`:** Aggregates all distinct `client_endpoint` and `server_endpoint` identities participating in `trace_spans` for each `session_id`:
  - `session_id`
  - `id` (resolved device endpoint name)
  - `title` (resolved device endpoint name)
  - `subTitle` (IP address(es) / protocol summary)
  - `mainStat` (total spans touching this node)
  - `secondaryStat` (avg latency ms across spans targeting this node)
  - `arc__success` (fraction `0.0..1.0` of non-error spans)
  - `arc__error` (fraction `0.0..1.0` of error spans)
- **`v_grafana_node_graph_edges`:** Aggregates directed links `(source, target, protocol)` per `session_id`, respecting span direction (`CLIENT_TO_SERVER` flows `client_endpoint → server_endpoint`; `SERVER_TO_CLIENT` unsolicited flows `server_endpoint → client_endpoint`):
  - `session_id`
  - `id` (`source || '->' || target || ':' || protocol`)
  - `source`
  - `target`
  - `mainStat` (span count + avg latency)
  - `secondaryStat` (error rate % + protocol)
  - `detail__protocol`
  - `detail__span_count`
  - `detail__error_count`
  - `detail__avg_duration_ms`
  - `detail__p95_duration_ms`

---

## 6. Core Domain Model & Interfaces (`Analyzer.Core`)

### 6.1 Strong Value Objects & Enums (`Analyzer.Core.Domain`)

#### Deterministic W3C Identifiers
- **`TraceId`** (`readonly struct : IEquatable<TraceId>`):
  - Stores a validated 32-character lowercase hexadecimal string (128-bit), rejecting null/empty, invalid length, non-hex characters, or all-zero (`00000000000000000000000000000000`).
  - `TraceId.Parse(string)` / `TraceId.TryParse(string?, out TraceId)`.
- **`SpanId`** (`readonly struct : IEquatable<SpanId>`):
  - Stores a validated 16-character lowercase hexadecimal string (64-bit), rejecting null/empty, invalid length, non-hex characters, or all-zero (`0000000000000000`).
  - `SpanId.Parse(string)` / `SpanId.TryParse(string?, out SpanId)`.
- **`DeterministicTraceIdGenerator`** (static pure domain service in `Analyzer.Core.Services`):
  - Computes `SHA256` over canonical UTF-8 inputs:
    - `CreateTraceId(Guid sessionId, Guid devicePairId, long anchorFrameNumber, SpanCorrelationRole role)` → first 16 bytes lower-hex (if all zeros, set lowest bit to `0x01`).
    - `CreateSpanId(Guid sessionId, Guid devicePairId, long frameNumber, SpanCorrelationRole role, int disambiguator = 0)` → first 8 bytes lower-hex (if all zeros, set lowest bit to `0x01`).
  - Zero randomness, zero external dependencies, 100% deterministic across OS/CPU architectures and unit tests.

#### Strong Domain Enums
- **`SpanKind`:** `Client`, `Server`, `Producer`, `Consumer`, `Internal`
- **`SpanStatusCode`:** `Unset`, `Ok`, `Error`
- **`SpanOriginKind`:**
  - `RequestResponse`
  - `Timeout`
  - `TimeoutAtEof`
  - `Malformed`
  - `Unsolicited`
  - `DirectNoAck`
  - `Confirm`
  - `ConfirmTimeout`
  - `OrphanResponse`
- **`SpanCorrelationRole`:**
  - `Transaction`, `SboSelect`, `SboOperate`, `UnsolicitedResponse`, `Confirm`, `ConfirmTimeout`, `DirectNoAck`, `Malformed`, `OrphanResponse`
- **`SpanEventKind`:**
  - `RequestSent`, `ResponseReceived`, `TimeoutExpired`, `ProtocolException`, `CommandIssued`, `TagValueChanged`, `ConfirmSent`, `ConfirmTimeoutExpired`

### 6.2 Span Records & Updates to Existing Domain Records

- **`SpanEventRecord`** (serialized to Grafana Trace `logs` JSONB shape `{"timestamp": <epoch_ms>, "fields": [...]}` at the persistence seam):
  - `DateTime TimestampUtc`
  - `SpanEventKind Kind`
  - `string Name`
  - `IReadOnlyDictionary<string, object?> Fields`
- **`TraceSpanRecord`:**
  - `DateTime StartTimeUtc`
  - `DateTime EndTimeUtc`
  - `double DurationMs`
  - `Guid SessionId`
  - `Guid DevicePairId`
  - `TraceId TraceId`
  - `SpanId SpanId`
  - `SpanId? ParentSpanId`
  - `string ServiceName`
  - `string OperationName`
  - `SpanKind SpanKind`
  - `SpanOriginKind OriginKind`
  - `SpanStatusCode StatusCode`
  - `string? StatusMessage`
  - `ProtocolType Protocol`
  - `string ClientEndpoint`
  - `string ServerEndpoint`
  - `TrafficDirection Direction`
  - `long? RequestFrameNumber`
  - `long? ResponseFrameNumber`
  - `string? TransactionId`
  - `short? FunctionCode`
  - `IReadOnlyDictionary<string, object?> Attributes`
  - `IReadOnlyList<SpanEventRecord> Events`
- **Updates to existing domain records (backward-compatible via trailing defaults):**
  - `TestSession`: add `bool StoreTraceSpans = true`, `int SboWindowMs = 10000`.
  - `DeviceEndpointPair`: add `string? ClientName = null`, `string? ServerName = null`, plus pure helper methods `ResolveClientEndpoint()` and `ResolveServerEndpoint()`:
    - Returns trimmed `ClientName` / `ServerName` when present; otherwise `"{Ip}:{ProtocolAddressId}"` when the corresponding protocol address ID is set, or `"{Ip}"` when null.
  - `ProtocolTransactionRecord`: add `TraceId? TraceId = null`, `SpanId? SpanId = null`.
  - `ExtractedDataPointRecord`: add `TraceId? TraceId = null`, `SpanId? SpanId = null`.
  - `CapturedCommandEventRecord`: add `TraceId? TraceId = null`, `SpanId? SpanId = null`.
  - `ProtocolDecodeOutput`: add `IReadOnlyList<TraceSpanRecord>? TraceSpans = null` (or normalized empty list `IReadOnlyList<TraceSpanRecord> TraceSpans` with backward-compatible 4-arg constructor overload if helpful for existing tests).
  - `TimeoutFlushOutput`: new immutable record `(IReadOnlyList<ProtocolTransactionRecord> Transactions, IReadOnlyList<TraceSpanRecord> TraceSpans)`.
  - `PipelineExecutionSummary`: add `long TraceSpansPersisted = 0`.
  - `PipelineProgress`: include `TraceSpansPersisted` in `TotalRecordsPersisted` (or add dedicated `TotalTraceSpans` field).

### 6.3 Service Interface & Engine Updates

- **`IProtocolDecoder.FlushExpiredTimeouts`:**
  - Change return type from `IReadOnlyList<ProtocolTransactionRecord>` to `TimeoutFlushOutput` so mid-stream and EOF virtual-clock sweeps emit both timed-out RED transactions and timed-out spans (including DNP3 `ConfirmTimeout` spans that have no corresponding `ProtocolTransactionRecord`).
- **`VirtualClockRedEngine`:**
  - Because `ModbusTcpDecoder` and `Dnp3Decoder` share a single `VirtualClockRedEngine` instance in DI, each `PendingRequest` stores an optional **`PendingSpanContext`** (pre-allocated `TraceId`, `SpanId`, `ParentSpanId`, `ServiceName`, `OperationName`, `Protocol`, `ClientEndpoint`, `ServerEndpoint`, request `Attributes`, and request `Events`).
  - `RegisterRequest(...)` accepts an optional `PendingSpanContext? spanContext` (null when `StoreTraceSpans == false`).
  - `TryCompleteResponse(...)` returns the matching `PendingSpanContext?` alongside `ProtocolTransactionRecord` (which already has `TraceId` and `SpanId` stamped when tracing is enabled).
  - `FlushExpiredTimeouts(...)` returns `TimeoutFlushOutput`: for every expired `PendingRequest`, emits both the `ProtocolTransactionRecord` (with `TraceId`/`SpanId`) and, if `spanContext` is present, the completed timeout `TraceSpanRecord` (`OriginKind = Timeout` or `TimeoutAtEof`, `StatusCode = Error`, `EndTimeUtc = StartTimeUtc + DurationMs`, `TimeoutExpired` event appended).

---

## 7. Protocol Span Semantics & State Machines

### 7.1 Device / Service Naming Rules
- **`ClientEndpoint`** = `pair.ResolveClientEndpoint()`
- **`ServerEndpoint`** = `pair.ResolveServerEndpoint()`
- **`ServiceName`:**
  - **Client-initiated exchanges** (Modbus requests/responses, DNP3 solicited polls/writes/SBO/DirectOperateNoAck, timeouts, and DNP3 Master Confirms `FC 0x00`): `ServiceName = ServerEndpoint` (the target field device/server), `Direction = ClientToServer`, `SpanKind = Client` (or `Producer` for `DirectOperateNoAck`).
  - **Outstation-initiated unsolicited exchanges** (DNP3 Unsolicited Response `FC 0x82`): `ServiceName = ClientEndpoint` (the receiving SCADA Master / client handling the unsolicited push), `Direction = ServerToClient`, `SpanKind = Consumer`; in Node Graph, the edge flows `ServerEndpoint → ClientEndpoint`.
  - **Orphan responses & malformed frames:** `ServiceName = ServerEndpoint` for `ClientToServer` malformed frames and `ClientEndpoint` for `ServerToClient` orphan/malformed frames.

### 7.2 Low-Cardinality `OperationName` Catalog

#### Modbus TCP
- `FC 0x01`: `Modbus FC01 ReadCoils`
- `FC 0x02`: `Modbus FC02 ReadDiscreteInputs`
- `FC 0x03`: `Modbus FC03 ReadHoldingRegisters`
- `FC 0x04`: `Modbus FC04 ReadInputRegisters`
- `FC 0x05`: `Modbus FC05 WriteSingleCoil`
- `FC 0x06`: `Modbus FC06 WriteSingleRegister`
- `FC 0x0F`: `Modbus FC15 WriteMultipleCoils`
- `FC 0x10`: `Modbus FC16 WriteMultipleRegisters`
- Unknown valid FC `0xNN`: `Modbus FC{NN:D2} Unknown`
- Malformed frame: `Modbus MalformedFrame`

*(When a Modbus Exception `FC >= 0x80` occurs, `operation_name` uses the base function code name, e.g., `Modbus FC03 ReadHoldingRegisters`, while `status_code = ERROR` and `status_message = MODBUS_EX_02`.)*

#### DNP3
- `FC 0x00`: `DNP3 FC00 Confirm`
- `FC 0x01`: `DNP3 FC01 Read`
- `FC 0x02`: `DNP3 FC02 Write`
- `FC 0x03`: `DNP3 FC03 Select`
- `FC 0x04`: `DNP3 FC04 Operate`
- `FC 0x05`: `DNP3 FC05 DirectOperate`
- `FC 0x06`: `DNP3 FC06 DirectOperateNoAck`
- `FC 0x0D`: `DNP3 FC13 ColdRestart`
- `FC 0x0E`: `DNP3 FC14 WarmRestart`
- `FC 0x14`: `DNP3 FC20 EnableUnsolicited`
- `FC 0x15`: `DNP3 FC21 DisableUnsolicited`
- `FC 0x17`: `DNP3 FC23 DelayMeasure`
- `FC 0x81`: `DNP3 FC129 Response` (used only for unpaired Orphan `0x81` responses; paired responses keep the initiating request's `OperationName`, e.g., `DNP3 FC01 Read` or `DNP3 FC03 Select`!)
- `FC 0x82`: `DNP3 FC130 UnsolicitedResponse`
- Unknown valid FC `0xNN`: `DNP3 FC{NN:D2} Unknown`
- Malformed frame: `DNP3 MalformedFrame`

### 7.3 Modbus TCP Span Lifecycle (`ModbusTcpDecoder`)
1. **Read Request (`FC 01–04`, `ClientToServer`):**
   - If tracing is enabled, pre-allocate `TraceId` + `SpanId` (`SpanCorrelationRole.Transaction`) and attach `PendingSpanContext` (including `modbus.unit_id`, `modbus.start_address`, `modbus.quantity`, `net.client.ip/port`, `net.server.ip/port`, `pcap.request_bytes`, and `RequestSent` event) to `_redEngine.RegisterRequest(...)`.
2. **Write Request (`FC 05, 06, 15, 16`, `ClientToServer`):**
   - Pre-allocate `TraceId` + `SpanId` and register request with `PendingSpanContext` (including `CommandIssued` event + write target/quantity).
   - Immediately stamp `(traceId, spanId)` onto the request-side `CapturedCommandEventRecord` and any extracted `ExtractedDataPointRecord`s so request-side writes correlate directly with the upcoming response (or timeout) span.
3. **Matched Response (`ServerToClient`):**
   - Complete request in `_redEngine.TryCompleteResponse(...)` to obtain `okTx` (already stamped with `TraceId`/`SpanId`) and `PendingSpanContext`.
   - Extract data points (for reads), stamp `(traceId, spanId)` onto every `ExtractedDataPointRecord`.
   - Emit `TraceSpanRecord` (`OriginKind = RequestResponse`, `StartTime = req.TimestampUtc`, `EndTime = resp.TimestampUtc`, `DurationMs = okTx.DurationMs`, `StatusCode = isException ? Error : Ok`, `StatusMessage = isException ? statusCodeWire : null`).
   - Append response attributes (`pcap.response_bytes`, `tags.matched_count`, `tags.changed_count`, `modbus.exception_code` if exception) and events (`ResponseReceived`, `ProtocolException` if exception, and capped `TagValueChanged` events — default cap **10 changed tags per span**, with `tags.changes_truncated = true` attribute when exceeded).
4. **Orphan Response (`ServerToClient` where `TryCompleteResponse` returns `false`):**
   - Do **not** emit a `ProtocolTransactionRecord` (preserving RED accuracy).
   - When tracing is enabled, emit a zero-duration `TraceSpanRecord` (`OriginKind = OrphanResponse`, `StartTime = EndTime = frame.TimestampUtc`, `DurationMs = 0`, `StatusCode = isException ? Error : Unset`, `StatusMessage = isException ? statusCodeWire : "ORPHAN_RESPONSE"`, `attributes["protocol.unpaired"] = true`).
5. **Malformed Frame (either direction):**
   - Emit existing `ProtocolTransactionRecord` (stamped with `TraceId`/`SpanId` when tracing enabled) and a zero-duration `TraceSpanRecord` (`OriginKind = Malformed`, `StatusCode = Error`, `StatusMessage = "MALFORMED"`).

### 7.4 DNP3 Span Lifecycle & Multi-Step Correlation (`Dnp3Decoder`)

Decode all four Application Control header flags from `appSpan[0]`:
- `FIR = (appControl & 0x80) != 0`
- `FIN = (appControl & 0x40) != 0`
- `CON = (appControl & 0x20) != 0`
- `UNS = (appControl & 0x10) != 0`
- `SEQ = appControl & 0x0F`

#### State Maintained Inside `Dnp3Decoder` (Virtual-Clock Driven)
1. **Pending SBO Selections** keyed by `(Guid DevicePairId, ProtocolAddress TargetAddress)`:
   - Stores `(TraceId SelectTraceId, SpanId SelectSpanId, DateTime AnchorUtc)`.
   - Registered when a `Select` (`FC 0x03`) request is sent (`AnchorUtc = request.TimestampUtc`) and refreshed upon successful `Select` response (`AnchorUtc = response.TimestampUtc`); stale entries older than `sbo_window_ms` are pruned during `FlushExpiredTimeouts` (and cleared if `Select` fails with an IIN error or times out).
   - When `Operate` (`FC 0x04`) arrives for `(DevicePairId, TargetAddress)` with `frame.TimestampUtc - pendingSbo.AnchorUtc <= sboWindowMs`:
     - Consume the pending SBO entry.
     - Assign `Operate`'s `TraceId = pendingSbo.SelectTraceId` and `ParentSpanId = pendingSbo.SelectSpanId`, with a fresh `SpanId` (`SpanCorrelationRole.SboOperate`).
     - If no active SBO selection exists (or `sbo_window_ms` elapsed), `Operate` starts its own root trace (`ParentSpanId = null`) with `attributes["dnp3.sbo_linked"] = false`.
2. **Pending Application Confirms (`CON = 1`)** keyed by `(Guid DevicePairId, int AppSeq, bool IsUnsolicited)` + min-heap ordered by `ResponseTimestampUtc`:
   - Whenever a `ServerToClient` response (`FC 0x81` solicited OR `FC 0x82` unsolicited) has `CON == true` (and tracing is enabled), register `(TraceId, SpanId, DevicePairId, AppSeq, IsUnsolicited, ResponseTimestampUtc, ClientEndpoint, ServerEndpoint, SessionId)` in the pending confirm tracker.
   - When a `ClientToServer` Application Confirm (`FC 0x00`) arrives:
     - Match against pending confirm by `(DevicePairId, AppSeq, UNS)` (falling back to `(DevicePairId, AppSeq)` if `UNS` differs).
     - Emit a child `TraceSpanRecord` (`TraceId = pending.TraceId`, `ParentSpanId = pending.SpanId`, `SpanId = CreateSpanId(..., Confirm)`, `OriginKind = Confirm`, `OperationName = "DNP3 FC00 Confirm"`, `StartTime = pending.ResponseTimestampUtc`, `EndTime = frame.TimestampUtc`, `DurationMs = (frame.TimestampUtc - pending.ResponseTimestampUtc).TotalMilliseconds`, `StatusCode = Ok`, `RequestFrameNumber = frame.FrameNumber`, `ResponseFrameNumber = pending.ResponseFrameNumber`).
     - If no pending confirm matches (orphan confirm), emit a zero-duration standalone `Confirm` span with `attributes["protocol.unpaired"] = true` and `StatusCode = Unset`.
   - During `FlushExpiredTimeouts(currentVirtualTime, isEndOfFile)`:
     - Any pending confirm where `(currentVirtualTime - pending.ResponseTimestampUtc).TotalMilliseconds > timeoutThresholdMs` OR `isEndOfFile == true` is dequeued and emits a child error `TraceSpanRecord`:
       - `TraceId = pending.TraceId`, `ParentSpanId = pending.SpanId`, `SpanId = CreateSpanId(..., ConfirmTimeout)`
       - `OriginKind = ConfirmTimeout`, `OperationName = "DNP3 FC00 Confirm"`
       - `StatusCode = Error`, `StatusMessage = isMidStreamTimeout ? "CONFIRM_TIMEOUT" : "CONFIRM_TIMEOUT_AT_EOF"`
       - `StartTime = pending.ResponseTimestampUtc`, `DurationMs = isMidStreamTimeout ? timeoutThresholdMs : Math.Max(0.0, elapsedMs)`, `EndTime = StartTime + DurationMs`
       - Event: `ConfirmTimeoutExpired`.

#### DNP3 Frame Scenarios
- **Solicited Request (`FC 0x01, 0x02, 0x03, 0x04, 0x05`, etc.) → Response (`FC 0x81`):**
  - On request: dispatch payload objects first (for `FC 02–05`) to identify any CROB `TargetAddress`, resolve SBO linkage for `FC 0x04`, pre-allocate `(TraceId, SpanId, ParentSpanId)`, stamp `(TraceId, SpanId)` onto request-side `dataPoints` and `commandEvents`, and register in `_redEngine`.
  - On `FC 0x81` response: complete in `_redEngine`, dispatch response objects, stamp `(TraceId, SpanId)` onto response-side `dataPoints` and `commandEvents`, emit `TraceSpanRecord` (capturing `dnp3.iin1`, `dnp3.iin2`, `dnp3.fir`, `dnp3.fin`, `dnp3.con`, `dnp3.uns`, `dnp3.src`, `dnp3.dst`, `dnp3.object_groups`, `tags.matched_count`, `tags.changed_count`, plus events). If `CON == true`, register in Pending Confirms.
  - On unpaired `FC 0x81` response (`TryCompleteResponse == false`): emit `OrphanResponse` span (and still register in Pending Confirms if `CON == true` so a following `FC 0x00` links cleanly!).
- **DNP3 Unsolicited Response (`FC 0x82`, `ServerToClient`):**
  - Emit a root `TraceSpanRecord` (`OriginKind = Unsolicited`, `SpanKind = Consumer`, `ServiceName = ClientEndpoint`, `OperationName = "DNP3 FC130 UnsolicitedResponse"`, `StartTime = EndTime = frame.TimestampUtc`, `DurationMs = 0`, `StatusCode = isIinError ? Error : Ok`, `ResponseFrameNumber = frame.FrameNumber`).
  - Stamp `(TraceId, SpanId)` onto all extracted `dataPoints`.
  - If `CON == true`, register in Pending Confirms so the Master's `FC 0x00` Confirm (or `ConfirmTimeout`) attaches as a child span!
  - Does **not** emit a `red_transactions` row (keeping request/response RED KPIs clean).
- **DNP3 Direct Operate No-Ack (`FC 0x06`, `ClientToServer`):**
  - Emit a root `TraceSpanRecord` (`OriginKind = DirectNoAck`, `SpanKind = Producer`, `ServiceName = ServerEndpoint`, `OperationName = "DNP3 FC06 DirectOperateNoAck"`, `StartTime = EndTime = frame.TimestampUtc`, `DurationMs = 0`, `StatusCode = Ok`, `RequestFrameNumber = frame.FrameNumber`).
  - Stamp `(TraceId, SpanId)` onto extracted `commandEvents` and `dataPoints`.
  - Does **not** register a pending request timeout in `_redEngine` (since no response is expected by protocol).
- **Malformed DNP3 Frame:**
  - Emit existing `ProtocolTransactionRecord` (stamped with `TraceId`/`SpanId`) + zero-duration `Malformed` error `TraceSpanRecord`.

### 7.5 Standard Span Attributes & Events Schema

#### `attributes` JSONB Keys (flat OTel dot-notation)
- Common: `protocol`, `session.id`, `device_pair.id`, `device_pair.name`, `net.client.ip`, `net.client.port`, `net.server.ip`, `net.server.port`, `pcap.request_frame`, `pcap.response_frame`, `pcap.request_bytes`, `pcap.response_bytes`, `protocol.function_code`, `protocol.transaction_id`, `tags.matched_count`, `tags.changed_count`, `tags.changes_truncated` (bool, optional), `protocol.unpaired` (bool, when orphan).
- Modbus: `modbus.unit_id`, `modbus.register_type`, `modbus.start_address`, `modbus.quantity`, `modbus.exception_code` (when exception).
- DNP3: `dnp3.src`, `dnp3.dst`, `dnp3.app_seq`, `dnp3.fir`, `dnp3.fin`, `dnp3.con`, `dnp3.uns`, `dnp3.iin1`, `dnp3.iin2`, `dnp3.object_groups` (comma-separated, e.g., `"G30V02,G01V02"`), `dnp3.sbo_linked` (bool, on `FC 0x04`), `dnp3.target_address` (on CROB).

#### `events` JSONB Array (Grafana Trace `logs` compatible)
Each entry is serialized at the persistence seam as:
```json
{
  "timestamp": 1732098001234.567,
  "fields": [
    { "key": "event", "value": "tag_value_changed" },
    { "key": "tag_name", "value": "Breaker_52A" },
    { "key": "scaled_value", "value": false },
    { "key": "quality_flags", "value": "ONLINE" }
  ]
}
```
- Included event kinds: `RequestSent`, `ResponseReceived`, `TimeoutExpired`, `ProtocolException`, `CommandIssued`, `ConfirmSent`, `ConfirmTimeoutExpired`, and up to **10** `TagValueChanged` events per span (bounded so large 125-register polls cannot bloat JSONB).

---

## 8. Configuration, CLI & Persistence Integration

### 8.1 `session_manifest.json` Extensions (Backward-Compatible)
```json
{
  "session_name": "SAT_Substation_Feeder1",
  "pcap_file": "feeder1_capture.pcap",
  "timeout_threshold_ms": 1500,
  "sbo_window_ms": 10000,
  "store_unmapped_registers": false,
  "store_trace_spans": true,
  "device_pairs": [
    {
      "name": "RTAC_Client_to_Relay_Server",
      "protocol": "ModbusTCP",
      "client_name": "SEL_RTAC",
      "server_name": "Feeder1_Relay",
      "client_ip": "10.0.1.10",
      "server_ip": "10.0.1.20",
      "client_protocol_address_id": null,
      "server_protocol_address_id": 1,
      "tag_mapping_csv": "relay_modbus_tags.csv"
    }
  ]
}
```
- Validation in `ManifestParser`:
  - `store_trace_spans` defaults to `true` when omitted.
  - `sbo_window_ms` defaults to `10000` when omitted; must be `> 0` (throws `FormatException` if `<= 0`).
  - `client_name` and `server_name` are optional; trimmed when provided, `null` if blank/omitted.

### 8.2 CLI Extensions (`Analyzer.Cli`)
- Add `--no-traces` (`bool`, default `false`) option to `analyze` command and `bool DisableTraces = false` to `AnalysisOptions`.
- Effective tracing setting: `session.StoreTraceSpans && !options.DisableTraces`. When `--no-traces` is passed, override `session = session with { StoreTraceSpans = false }` before `InitializeSessionAsync` so `test_sessions.store_trace_spans` accurately reflects what was persisted.
- Update CLI completion summary output to print `Trace spans persisted: <count>` when tracing is enabled.

### 8.3 Pipeline & Batch Persistence (`IngestionPipelineOrchestrator` & `TimescaleDbBatchSink`)
- `IngestionPipelineOrchestrator` buffers `TraceSpanRecord`s alongside transactions, data points, commands, and unmapped registers, counting them toward `_batchSize` and flushing via `IDataSink.WriteBatchAsync(...)`.
- When `session.StoreTraceSpans == false`, decoders do not allocate `TraceId`/`SpanId` or emit `TraceSpanRecord`s, and the orchestrator skips persisting spans.
- `TimescaleDbBatchSink`:
  - Updates `InitializeSessionAsync` `INSERT INTO test_sessions` to persist `store_trace_spans` and `sbo_window_ms`.
  - Updates `TimescaleDbTables.DevicePairs` to copy `client_name` and `server_name`.
  - Updates `TimescaleDbTables.RedTransactions`, `CapturedCommandEvents`, and `TagValues` to copy `trace_id` and `span_id`.
  - Adds `TimescaleDbTables.TraceSpans` using `NpgsqlBinaryImporter` (`NpgsqlDbType.Jsonb` for `attributes` and `events`, `NpgsqlDbType.Varchar` for `trace_id`/`span_id`/`parent_span_id` and wire enums).
  - Adds wire enum mappings in `PersistenceWireFormat` for `SpanKind`, `SpanOriginKind`, `SpanStatusCode`, plus JSON serialization helpers for `attributes` and `events`.

---

## 9. Grafana Provisioning & Dashboard Specification

### 9.1 New Provisioned Dashboard: `docker/grafana/dashboards/trace_topology_explorer.json`
Title: **Industrial Protocol Trace & Topology Explorer** (UID: `industrial-protocol-traces`).

Template variables:
- `$session`: Session selector (`SELECT name AS __text, id::text AS __value FROM test_sessions ORDER BY ingested_at DESC`)
- `$device_pair`: Multi-select / All device pairs for `$session`
- `$protocol`: Multi-select / All (`ModbusTCP`, `DNP3`)
- `$status`: Multi-select / All (`OK`, `ERROR`, `UNSET`)
- `$trace_id`: Text box / URL-bindable variable for direct Trace Waterfall inspection
- `$window_bucket`: Custom interval (`1s`, `5s`, `10s`, `30s`) for the Time-Window Waterfall panel

Panels:
1. **Device Communication Topology (Node Graph panel):**
   - Query A (`nodes`): `SELECT id, title, "subTitle", "mainStat", "secondaryStat", arc__success, arc__error FROM v_grafana_node_graph_nodes WHERE session_id = '$session';`
   - Query B (`edges`): `SELECT id, source, target, "mainStat", "secondaryStat", detail__protocol, detail__span_count, detail__error_count, detail__avg_duration_ms, detail__p95_duration_ms FROM v_grafana_node_graph_edges WHERE session_id = '$session';`
2. **Trace & Span Explorer Table (Table panel):**
   - Lists root traces / notable spans filtered by `$session`, `$device_pair`, `$protocol`, `$status`, and Grafana's `$__timeFilter(start_time)` (showing start time, `trace_id`, `service_name`, `operation_name`, `origin_kind`, `status_code`, `status_message`, `duration_ms`, span count, request/response frames).
   - Data Link on `trace_id` column sets `$trace_id` on the current dashboard to load that trace in the Waterfall panel immediately.
3. **Trace Waterfall (Traces panel):**
   - Queries `v_grafana_traces` for `session_id = '$session' AND "traceID" = '$trace_id'` ordered by `"startTime" ASC`.
   - Renders full Tempo-style hierarchical waterfall (e.g., SBO Select → Operate → Confirm), expandable `serviceTags`, `tags` (`attributes`), and `logs` (`events`).
4. **Time-Window Capture Waterfall (Traces panel, collapsible row):**
   - Queries `v_grafana_traces` for `session_id = '$session'` within `$__timeFilter(start_time_utc)` (capped to e.g. `LIMIT 250`), aliasing `"traceID"` to a single synthetic window ID so engineers can inspect concurrent multi-device polling bursts across a selected capture window.
5. **Correlated Telemetry & Commands (Table panels):**
   - Two side-by-side detail tables querying `tag_values` and `captured_command_events` where `session_id = '$session' AND trace_id = '$trace_id'`, showing the exact decoded engineering values and raw control commands associated with the selected trace.

### 9.2 1-Click Data Links from Existing Dashboard (`industrial_protocol_analyzer.json`)
Add Grafana Data Links on existing RED error/transaction tables, command event tables, and tag value tables (where `trace_id` is projected) targeting:
`/d/industrial-protocol-traces?var-session=${__data.fields.session_id}&var-trace_id=${__data.fields.trace_id}&from=${__from}&to=${__to}`

---

## 10. Testing Strategy & Seams

All tests follow the codebase's existing seam discipline—testing external behavior through the highest practical seam without invoking `tshark` or requiring a live DB in unit tests.

### 10.1 Unit Tests (`tests/*.Tests`, zero external binaries)
1. **`Analyzer.Core.Tests`:**
   - `TraceId` / `SpanId` validation (rejects bad length, non-hex, all-zeros; normalizes lowercase) and `DeterministicTraceIdGenerator` determinism + collision separation across roles/frames.
   - `DeviceEndpointPair.ResolveClientEndpoint()` / `ResolveServerEndpoint()` fallback hierarchy (`name` → `IP:addr` → `IP`).
   - `VirtualClockRedEngine`: pre-allocated `PendingSpanContext` propagation into completed transactions, mid-stream `Timeout` spans, and `TimeoutAtEof` spans via `FlushExpiredTimeouts`.
   - `IngestionPipelineOrchestrator`: end-to-end synthetic `DissectedFrame` stream verifying `trace_spans` batching, summary counts, and `--no-traces` (`StoreTraceSpans = false`) emitting zero spans and `null` correlation IDs on all tables.
2. **`Analyzer.Decoders.Modbus.Tests`:**
   - Read (`FC 01–04`) and Write (`FC 05, 06, 15, 16`) span start/end/duration, attributes, `CommandIssued` + capped `TagValueChanged` events, and identical `(TraceId, SpanId)` stamped on `red_transactions`, `captured_command_events`, and `tag_values`.
   - Modbus Exception (`FC >= 0x80`), Malformed frame, Timeout, and Orphan Response span emission.
   - `StoreTraceSpans = false` emits zero spans and `null` IDs.
3. **`Analyzer.Decoders.Dnp3.Tests`:**
   - Solicited Request → Response (`FC 0x81`) span emission, IIN error mapping, `appControl` flag extraction (`FIR/FIN/CON/UNS`), and `(TraceId, SpanId)` stamping onto `dataPoints` and `commandEvents`.
   - SBO (`FC 0x03` Select → `FC 0x04` Operate): matching `(DevicePairId, TargetAddress)` within `sbo_window_ms` links `Operate` as child of `Select`; elapsed beyond `sbo_window_ms` or different `TargetAddress` starts an independent root trace (`dnp3.sbo_linked = false`).
   - `CON = 1` Application Confirm (`FC 0x00`): links as child span to both solicited `FC 0x81` and unsolicited `FC 0x82` responses; missing confirm past `timeout_threshold_ms` or at EOF emits a child `ConfirmTimeout` error span.
   - Unsolicited (`FC 0x82`), Direct Operate No-Ack (`FC 0x06`), Orphan Response, and Malformed frame spans.
4. **`Analyzer.Infrastructure.Tests`:**
   - `ManifestParser`: parses `store_trace_spans`, `sbo_window_ms`, `client_name`, `server_name`; verifies backward-compatible defaults and rejects `sbo_window_ms <= 0`.
   - `TimescaleDbBatchSink` (via `RecordingPostgresWriter`): verifies binary `COPY` column ordering and wire/JSONB serialization for `trace_spans` and updated `device_pairs`, `red_transactions`, `captured_command_events`, `tag_values`.
5. **`Analyzer.Cli.Tests`:**
   - `--no-traces` CLI flag parsing, overriding `store_trace_spans: true` from manifest, and completion summary formatting.

### 10.2 Live Integration Tests (`tests/Analyzer.IntegrationTests`)
- Verify `002_add_trace_spans.sql` idempotency (running twice succeeds cleanly) against live TimescaleDB.
- Ingest real Modbus and DNP3 capture fixtures end-to-end and assert:
  - `trace_spans` rows exist with valid W3C hex IDs and non-negative durations.
  - Foreign correlation joins (`red_transactions`, `captured_command_events`, `tag_values` ↔ `trace_spans`) match 100%.
  - `v_grafana_traces`, `v_grafana_node_graph_nodes`, and `v_grafana_node_graph_edges` execute cleanly and return non-empty, well-typed rows matching Grafana's DataFrame contracts.
  - `delete_test_session(sessionId)` cascades and removes all `trace_spans` rows.

---

## 11. Out of Scope

- Deploying a **Grafana Tempo** server container or pushing spans via OTLP gRPC/HTTP (deferred; schema and W3C IDs are deliberately OTel-compatible so an `IOtlpSpanExporter` adapter can be added later).
- **Cross-device gateway correlation** (automatically linking upstream SCADA→RTAC DNP3 spans to downstream RTAC→Relay Modbus spans into one distributed trace).
- **Retroactive backfill** of `trace_spans` or `trace_id`/`span_id` for sessions ingested prior to applying `002_add_trace_spans.sql`.
- **Web UI (`Analyzer.Web`)** upload form updates (currently a `/health` stub).
- Adding `trace_id`/`span_id` to `modbus_raw_unmapped` (correlates via `(session_id, device_pair_id, frame_number)` if needed).

---

## 12. Suggested Implementation Sequence (Vertical Slices)

1. **Slice 1 — Core Domain & Virtual Clock Span Primitives (`Analyzer.Core`):** `TraceId`, `SpanId`, `DeterministicTraceIdGenerator`, span enums/records, `DeviceEndpointPair` endpoint helpers, `TimeoutFlushOutput`, `VirtualClockRedEngine` span context propagation, and unit tests.
2. **Slice 2 — Modbus TCP Span Emission & Cross-Record Stamping (`Analyzer.Decoders.Modbus`):** Read/write/exception/malformed/orphan spans, attributes/events, `(TraceId, SpanId)` stamping on `dataPoints`/`commandEvents`, and unit tests.
3. **Slice 3 — DNP3 Span Emission, SBO & Confirm Correlation (`Analyzer.Decoders.Dnp3`):** `appControl` flags, SBO window correlation, `CON=1` confirm & `ConfirmTimeout` tracking, Unsolicited/DirectNoAck/Orphan/Malformed spans, and unit tests.
4. **Slice 4 — SQL Migration, Manifest, Persistence & CLI (`docker/sql`, `Analyzer.Infrastructure`, `Analyzer.Cli`):** `002_add_trace_spans.sql` + views, `docker-compose.yml` mount update, `ManifestParser`, `PersistenceWireFormat`, `TimescaleDbTables`/`TimescaleDbBatchSink`, `IngestionPipelineOrchestrator`, CLI `--no-traces`, and unit + live integration tests.
5. **Slice 5 — Grafana Dashboards & Data Links (`docker/grafana/dashboards`):** Provision `trace_topology_explorer.json` (Node Graph, Trace Table, Trace Waterfall, Time-Window Waterfall, Correlated Telemetry/Commands) and add 1-click Data Links to `industrial_protocol_analyzer.json`.
