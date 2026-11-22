-- ============================================================================
-- Incremental Migration 002: Trace Spans Hypertable & Correlation Columns
-- Idempotent migration safe for both fresh initdb and existing TimescaleDB volumes.
-- ============================================================================

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

-- 4. trace_spans hypertable
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

-- 5. Grafana Traces & Node Graph SQL Views
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
    (EXTRACT(EPOCH FROM s.start_time) * 1000.0)::double precision AS "startTime",
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
            SELECT jsonb_agg(jsonb_build_object('key', kv.key, 'value', kv.value) ORDER BY kv.key)
            FROM jsonb_each(s.attributes) AS kv(key, value)
        ),
        '[]'::jsonb
    ) AS "tags",
    s.events AS "logs"
FROM trace_spans s
JOIN device_pairs dp ON dp.id = s.device_pair_id;

CREATE OR REPLACE VIEW v_grafana_node_graph_nodes AS
WITH node_spans AS (
    SELECT
        s.session_id,
        ep.node_id,
        ep.node_ip,
        s.protocol,
        s.duration_ms,
        ep.is_target,
        (s.status_code = 'ERROR') AS is_error
    FROM trace_spans s
    JOIN device_pairs dp ON dp.id = s.device_pair_id
    CROSS JOIN LATERAL (
        SELECT
            s.client_endpoint AS node_id,
            host(dp.client_ip) AS node_ip,
            (s.direction = 'SERVER_TO_CLIENT' OR s.client_endpoint = s.server_endpoint) AS is_target
        UNION ALL
        SELECT
            s.server_endpoint AS node_id,
            host(dp.server_ip) AS node_ip,
            (s.direction <> 'SERVER_TO_CLIENT') AS is_target
        WHERE s.server_endpoint <> s.client_endpoint
    ) ep
)
SELECT
    session_id,
    node_id AS id,
    node_id AS title,
    string_agg(DISTINCT node_ip, ', ' ORDER BY node_ip)
        || ' (' || string_agg(DISTINCT protocol, ', ' ORDER BY protocol) || ')' AS "subTitle",
    COUNT(*)::bigint AS "mainStat",
    ROUND(COALESCE(AVG(duration_ms) FILTER (WHERE is_target), 0.0)::numeric, 2)::double precision AS "secondaryStat",
    (COUNT(*) FILTER (WHERE NOT is_error)::double precision / NULLIF(COUNT(*), 0)::double precision) AS arc__success,
    (COUNT(*) FILTER (WHERE is_error)::double precision / NULLIF(COUNT(*), 0)::double precision) AS arc__error
FROM node_spans
GROUP BY session_id, node_id;

CREATE OR REPLACE VIEW v_grafana_node_graph_edges AS
WITH directed_spans AS (
    SELECT
        s.session_id,
        CASE
            WHEN s.direction = 'SERVER_TO_CLIENT' THEN s.server_endpoint
            ELSE s.client_endpoint
        END AS source,
        CASE
            WHEN s.direction = 'SERVER_TO_CLIENT' THEN s.client_endpoint
            ELSE s.server_endpoint
        END AS target,
        s.protocol,
        s.duration_ms,
        (s.status_code = 'ERROR') AS is_error
    FROM trace_spans s
),
edge_stats AS (
    SELECT
        session_id,
        source,
        target,
        protocol,
        COUNT(*)::bigint AS span_count,
        COUNT(*) FILTER (WHERE is_error)::bigint AS error_count,
        ROUND(AVG(duration_ms)::numeric, 2)::double precision AS avg_duration_ms,
        ROUND((percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms))::numeric, 2)::double precision AS p95_duration_ms
    FROM directed_spans
    GROUP BY session_id, source, target, protocol
)
SELECT
    session_id,
    source || '->' || target || ':' || protocol AS id,
    source,
    target,
    span_count::text || ' spans / ' || ROUND(avg_duration_ms::numeric, 2)::text || ' ms' AS "mainStat",
    ROUND((error_count * 100.0 / NULLIF(span_count, 0))::numeric, 1)::text || '% err (' || protocol || ')' AS "secondaryStat",
    protocol AS detail__protocol,
    span_count AS detail__span_count,
    error_count AS detail__error_count,
    avg_duration_ms AS detail__avg_duration_ms,
    p95_duration_ms AS detail__p95_duration_ms
FROM edge_stats;
