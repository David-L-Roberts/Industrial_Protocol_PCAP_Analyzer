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
