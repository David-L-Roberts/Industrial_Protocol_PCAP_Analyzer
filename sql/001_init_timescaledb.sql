CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ============================================================================
-- 1. TEST SESSIONS (Parent Metadata Table)
-- ============================================================================
CREATE TABLE test_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    pcap_file_name VARCHAR(255) NOT NULL,
    s3_object_key VARCHAR(512),
    timeout_threshold_ms INT NOT NULL DEFAULT 2000,
    store_unmapped_registers BOOLEAN NOT NULL DEFAULT FALSE,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(50) NOT NULL DEFAULT 'PROCESSING' -- 'PROCESSING', 'COMPLETED', 'FAILED'
);

-- ============================================================================
-- 2. DEVICE PAIRS (Strict Client/Server Semantics)
-- ============================================================================
CREATE TABLE device_pairs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES test_sessions(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    protocol VARCHAR(50) NOT NULL,            -- 'ModbusTCP', 'DNP3'
    client_ip INET NOT NULL,
    server_ip INET NOT NULL,
    client_protocol_address_id INT,           -- e.g. DNP3 Master Address (nullable for Modbus)
    server_protocol_address_id INT            -- e.g. DNP3 Outstation Address or Modbus Unit ID
);
CREATE INDEX idx_device_pairs_session ON device_pairs(session_id);

-- ============================================================================
-- 3. TAG DEFINITIONS (Includes Scaling & T0 Initial State for Server Replay)
-- ============================================================================
CREATE TABLE tag_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_pair_id UUID NOT NULL REFERENCES device_pairs(id) ON DELETE CASCADE,
    tag_name VARCHAR(255) NOT NULL,
    protocol_address VARCHAR(100) NOT NULL,   -- e.g. 'HR:40001', 'COIL:00012', 'G30V02:Idx4'
    data_type VARCHAR(50) NOT NULL,           -- 'BOOL', 'INT16', 'UINT16', 'INT32', 'FLOAT32_BE', 'FLOAT32_SWAPPED'
    scale_multiplier DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    scale_offset DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    engineering_units VARCHAR(50),
    description TEXT,
    -- Initial baseline state (T0) captured from first appearance in PCAP for Server Replay:
    initial_unscaled_numeric_value DOUBLE PRECISION,
    initial_scaled_numeric_value DOUBLE PRECISION,
    initial_boolean_value BOOLEAN,
    initial_raw_hex VARCHAR(64)
);
CREATE UNIQUE INDEX idx_tag_unique ON tag_definitions(device_pair_id, protocol_address);

-- ============================================================================
-- 4. RED TRANSACTIONS (Hypertable: Rate, Errors, Duration)
-- ============================================================================
CREATE TABLE red_transactions (
    timestamp TIMESTAMPTZ NOT NULL,
    session_id UUID NOT NULL REFERENCES test_sessions(id) ON DELETE CASCADE,
    device_pair_id UUID NOT NULL REFERENCES device_pairs(id) ON DELETE CASCADE,
    frame_number BIGINT NOT NULL,
    direction VARCHAR(20) NOT NULL,           -- 'CLIENT_TO_SERVER', 'SERVER_TO_CLIENT'
    transaction_id VARCHAR(50),               -- Modbus MBAP TxID or DNP3 App Sequence
    function_code SMALLINT,
    duration_ms DOUBLE PRECISION,             -- Response Timestamp - Request Timestamp
    is_error BOOLEAN NOT NULL DEFAULT FALSE,
    error_type VARCHAR(50) NOT NULL,          -- 'NONE', 'TIMEOUT', 'TIMEOUT_AT_EOF', 'EXCEPTION', 'MALFORMED'
    status_code VARCHAR(50) NOT NULL          -- 'SUCCESS', 'MODBUS_EX_02', 'DNP3_IIN_PARAM_ERR', etc.
);
SELECT create_hypertable('red_transactions', 'timestamp', chunk_time_interval => INTERVAL '1 day');
CREATE INDEX idx_red_session_cascade ON red_transactions(session_id, timestamp DESC);
CREATE INDEX idx_red_device_pair ON red_transactions(device_pair_id, timestamp DESC);

-- ============================================================================
-- 5. TAG VALUES / TIME SERIES (Hypertable: Dual Timestamps & Dual Numerics)
-- ============================================================================
CREATE TABLE tag_values (
    packet_timestamp TIMESTAMPTZ NOT NULL,
    event_timestamp TIMESTAMPTZ,              -- DNP3 internal RTU hardware timestamp (nullable)
    session_id UUID NOT NULL REFERENCES test_sessions(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES tag_definitions(id) ON DELETE CASCADE,
    frame_number BIGINT NOT NULL,
    direction VARCHAR(20) NOT NULL,           -- 'CLIENT_TO_SERVER', 'SERVER_TO_CLIENT'
    unscaled_numeric_value DOUBLE PRECISION,  -- Wire value before scaling
    scaled_numeric_value DOUBLE PRECISION,    -- (unscaled * scale_multiplier) + scale_offset
    boolean_value BOOLEAN,
    raw_hex VARCHAR(64) NOT NULL,
    quality_flags VARCHAR(100),               -- e.g. 'ONLINE|RESTART|COMM_LOST'
    is_value_change BOOLEAN NOT NULL DEFAULT FALSE
);
SELECT create_hypertable('tag_values', 'packet_timestamp', chunk_time_interval => INTERVAL '1 day');
CREATE INDEX idx_tag_vals_session_cascade ON tag_values(session_id, packet_timestamp DESC);
CREATE INDEX idx_tag_vals_query ON tag_values(tag_id, packet_timestamp DESC);
CREATE INDEX idx_tag_vals_changes ON tag_values(tag_id, packet_timestamp DESC) WHERE is_value_change = TRUE;

-- ============================================================================
-- 6. CAPTURED COMMAND EVENTS (Hypertable for Client Control Replay)
-- ============================================================================
CREATE TABLE captured_command_events (
    timestamp TIMESTAMPTZ NOT NULL,
    session_id UUID NOT NULL REFERENCES test_sessions(id) ON DELETE CASCADE,
    device_pair_id UUID NOT NULL REFERENCES device_pairs(id) ON DELETE CASCADE,
    frame_number BIGINT NOT NULL,
    direction VARCHAR(20) NOT NULL DEFAULT 'CLIENT_TO_SERVER',
    protocol VARCHAR(50) NOT NULL,            -- 'ModbusTCP', 'DNP3'
    function_code SMALLINT NOT NULL,
    command_type VARCHAR(50) NOT NULL,        -- 'MODBUS_WRITE_SINGLE_COIL', 'MODBUS_WRITE_MULTI_REGS', 'DNP3_CROB_SELECT', 'DNP3_CROB_OPERATE', 'DNP3_DIRECT_OPERATE'
    target_address VARCHAR(100) NOT NULL,     -- e.g. 'HR:40005', 'G12V01:Idx2'
    control_action VARCHAR(50),               -- DNP3 CROB: 'PULSE_ON', 'PULSE_OFF', 'LATCH_ON', 'LATCH_OFF', 'TRIP', 'CLOSE'
    command_count SMALLINT,                   -- DNP3 CROB count or Modbus register count
    pulse_on_ms BIGINT,                       -- DNP3 CROB On-Time
    pulse_off_ms BIGINT,                      -- DNP3 CROB Off-Time
    unscaled_command_value DOUBLE PRECISION,  -- Written numeric value (if applicable)
    raw_pdu_bytes BYTEA NOT NULL              -- Exact Application PDU bytes for wire-accurate replay
);
SELECT create_hypertable('captured_command_events', 'timestamp', chunk_time_interval => INTERVAL '1 day');
CREATE INDEX idx_cmd_events_session_seq ON captured_command_events(session_id, frame_number ASC);

-- ============================================================================
-- 7. UNMAPPED MODBUS REGISTERS (Hypertable for Diagnostics & Contiguous Replay)
-- ============================================================================
CREATE TABLE modbus_raw_unmapped (
    timestamp TIMESTAMPTZ NOT NULL,
    session_id UUID NOT NULL REFERENCES test_sessions(id) ON DELETE CASCADE,
    device_pair_id UUID NOT NULL REFERENCES device_pairs(id) ON DELETE CASCADE,
    frame_number BIGINT NOT NULL,
    direction VARCHAR(20) NOT NULL,           -- 'CLIENT_TO_SERVER', 'SERVER_TO_CLIENT'
    unit_id SMALLINT NOT NULL,
    register_type VARCHAR(20) NOT NULL,       -- 'HOLDING', 'INPUT', 'COIL', 'DISCRETE_INPUT'
    register_offset INT NOT NULL,
    raw_value_hex VARCHAR(16) NOT NULL
);
SELECT create_hypertable('modbus_raw_unmapped', 'timestamp', chunk_time_interval => INTERVAL '1 day');
CREATE INDEX idx_modbus_unmapped_session ON modbus_raw_unmapped(session_id, timestamp DESC);

-- ============================================================================
-- 8. SESSION CLEANUP FUNCTION (Future Compression Hook)
-- ============================================================================
CREATE OR REPLACE FUNCTION delete_test_session(target_session_id UUID)
RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN 
        SELECT DISTINCT chunk_schema, chunk_name 
        FROM timescaledb_information.chunks
        WHERE is_compressed = TRUE
    LOOP
        EXECUTE format('SELECT decompress_chunk(''%I.%I'', if_compressed => true);', r.chunk_schema, r.chunk_name);
    END LOOP;

    DELETE FROM test_sessions WHERE id = target_session_id;
END;
$$ LANGUAGE plpgsql;

