using Analyzer.Core.Domain;
using NpgsqlTypes;
using static Analyzer.Infrastructure.Persistence.PersistenceWireFormat;

namespace Analyzer.Infrastructure.Persistence;

/// <summary>
/// Column mappings from domain records to the TimescaleDB tables defined in <c>sql/001_init_timescaledb.sql</c>.
/// </summary>
internal static class TimescaleDbTables
{
    public static readonly CopyTableMap<DeviceEndpointPair> DevicePairs = new(
        "device_pairs",
        ("id", NpgsqlDbType.Uuid, r => r.Id),
        ("session_id", NpgsqlDbType.Uuid, r => r.SessionId),
        ("name", NpgsqlDbType.Varchar, r => r.Name),
        ("protocol", NpgsqlDbType.Varchar, r => ToWire(r.Protocol)),
        ("client_ip", NpgsqlDbType.Inet, r => r.ClientIp),
        ("server_ip", NpgsqlDbType.Inet, r => r.ServerIp),
        ("client_protocol_address_id", NpgsqlDbType.Integer, r => r.ClientProtocolAddressId),
        ("server_protocol_address_id", NpgsqlDbType.Integer, r => r.ServerProtocolAddressId));

    public static readonly CopyTableMap<TagDefinition> TagDefinitions = new(
        "tag_definitions",
        ("id", NpgsqlDbType.Uuid, r => r.Id),
        ("device_pair_id", NpgsqlDbType.Uuid, r => r.DevicePairId),
        ("tag_name", NpgsqlDbType.Varchar, r => r.TagName),
        ("protocol_address", NpgsqlDbType.Varchar, r => r.ProtocolAddress.Value),
        ("data_type", NpgsqlDbType.Varchar, r => ToWire(r.DataType)),
        ("scale_multiplier", NpgsqlDbType.Double, r => r.ScaleMultiplier),
        ("scale_offset", NpgsqlDbType.Double, r => r.ScaleOffset),
        ("engineering_units", NpgsqlDbType.Varchar, r => r.EngineeringUnits),
        ("description", NpgsqlDbType.Text, r => r.Description),
        ("initial_unscaled_numeric_value", NpgsqlDbType.Double, _ => null),
        ("initial_scaled_numeric_value", NpgsqlDbType.Double, _ => null),
        ("initial_boolean_value", NpgsqlDbType.Boolean, _ => null),
        ("initial_raw_hex", NpgsqlDbType.Varchar, _ => null));

    public static readonly CopyTableMap<ProtocolTransactionRecord> RedTransactions = new(
        "red_transactions",
        ("timestamp", NpgsqlDbType.TimestampTz, r => ToUtc(r.Timestamp)),
        ("session_id", NpgsqlDbType.Uuid, r => r.SessionId),
        ("device_pair_id", NpgsqlDbType.Uuid, r => r.DevicePairId),
        ("frame_number", NpgsqlDbType.Bigint, r => r.FrameNumber),
        ("direction", NpgsqlDbType.Varchar, r => ToWire(r.Direction)),
        ("transaction_id", NpgsqlDbType.Varchar, r => r.TransactionId),
        ("function_code", NpgsqlDbType.Smallint, r => r.FunctionCode),
        ("duration_ms", NpgsqlDbType.Double, r => r.DurationMs),
        ("is_error", NpgsqlDbType.Boolean, r => r.IsError),
        ("error_type", NpgsqlDbType.Varchar, r => ToWire(r.ErrorType)),
        ("status_code", NpgsqlDbType.Varchar, r => ToWire(r.StatusCode)));

    public static readonly CopyTableMap<ExtractedDataPointRecord> TagValues = new(
        "tag_values",
        ("packet_timestamp", NpgsqlDbType.TimestampTz, r => ToUtc(r.PacketTimestamp)),
        ("event_timestamp", NpgsqlDbType.TimestampTz, r => ToUtc(r.EventTimestamp)),
        ("session_id", NpgsqlDbType.Uuid, r => r.SessionId),
        ("tag_id", NpgsqlDbType.Uuid, r => r.TagId),
        ("frame_number", NpgsqlDbType.Bigint, r => r.FrameNumber),
        ("direction", NpgsqlDbType.Varchar, r => ToWire(r.Direction)),
        ("unscaled_numeric_value", NpgsqlDbType.Double, r => r.UnscaledNumericValue),
        ("scaled_numeric_value", NpgsqlDbType.Double, r => r.ScaledNumericValue),
        ("boolean_value", NpgsqlDbType.Boolean, r => r.BooleanValue),
        ("raw_hex", NpgsqlDbType.Varchar, r => r.RawHex),
        ("quality_flags", NpgsqlDbType.Varchar, r => ToWire(r.QualityFlags)),
        ("is_value_change", NpgsqlDbType.Boolean, r => r.IsValueChange));

    public static readonly CopyTableMap<CapturedCommandEventRecord> CapturedCommandEvents = new(
        "captured_command_events",
        ("timestamp", NpgsqlDbType.TimestampTz, r => ToUtc(r.Timestamp)),
        ("session_id", NpgsqlDbType.Uuid, r => r.SessionId),
        ("device_pair_id", NpgsqlDbType.Uuid, r => r.DevicePairId),
        ("frame_number", NpgsqlDbType.Bigint, r => r.FrameNumber),
        ("direction", NpgsqlDbType.Varchar, r => ToWire(r.Direction)),
        ("protocol", NpgsqlDbType.Varchar, r => ToWire(r.Protocol)),
        ("function_code", NpgsqlDbType.Smallint, r => r.FunctionCode),
        ("command_type", NpgsqlDbType.Varchar, r => ToWire(r.CommandType)),
        ("target_address", NpgsqlDbType.Varchar, r => r.TargetAddress.Value),
        ("control_action", NpgsqlDbType.Varchar, r => ToWire(r.ControlAction)),
        ("command_count", NpgsqlDbType.Smallint, r => r.CommandCount),
        ("pulse_on_ms", NpgsqlDbType.Bigint, r => r.PulseOnMs),
        ("pulse_off_ms", NpgsqlDbType.Bigint, r => r.PulseOffMs),
        ("unscaled_command_value", NpgsqlDbType.Double, r => r.UnscaledCommandValue),
        ("raw_pdu_bytes", NpgsqlDbType.Bytea, r => r.RawPduBytes));

    public static readonly CopyTableMap<ModbusUnmappedRecord> ModbusRawUnmapped = new(
        "modbus_raw_unmapped",
        ("timestamp", NpgsqlDbType.TimestampTz, r => ToUtc(r.Timestamp)),
        ("session_id", NpgsqlDbType.Uuid, r => r.SessionId),
        ("device_pair_id", NpgsqlDbType.Uuid, r => r.DevicePairId),
        ("frame_number", NpgsqlDbType.Bigint, r => r.FrameNumber),
        ("direction", NpgsqlDbType.Varchar, r => ToWire(r.Direction)),
        ("unit_id", NpgsqlDbType.Smallint, r => r.UnitId),
        ("register_type", NpgsqlDbType.Varchar, r => ToWire(r.RegisterType)),
        ("register_offset", NpgsqlDbType.Integer, r => r.RegisterOffset),
        ("raw_value_hex", NpgsqlDbType.Varchar, r => r.RawValueHex));
}
