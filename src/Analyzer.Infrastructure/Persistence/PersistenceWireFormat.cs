using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Analyzer.Core.Domain;

namespace Analyzer.Infrastructure.Persistence;

/// <summary>
/// Persistence seam: serializes strongly typed domain enums and metadata into the wire literals and JSONB payloads
/// stored in TimescaleDB (see <c>docker/sql/001_init_timescaledb.sql</c> and <c>002_add_trace_spans.sql</c>).
/// </summary>
internal static class PersistenceWireFormat
{
    public static string ToWire(TrafficDirection value) => value switch
    {
        TrafficDirection.ClientToServer => "CLIENT_TO_SERVER",
        TrafficDirection.ServerToClient => "SERVER_TO_CLIENT",
        _ => throw Unmapped(value)
    };

    public static string ToWire(TransactionErrorType value) => value switch
    {
        TransactionErrorType.None => "NONE",
        TransactionErrorType.Timeout => "TIMEOUT",
        TransactionErrorType.TimeoutAtEof => "TIMEOUT_AT_EOF",
        TransactionErrorType.Exception => "EXCEPTION",
        TransactionErrorType.Malformed => "MALFORMED",
        _ => throw Unmapped(value)
    };

    public static string ToWire(TransactionStatusCode value) => value switch
    {
        TransactionStatusCode.Success => "SUCCESS",
        TransactionStatusCode.Timeout => "TIMEOUT",
        TransactionStatusCode.TimeoutAtEof => "TIMEOUT_AT_EOF",
        TransactionStatusCode.Malformed => "MALFORMED",
        TransactionStatusCode.ModbusEx01 => "MODBUS_EX_01",
        TransactionStatusCode.ModbusEx02 => "MODBUS_EX_02",
        TransactionStatusCode.ModbusEx03 => "MODBUS_EX_03",
        TransactionStatusCode.ModbusEx04 => "MODBUS_EX_04",
        TransactionStatusCode.ModbusEx05 => "MODBUS_EX_05",
        TransactionStatusCode.ModbusEx06 => "MODBUS_EX_06",
        TransactionStatusCode.ModbusEx08 => "MODBUS_EX_08",
        TransactionStatusCode.ModbusEx0A => "MODBUS_EX_0A",
        TransactionStatusCode.ModbusEx0B => "MODBUS_EX_0B",
        TransactionStatusCode.ModbusExceptionUnknown => "MODBUS_EX_UNKNOWN",
        TransactionStatusCode.Dnp3IinFuncNotSupported => "DNP3_IIN_FUNC_NOT_SUPPORTED",
        TransactionStatusCode.Dnp3IinObjectUnknown => "DNP3_IIN_OBJECT_UNKNOWN",
        TransactionStatusCode.Dnp3IinParamErr => "DNP3_IIN_PARAM_ERR",
        TransactionStatusCode.Dnp3IinEventBufferOverflow => "DNP3_IIN_EVENT_BUFFER_OVERFLOW",
        TransactionStatusCode.Dnp3IinAlreadyExecuting => "DNP3_IIN_ALREADY_EXECUTING",
        TransactionStatusCode.Dnp3IinConfigCorrupt => "DNP3_IIN_CONFIG_CORRUPT",
        _ => throw Unmapped(value)
    };

    public static string ToWire(SessionStatus value) => value switch
    {
        SessionStatus.Processing => "PROCESSING",
        SessionStatus.Completed => "COMPLETED",
        SessionStatus.Failed => "FAILED",
        _ => throw Unmapped(value)
    };

    public static string ToWire(TagDataType value) => value switch
    {
        TagDataType.Bool => "BOOL",
        TagDataType.Int16 => "INT16",
        TagDataType.UInt16 => "UINT16",
        TagDataType.Int32 => "INT32",
        TagDataType.UInt32 => "UINT32",
        TagDataType.Int64 => "INT64",
        TagDataType.UInt64 => "UINT64",
        TagDataType.Float32 => "FLOAT32",
        TagDataType.Float64 => "FLOAT64",
        _ => throw Unmapped(value)
    };

    public static string ToWire(RegisterEndianness value) => value switch
    {
        RegisterEndianness.Abcd => "ABCD",
        RegisterEndianness.Dcba => "DCBA",
        RegisterEndianness.Badc => "BADC",
        RegisterEndianness.Cdab => "CDAB",
        _ => throw Unmapped(value)
    };

    /// <summary>
    /// Normalizes a domain timestamp to UTC for <c>TIMESTAMPTZ</c> columns. Domain timestamps are UTC by
    /// convention, so <see cref="DateTimeKind.Unspecified"/> values are tagged as UTC rather than shifted.
    /// </summary>
    public static DateTime ToUtc(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
    };

    public static DateTime? ToUtc(DateTime? value) => value.HasValue ? ToUtc(value.Value) : null;

    public static string ToWire(ProtocolType value) => value switch
    {
        ProtocolType.ModbusTcp => "ModbusTCP",
        ProtocolType.Dnp3 => "DNP3",
        _ => throw Unmapped(value)
    };

    public static string ToWire(CommandType value) => value switch
    {
        CommandType.ModbusWriteSingleCoil => "MODBUS_WRITE_SINGLE_COIL",
        CommandType.ModbusWriteSingleReg => "MODBUS_WRITE_SINGLE_REG",
        CommandType.ModbusWriteMultiCoils => "MODBUS_WRITE_MULTI_COILS",
        CommandType.ModbusWriteMultiRegs => "MODBUS_WRITE_MULTI_REGS",
        CommandType.Dnp3CrobSelect => "DNP3_CROB_SELECT",
        CommandType.Dnp3CrobOperate => "DNP3_CROB_OPERATE",
        CommandType.Dnp3DirectOperate => "DNP3_DIRECT_OPERATE",
        _ => throw Unmapped(value)
    };

    public static string? ToWire(Dnp3ControlAction? value) => value switch
    {
        null => null,
        Dnp3ControlAction.PulseOn => "PULSE_ON",
        Dnp3ControlAction.PulseOff => "PULSE_OFF",
        Dnp3ControlAction.LatchOn => "LATCH_ON",
        Dnp3ControlAction.LatchOff => "LATCH_OFF",
        Dnp3ControlAction.Trip => "TRIP",
        Dnp3ControlAction.Close => "CLOSE",
        _ => throw Unmapped(value.Value)
    };

    public static string ToWire(ModbusRegisterType value) => value switch
    {
        ModbusRegisterType.Holding => "HOLDING",
        ModbusRegisterType.Input => "INPUT",
        ModbusRegisterType.Coil => "COIL",
        ModbusRegisterType.DiscreteInput => "DISCRETE_INPUT",
        _ => throw Unmapped(value)
    };

    public static string ToWire(SpanKind value) => value switch
    {
        SpanKind.Client => "CLIENT",
        SpanKind.Server => "SERVER",
        SpanKind.Producer => "PRODUCER",
        SpanKind.Consumer => "CONSUMER",
        SpanKind.Internal => "INTERNAL",
        _ => throw Unmapped(value)
    };

    public static string ToWire(SpanStatusCode value) => value switch
    {
        SpanStatusCode.Unset => "UNSET",
        SpanStatusCode.Ok => "OK",
        SpanStatusCode.Error => "ERROR",
        _ => throw Unmapped(value)
    };

    public static string ToWire(SpanOriginKind value) => value switch
    {
        SpanOriginKind.RequestResponse => "REQUEST_RESPONSE",
        SpanOriginKind.Timeout => "TIMEOUT",
        SpanOriginKind.TimeoutAtEof => "TIMEOUT_AT_EOF",
        SpanOriginKind.Malformed => "MALFORMED",
        SpanOriginKind.Unsolicited => "UNSOLICITED",
        SpanOriginKind.DirectNoAck => "DIRECT_NO_ACK",
        SpanOriginKind.Confirm => "CONFIRM",
        SpanOriginKind.ConfirmTimeout => "CONFIRM_TIMEOUT",
        SpanOriginKind.OrphanResponse => "ORPHAN_RESPONSE",
        _ => throw Unmapped(value)
    };

    public static string ToWire(SpanEventKind value) => value switch
    {
        SpanEventKind.RequestSent => "request_sent",
        SpanEventKind.ResponseReceived => "response_received",
        SpanEventKind.TimeoutExpired => "timeout_expired",
        SpanEventKind.ProtocolException => "protocol_exception",
        SpanEventKind.CommandIssued => "command_issued",
        SpanEventKind.TagValueChanged => "tag_value_changed",
        SpanEventKind.ConfirmSent => "confirm_sent",
        SpanEventKind.ConfirmTimeoutExpired => "confirm_timeout_expired",
        _ => throw Unmapped(value)
    };

    public static string ToAttributesJson(IReadOnlyDictionary<string, object?>? attributes)
    {
        if (attributes is null || attributes.Count == 0)
        {
            return "{}";
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var kvp in attributes)
            {
                writer.WritePropertyName(kvp.Key);
                WriteJsonValue(writer, kvp.Value);
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    public static string ToEventsJson(IReadOnlyList<SpanEventRecord>? events)
    {
        if (events is null || events.Count == 0)
        {
            return "[]";
        }

        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartArray();
            foreach (var ev in events)
            {
                writer.WriteStartObject();
                double epochMs = (ToUtc(ev.TimestampUtc) - DateTime.UnixEpoch).TotalMilliseconds;
                writer.WriteNumber("timestamp", epochMs);
                writer.WriteStartArray("fields");

                string eventWire = ToWire(ev.Kind);
                WriteKeyValueField(writer, "event", eventWire);

                if (!string.IsNullOrWhiteSpace(ev.Name) &&
                    !string.Equals(ev.Name, eventWire, StringComparison.OrdinalIgnoreCase))
                {
                    WriteKeyValueField(writer, "name", ev.Name);
                }

                if (ev.Fields is not null)
                {
                    foreach (var field in ev.Fields)
                    {
                        if (string.Equals(field.Key, "event", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        WriteKeyValueField(writer, field.Key, field.Value);
                    }
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void WriteKeyValueField(Utf8JsonWriter writer, string key, object? value)
    {
        writer.WriteStartObject();
        writer.WriteString("key", key);
        writer.WritePropertyName("value");
        WriteJsonValue(writer, value);
        writer.WriteEndObject();
    }

    private static void WriteJsonValue(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                break;
            case string s:
                writer.WriteStringValue(s);
                break;
            case bool b:
                writer.WriteBooleanValue(b);
                break;
            case int i:
                writer.WriteNumberValue(i);
                break;
            case long l:
                writer.WriteNumberValue(l);
                break;
            case short sh:
                writer.WriteNumberValue(sh);
                break;
            case ushort us:
                writer.WriteNumberValue(us);
                break;
            case uint ui:
                writer.WriteNumberValue(ui);
                break;
            case ulong ul:
                writer.WriteNumberValue(ul);
                break;
            case byte by:
                writer.WriteNumberValue(by);
                break;
            case sbyte sby:
                writer.WriteNumberValue(sby);
                break;
            case double d:
                if (double.IsFinite(d))
                {
                    writer.WriteNumberValue(d);
                }
                else
                {
                    writer.WriteStringValue(d.ToString(CultureInfo.InvariantCulture));
                }
                break;
            case float f:
                if (float.IsFinite(f))
                {
                    writer.WriteNumberValue(f);
                }
                else
                {
                    writer.WriteStringValue(f.ToString(CultureInfo.InvariantCulture));
                }
                break;
            case decimal dec:
                writer.WriteNumberValue(dec);
                break;
            case Guid g:
                writer.WriteStringValue(g.ToString("D"));
                break;
            case DateTime dt:
                writer.WriteStringValue(ToUtc(dt).ToString("O", CultureInfo.InvariantCulture));
                break;
            case DateTimeOffset dto:
                writer.WriteStringValue(dto.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
                break;
            case TraceId tid:
                writer.WriteStringValue(tid.Value);
                break;
            case SpanId sid:
                writer.WriteStringValue(sid.Value);
                break;
            case ProtocolAddress pa:
                writer.WriteStringValue(pa.Value);
                break;
            case Enum e:
                writer.WriteStringValue(e.ToString());
                break;
            default:
                writer.WriteStringValue(Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty);
                break;
        }
    }

    private static readonly (PointQualityFlags Flag, string Wire)[] QualityFlagWireNames =
    [
        (PointQualityFlags.Online, "ONLINE"),
        (PointQualityFlags.Restart, "RESTART"),
        (PointQualityFlags.CommLost, "COMM_LOST"),
        (PointQualityFlags.RemoteForced, "REMOTE_FORCED"),
        (PointQualityFlags.LocalForced, "LOCAL_FORCED"),
        (PointQualityFlags.ChatterFilter, "CHATTER_FILTER"),
        (PointQualityFlags.OverRange, "OVER_RANGE"),
        (PointQualityFlags.ReferenceErr, "REFERENCE_ERR")
    ];

    /// <summary>
    /// Serializes quality flags as a pipe-delimited list in bit order (e.g. <c>ONLINE|RESTART|COMM_LOST</c>);
    /// <see cref="PointQualityFlags.None"/> is stored as SQL NULL.
    /// </summary>
    public static string? ToWire(PointQualityFlags value)
    {
        if (value == PointQualityFlags.None)
        {
            return null;
        }

        var names = new List<string>(QualityFlagWireNames.Length);
        var remaining = value;
        foreach (var (flag, wire) in QualityFlagWireNames)
        {
            if (value.HasFlag(flag))
            {
                names.Add(wire);
                remaining &= ~flag;
            }
        }

        if (remaining != PointQualityFlags.None)
        {
            throw Unmapped(remaining);
        }

        return string.Join('|', names);
    }

    private static ArgumentOutOfRangeException Unmapped<TEnum>(TEnum value) where TEnum : struct, Enum =>
        new(nameof(value), value, $"No persistence wire format is defined for {typeof(TEnum).Name}.{value}.");
}
