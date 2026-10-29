using Analyzer.Core.Domain;

namespace Analyzer.Infrastructure.Persistence;

/// <summary>
/// Persistence seam: serializes strongly typed domain enums into the string literals stored in TimescaleDB
/// (see <c>sql/001_init_timescaledb.sql</c>).
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
        TagDataType.Float32Be => "FLOAT32_BE",
        TagDataType.Float32Swapped => "FLOAT32_SWAPPED",
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
