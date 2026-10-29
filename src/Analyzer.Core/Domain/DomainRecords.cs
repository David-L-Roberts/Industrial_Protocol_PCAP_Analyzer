using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace Analyzer.Core.Domain;

public enum TrafficDirection
{
    ClientToServer,
    ServerToClient
}

public enum ProtocolType
{
    ModbusTcp,
    Dnp3
}

public enum SessionStatus
{
    Processing,
    Completed,
    Failed
}

public enum TagDataType
{
    Bool,
    Int16,
    UInt16,
    Int32,
    Float32Be,
    Float32Swapped
}

public enum TransactionErrorType
{
    None,
    Timeout,
    TimeoutAtEof,
    Exception,
    Malformed
}

public enum TransactionStatusCode
{
    Success,
    Timeout,
    TimeoutAtEof,
    Malformed,
    ModbusEx01,
    ModbusEx02,
    ModbusEx03,
    ModbusEx04,
    ModbusEx05,
    ModbusEx06,
    ModbusEx08,
    ModbusEx0A,
    ModbusEx0B,
    ModbusExceptionUnknown,
    Dnp3IinFuncNotSupported,
    Dnp3IinObjectUnknown,
    Dnp3IinParamErr,
    Dnp3IinEventBufferOverflow,
    Dnp3IinAlreadyExecuting,
    Dnp3IinConfigCorrupt
}

[Flags]
public enum PointQualityFlags
{
    None = 0,
    Online = 1 << 0,
    Restart = 1 << 1,
    CommLost = 1 << 2,
    RemoteForced = 1 << 3,
    LocalForced = 1 << 4,
    ChatterFilter = 1 << 5,
    OverRange = 1 << 6,
    ReferenceErr = 1 << 7
}

public enum CommandType
{
    ModbusWriteSingleCoil,
    ModbusWriteSingleReg,
    ModbusWriteMultiCoils,
    ModbusWriteMultiRegs,
    Dnp3CrobSelect,
    Dnp3CrobOperate,
    Dnp3DirectOperate
}

public enum Dnp3ControlAction
{
    PulseOn,
    PulseOff,
    LatchOn,
    LatchOff,
    Trip,
    Close
}

public enum ModbusRegisterType
{
    Holding,
    Input,
    Coil,
    DiscreteInput
}

public readonly struct ProtocolAddress : IEquatable<ProtocolAddress>
{
    public string Value { get; }

    public ProtocolAddress(string value)
    {
        if (!TryValidate(value, out var normalized))
        {
            throw new ArgumentException(
                $"Invalid protocol address '{value}'. Expected '<Prefix>:<Target>' format (e.g., 'HR:40001' or 'G30V02:Idx0').",
                nameof(value));
        }

        Value = normalized;
    }

    public static ProtocolAddress Parse(string value) => new(value);

    public static bool TryParse([NotNullWhen(true)] string? value, out ProtocolAddress result)
    {
        if (TryValidate(value, out var normalized))
        {
            result = new ProtocolAddress(normalized);
            return true;
        }

        result = default;
        return false;
    }

    private static bool TryValidate([NotNullWhen(true)] string? value, [NotNullWhen(true)] out string? normalized)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            normalized = null;
            return false;
        }

        var trimmed = value.Trim();
        int colonIndex = trimmed.IndexOf(':');
        if (colonIndex <= 0 || colonIndex == trimmed.Length - 1)
        {
            normalized = null;
            return false;
        }

        normalized = trimmed;
        return true;
    }

    public bool Equals(ProtocolAddress other) =>
        string.Equals(Value, other.Value, StringComparison.OrdinalIgnoreCase);

    public override bool Equals(object? obj) =>
        obj is ProtocolAddress other && Equals(other);

    public override int GetHashCode() =>
        Value is null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(Value);

    public static bool operator ==(ProtocolAddress left, ProtocolAddress right) => left.Equals(right);

    public static bool operator !=(ProtocolAddress left, ProtocolAddress right) => !left.Equals(right);

    public override string ToString() => Value ?? string.Empty;
}

public record TestSession(
    Guid Id,
    string Name,
    string PcapFileName,
    string? S3ObjectKey,
    int TimeoutThresholdMs = 2000,
    bool StoreUnmappedRegisters = false
);

public record DeviceEndpointPair(
    Guid Id,
    Guid SessionId,
    string Name,
    ProtocolType Protocol,
    IPAddress ClientIp,
    IPAddress ServerIp,
    int? ClientProtocolAddressId,
    int? ServerProtocolAddressId
);

public record TagDefinition(
    Guid Id,
    Guid DevicePairId,
    string TagName,
    ProtocolAddress ProtocolAddress,
    TagDataType DataType,
    double ScaleMultiplier,
    double ScaleOffset,
    string? EngineeringUnits,
    string? Description
)
{
    public double ComputeScaledValue(double unscaledValue) => (unscaledValue * ScaleMultiplier) + ScaleOffset;
}

public record TagInitialState(
    Guid TagId,
    double? InitialUnscaledNumericValue,
    double? InitialScaledNumericValue,
    bool? InitialBooleanValue,
    string InitialRawHex
);

public record DissectedFrame(
    long FrameNumber,
    DateTime TimestampUtc,
    IPAddress SourceIp,
    int SourcePort,
    IPAddress DestIp,
    int DestPort,
    ProtocolType ProtocolName,
    byte[] RawApplicationPayload,
    IReadOnlyDictionary<string, string>? DissectedFields = null
);

public record ProtocolTransactionRecord(
    DateTime Timestamp,
    Guid SessionId,
    Guid DevicePairId,
    long FrameNumber,
    TrafficDirection Direction,
    string TransactionId,
    short FunctionCode,
    double? DurationMs,
    bool IsError,
    TransactionErrorType ErrorType,
    TransactionStatusCode StatusCode
);

public record ExtractedDataPointRecord(
    DateTime PacketTimestamp,
    DateTime? EventTimestamp,
    Guid SessionId,
    Guid TagId,
    long FrameNumber,
    TrafficDirection Direction,
    double? UnscaledNumericValue,
    double? ScaledNumericValue,
    bool? BooleanValue,
    string RawHex,
    PointQualityFlags QualityFlags,
    bool IsValueChange
);

public record CapturedCommandEventRecord(
    DateTime Timestamp,
    Guid SessionId,
    Guid DevicePairId,
    long FrameNumber,
    TrafficDirection Direction,
    ProtocolType Protocol,
    short FunctionCode,
    CommandType CommandType,
    ProtocolAddress TargetAddress,
    Dnp3ControlAction? ControlAction,
    short? CommandCount,
    long? PulseOnMs,
    long? PulseOffMs,
    double? UnscaledCommandValue,
    byte[] RawPduBytes
);

public record ModbusUnmappedRecord(
    DateTime Timestamp,
    Guid SessionId,
    Guid DevicePairId,
    long FrameNumber,
    TrafficDirection Direction,
    short UnitId,
    ModbusRegisterType RegisterType,
    int RegisterOffset,
    string RawValueHex
);

public record ProtocolDecodeOutput(
    IReadOnlyList<ProtocolTransactionRecord> Transactions,
    IReadOnlyList<ExtractedDataPointRecord> DataPoints,
    IReadOnlyList<CapturedCommandEventRecord> CommandEvents,
    IReadOnlyList<ModbusUnmappedRecord> UnmappedRegisters
);

public record PipelineExecutionSummary(
    long TotalFramesProcessed,
    long MatchedFramesProcessed,
    long TotalTransactions,
    long SuccessTransactions,
    long ErrorTransactions,
    long TimeoutTransactions,
    long ExceptionTransactions,
    long DataPointsPersisted,
    long CommandEventsPersisted,
    long UnmappedRegistersPersisted
);
