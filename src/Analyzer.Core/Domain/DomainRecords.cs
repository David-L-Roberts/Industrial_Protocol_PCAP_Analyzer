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
    string ClientIp,
    string ServerIp,
    int? ClientProtocolAddressId,
    int? ServerProtocolAddressId
);

public record TagDefinition(
    Guid Id,
    Guid DevicePairId,
    string TagName,
    string ProtocolAddress,
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
    string SourceIp,
    int SourcePort,
    string DestIp,
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
    string? QualityFlags,
    bool IsValueChange
);

public record CapturedCommandEventRecord(
    DateTime Timestamp,
    Guid SessionId,
    Guid DevicePairId,
    long FrameNumber,
    TrafficDirection Direction,
    string Protocol,
    short FunctionCode,
    string CommandType,
    string TargetAddress,
    string? ControlAction,
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
    string RegisterType,
    int RegisterOffset,
    string RawValueHex
);

public record ProtocolDecodeOutput(
    IReadOnlyList<ProtocolTransactionRecord> Transactions,
    IReadOnlyList<ExtractedDataPointRecord> DataPoints,
    IReadOnlyList<CapturedCommandEventRecord> CommandEvents,
    IReadOnlyList<ModbusUnmappedRecord> UnmappedRegisters
);
