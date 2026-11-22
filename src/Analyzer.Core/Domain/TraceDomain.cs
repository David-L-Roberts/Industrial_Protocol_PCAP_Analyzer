using System.Diagnostics.CodeAnalysis;

namespace Analyzer.Core.Domain;

internal static class W3cHexIdValidator
{
    public static bool TryNormalizeNonZeroHex(
        [NotNullWhen(true)] string? value,
        int expectedLength,
        [NotNullWhen(true)] out string? normalized)
    {
        if (string.IsNullOrEmpty(value) || value.Length != expectedLength)
        {
            normalized = null;
            return false;
        }

        bool hasNonZero = false;
        foreach (char c in value)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                normalized = null;
                return false;
            }

            if (c != '0')
            {
                hasNonZero = true;
            }
        }

        if (!hasNonZero)
        {
            normalized = null;
            return false;
        }

        normalized = value.ToLowerInvariant();
        return true;
    }
}

/// <summary>
/// Validated W3C 32-character lowercase hexadecimal (128-bit) non-zero trace identifier.
/// </summary>
public readonly struct TraceId : IEquatable<TraceId>
{
    public const int HexLength = 32;

    public string Value { get; }

    public TraceId(string value)
    {
        if (!W3cHexIdValidator.TryNormalizeNonZeroHex(value, HexLength, out var normalized))
        {
            throw new ArgumentException(
                $"Invalid TraceId '{value}'. Expected {HexLength} non-zero hexadecimal characters.",
                nameof(value));
        }

        Value = normalized;
    }

    public static TraceId Parse(string value) => new(value);

    public static bool TryParse([NotNullWhen(true)] string? value, out TraceId result)
    {
        if (W3cHexIdValidator.TryNormalizeNonZeroHex(value, HexLength, out var normalized))
        {
            result = new TraceId(normalized);
            return true;
        }

        result = default;
        return false;
    }

    public bool Equals(TraceId other) =>
        string.Equals(Value, other.Value, StringComparison.Ordinal);

    public override bool Equals(object? obj) =>
        obj is TraceId other && Equals(other);

    public override int GetHashCode() =>
        Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    public static bool operator ==(TraceId left, TraceId right) => left.Equals(right);

    public static bool operator !=(TraceId left, TraceId right) => !left.Equals(right);

    public override string ToString() => Value ?? string.Empty;
}

/// <summary>
/// Validated W3C 16-character lowercase hexadecimal (64-bit) non-zero span identifier.
/// </summary>
public readonly struct SpanId : IEquatable<SpanId>
{
    public const int HexLength = 16;

    public string Value { get; }

    public SpanId(string value)
    {
        if (!W3cHexIdValidator.TryNormalizeNonZeroHex(value, HexLength, out var normalized))
        {
            throw new ArgumentException(
                $"Invalid SpanId '{value}'. Expected {HexLength} non-zero hexadecimal characters.",
                nameof(value));
        }

        Value = normalized;
    }

    public static SpanId Parse(string value) => new(value);

    public static bool TryParse([NotNullWhen(true)] string? value, out SpanId result)
    {
        if (W3cHexIdValidator.TryNormalizeNonZeroHex(value, HexLength, out var normalized))
        {
            result = new SpanId(normalized);
            return true;
        }

        result = default;
        return false;
    }

    public bool Equals(SpanId other) =>
        string.Equals(Value, other.Value, StringComparison.Ordinal);

    public override bool Equals(object? obj) =>
        obj is SpanId other && Equals(other);

    public override int GetHashCode() =>
        Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);

    public static bool operator ==(SpanId left, SpanId right) => left.Equals(right);

    public static bool operator !=(SpanId left, SpanId right) => !left.Equals(right);

    public override string ToString() => Value ?? string.Empty;
}

public enum SpanKind
{
    Client,
    Server,
    Producer,
    Consumer,
    Internal
}

public enum SpanStatusCode
{
    Unset,
    Ok,
    Error
}

public enum SpanOriginKind
{
    RequestResponse,
    Timeout,
    TimeoutAtEof,
    Malformed,
    Unsolicited,
    DirectNoAck,
    Confirm,
    ConfirmTimeout,
    OrphanResponse
}

public enum SpanCorrelationRole
{
    Transaction,
    SboSelect,
    SboOperate,
    UnsolicitedResponse,
    Confirm,
    ConfirmTimeout,
    DirectNoAck,
    Malformed,
    OrphanResponse
}

public enum SpanEventKind
{
    RequestSent,
    ResponseReceived,
    TimeoutExpired,
    ProtocolException,
    CommandIssued,
    TagValueChanged,
    ConfirmSent,
    ConfirmTimeoutExpired
}

public record SpanEventRecord(
    DateTime TimestampUtc,
    SpanEventKind Kind,
    string Name,
    IReadOnlyDictionary<string, object?> Fields
);

public record TraceSpanRecord(
    DateTime StartTimeUtc,
    DateTime EndTimeUtc,
    double DurationMs,
    Guid SessionId,
    Guid DevicePairId,
    TraceId TraceId,
    SpanId SpanId,
    SpanId? ParentSpanId,
    string ServiceName,
    string OperationName,
    SpanKind SpanKind,
    SpanOriginKind OriginKind,
    SpanStatusCode StatusCode,
    string? StatusMessage,
    ProtocolType Protocol,
    string ClientEndpoint,
    string ServerEndpoint,
    TrafficDirection Direction,
    long? RequestFrameNumber,
    long? ResponseFrameNumber,
    string? TransactionId,
    short? FunctionCode,
    IReadOnlyDictionary<string, object?> Attributes,
    IReadOnlyList<SpanEventRecord> Events
);

public record PendingSpanContext(
    TraceId TraceId,
    SpanId SpanId,
    SpanId? ParentSpanId,
    string ServiceName,
    string OperationName,
    ProtocolType Protocol,
    string ClientEndpoint,
    string ServerEndpoint,
    IReadOnlyDictionary<string, object?> Attributes,
    IReadOnlyList<SpanEventRecord> Events,
    SpanKind SpanKind = SpanKind.Client,
    TrafficDirection Direction = TrafficDirection.ClientToServer,
    DateTime RequestTimestampUtc = default,
    long? RequestFrameNumber = null
)
{
    public TraceSpanRecord CreateTimeoutSpan(
        Guid sessionId,
        Guid devicePairId,
        long requestFrameNumber,
        DateTime startTimeUtc,
        DateTime endTimeUtc,
        double durationMs,
        string transactionId,
        short functionCode,
        bool isMidStreamTimeout)
    {
        var originKind = isMidStreamTimeout ? SpanOriginKind.Timeout : SpanOriginKind.TimeoutAtEof;
        string statusMessage = isMidStreamTimeout ? "TIMEOUT" : "TIMEOUT_AT_EOF";

        var events = new List<SpanEventRecord>(Events.Count + 1);
        events.AddRange(Events);
        events.Add(new SpanEventRecord(
            TimestampUtc: endTimeUtc,
            Kind: SpanEventKind.TimeoutExpired,
            Name: string.Empty,
            Fields: new Dictionary<string, object?>
            {
                ["timeout_ms"] = durationMs,
                ["reason"] = originKind
            }));

        return new TraceSpanRecord(
            StartTimeUtc: startTimeUtc,
            EndTimeUtc: endTimeUtc,
            DurationMs: durationMs,
            SessionId: sessionId,
            DevicePairId: devicePairId,
            TraceId: TraceId,
            SpanId: SpanId,
            ParentSpanId: ParentSpanId,
            ServiceName: ServiceName,
            OperationName: OperationName,
            SpanKind: SpanKind,
            OriginKind: originKind,
            StatusCode: SpanStatusCode.Error,
            StatusMessage: statusMessage,
            Protocol: Protocol,
            ClientEndpoint: ClientEndpoint,
            ServerEndpoint: ServerEndpoint,
            Direction: Direction,
            RequestFrameNumber: requestFrameNumber,
            ResponseFrameNumber: null,
            TransactionId: transactionId,
            FunctionCode: functionCode,
            Attributes: Attributes,
            Events: events);
    }
}

public record TimeoutFlushOutput(
    IReadOnlyList<ProtocolTransactionRecord> Transactions,
    IReadOnlyList<TraceSpanRecord> TraceSpans)
{
    public static TimeoutFlushOutput Empty { get; } = new([], []);
}
