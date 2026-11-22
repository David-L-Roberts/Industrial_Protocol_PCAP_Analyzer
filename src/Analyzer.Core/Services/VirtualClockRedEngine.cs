using System.Diagnostics.CodeAnalysis;
using Analyzer.Core.Domain;

namespace Analyzer.Core.Services;

public class VirtualClockRedEngine
{
    private sealed record PendingRequest(
        Guid SessionId,
        Guid DevicePairId,
        long FrameNumber,
        DateTime TimestampUtc,
        string TransactionId,
        string CorrelationKey,
        short FunctionCode,
        object? RequestContext,
        PendingSpanContext? SpanContext);

    private readonly int _timeoutThresholdMs;
    private readonly Dictionary<(Guid DevicePairId, string CorrelationKey), PendingRequest> _pendingByKey = new();
    private readonly PriorityQueue<PendingRequest, DateTime> _priorityQueue = new();

    public VirtualClockRedEngine(int timeoutThresholdMs)
    {
        if (timeoutThresholdMs <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(timeoutThresholdMs), "Timeout threshold must be positive.");
        }

        _timeoutThresholdMs = timeoutThresholdMs;
    }

    public int TimeoutThresholdMs => _timeoutThresholdMs;

    public void RegisterRequest<TContext>(
        Guid sessionId,
        Guid devicePairId,
        long frameNumber,
        DateTime timestampUtc,
        string transactionId,
        short functionCode,
        TContext? requestContext,
        string? correlationKey = null,
        PendingSpanContext? spanContext = null)
    {
        var effectiveKey = correlationKey ?? transactionId;
        var resolvedSpanContext = spanContext is null
            ? null
            : spanContext with
            {
                RequestTimestampUtc = spanContext.RequestTimestampUtc == default ? timestampUtc : spanContext.RequestTimestampUtc,
                RequestFrameNumber = spanContext.RequestFrameNumber ?? frameNumber
            };

        var req = new PendingRequest(
            SessionId: sessionId,
            DevicePairId: devicePairId,
            FrameNumber: frameNumber,
            TimestampUtc: timestampUtc,
            TransactionId: transactionId,
            CorrelationKey: effectiveKey,
            FunctionCode: functionCode,
            RequestContext: requestContext,
            SpanContext: resolvedSpanContext);

        _pendingByKey[(devicePairId, effectiveKey)] = req;
        _priorityQueue.Enqueue(req, timestampUtc);
    }

    public void RegisterRequest(
        Guid sessionId,
        Guid devicePairId,
        long frameNumber,
        DateTime timestampUtc,
        string transactionId,
        short functionCode,
        string? correlationKey = null,
        PendingSpanContext? spanContext = null) =>
        RegisterRequest<object>(sessionId, devicePairId, frameNumber, timestampUtc, transactionId, functionCode, null, correlationKey, spanContext);

    public bool TryCompleteResponse<TContext>(
        Guid devicePairId,
        string transactionId,
        long responseFrameNumber,
        DateTime responseTimestampUtc,
        short responseFunctionCode,
        bool isException,
        TransactionStatusCode statusCode,
        [NotNullWhen(true)] out ProtocolTransactionRecord? transaction,
        out TContext? requestContext,
        out PendingSpanContext? spanContext,
        string? correlationKey = null)
    {
        var key = (devicePairId, correlationKey ?? transactionId);
        if (!_pendingByKey.Remove(key, out var pending))
        {
            transaction = null;
            requestContext = default;
            spanContext = null;
            return false;
        }

        var durationMs = (responseTimestampUtc - pending.TimestampUtc).TotalMilliseconds;
        requestContext = pending.RequestContext is TContext typed ? typed : default;
        spanContext = pending.SpanContext;

        transaction = new ProtocolTransactionRecord(
            Timestamp: responseTimestampUtc,
            SessionId: pending.SessionId,
            DevicePairId: devicePairId,
            FrameNumber: responseFrameNumber,
            Direction: TrafficDirection.ServerToClient,
            TransactionId: transactionId,
            FunctionCode: responseFunctionCode,
            DurationMs: durationMs,
            IsError: isException,
            ErrorType: isException ? TransactionErrorType.Exception : TransactionErrorType.None,
            StatusCode: statusCode,
            TraceId: pending.SpanContext?.TraceId,
            SpanId: pending.SpanContext?.SpanId);

        return true;
    }

    public bool TryCompleteResponse<TContext>(
        Guid devicePairId,
        string transactionId,
        long responseFrameNumber,
        DateTime responseTimestampUtc,
        short responseFunctionCode,
        bool isException,
        TransactionStatusCode statusCode,
        [NotNullWhen(true)] out ProtocolTransactionRecord? transaction,
        out TContext? requestContext,
        string? correlationKey = null) =>
        TryCompleteResponse(
            devicePairId,
            transactionId,
            responseFrameNumber,
            responseTimestampUtc,
            responseFunctionCode,
            isException,
            statusCode,
            out transaction,
            out requestContext,
            out _,
            correlationKey);

    public bool TryCompleteResponse(
        Guid devicePairId,
        string transactionId,
        long responseFrameNumber,
        DateTime responseTimestampUtc,
        short responseFunctionCode,
        bool isException,
        TransactionStatusCode statusCode,
        [NotNullWhen(true)] out ProtocolTransactionRecord? transaction,
        out PendingSpanContext? spanContext,
        string? correlationKey = null) =>
        TryCompleteResponse<object>(
            devicePairId,
            transactionId,
            responseFrameNumber,
            responseTimestampUtc,
            responseFunctionCode,
            isException,
            statusCode,
            out transaction,
            out _,
            out spanContext,
            correlationKey);

    public bool TryCompleteResponse(
        Guid devicePairId,
        string transactionId,
        long responseFrameNumber,
        DateTime responseTimestampUtc,
        short responseFunctionCode,
        bool isException,
        TransactionStatusCode statusCode,
        [NotNullWhen(true)] out ProtocolTransactionRecord? transaction,
        string? correlationKey = null) =>
        TryCompleteResponse<object>(
            devicePairId,
            transactionId,
            responseFrameNumber,
            responseTimestampUtc,
            responseFunctionCode,
            isException,
            statusCode,
            out transaction,
            out _,
            out _,
            correlationKey);

    public TimeoutFlushOutput FlushExpiredTimeouts(DateTime currentVirtualTime, bool isEndOfFile)
    {
        var transactions = new List<ProtocolTransactionRecord>();
        var traceSpans = new List<TraceSpanRecord>();

        while (_priorityQueue.TryPeek(out var candidate, out var reqTimestamp))
        {
            var key = (candidate.DevicePairId, candidate.CorrelationKey);

            // Discard stale queue entries that were already completed or superseded
            if (!_pendingByKey.TryGetValue(key, out var active) || !ReferenceEquals(active, candidate))
            {
                _priorityQueue.Dequeue();
                continue;
            }

            var elapsedMs = (currentVirtualTime - reqTimestamp).TotalMilliseconds;
            if (!isEndOfFile && elapsedMs <= _timeoutThresholdMs)
            {
                break;
            }

            _priorityQueue.Dequeue();
            _pendingByKey.Remove(key);

            bool isMidStreamTimeout = elapsedMs > _timeoutThresholdMs;
            var errorType = isMidStreamTimeout ? TransactionErrorType.Timeout : TransactionErrorType.TimeoutAtEof;
            var statusCode = isMidStreamTimeout ? TransactionStatusCode.Timeout : TransactionStatusCode.TimeoutAtEof;
            var durationMs = isMidStreamTimeout ? _timeoutThresholdMs : Math.Max(0.0, elapsedMs);

            transactions.Add(new ProtocolTransactionRecord(
                Timestamp: candidate.TimestampUtc,
                SessionId: candidate.SessionId,
                DevicePairId: candidate.DevicePairId,
                FrameNumber: candidate.FrameNumber,
                Direction: TrafficDirection.ClientToServer,
                TransactionId: candidate.TransactionId,
                FunctionCode: candidate.FunctionCode,
                DurationMs: durationMs,
                IsError: true,
                ErrorType: errorType,
                StatusCode: statusCode,
                TraceId: candidate.SpanContext?.TraceId,
                SpanId: candidate.SpanContext?.SpanId));

            if (candidate.SpanContext is { } spanCtx)
            {
                DateTime startTimeUtc = candidate.TimestampUtc;
                DateTime endTimeUtc = isMidStreamTimeout
                    ? startTimeUtc.AddMilliseconds(_timeoutThresholdMs)
                    : (currentVirtualTime >= startTimeUtc ? currentVirtualTime : startTimeUtc);

                traceSpans.Add(spanCtx.CreateTimeoutSpan(
                    sessionId: candidate.SessionId,
                    devicePairId: candidate.DevicePairId,
                    requestFrameNumber: candidate.FrameNumber,
                    startTimeUtc: startTimeUtc,
                    endTimeUtc: endTimeUtc,
                    durationMs: durationMs,
                    transactionId: candidate.TransactionId,
                    functionCode: candidate.FunctionCode,
                    isMidStreamTimeout: isMidStreamTimeout));
            }
        }

        return new TimeoutFlushOutput(transactions, traceSpans);
    }
}
