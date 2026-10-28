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
        object? RequestContext);

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

    public void RegisterRequest<TContext>(
        Guid sessionId,
        Guid devicePairId,
        long frameNumber,
        DateTime timestampUtc,
        string transactionId,
        short functionCode,
        TContext? requestContext,
        string? correlationKey = null)
    {
        var effectiveKey = correlationKey ?? transactionId;
        var req = new PendingRequest(
            SessionId: sessionId,
            DevicePairId: devicePairId,
            FrameNumber: frameNumber,
            TimestampUtc: timestampUtc,
            TransactionId: transactionId,
            CorrelationKey: effectiveKey,
            FunctionCode: functionCode,
            RequestContext: requestContext);

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
        string? correlationKey = null) =>
        RegisterRequest<object>(sessionId, devicePairId, frameNumber, timestampUtc, transactionId, functionCode, null, correlationKey);

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
        string? correlationKey = null)
    {
        var key = (devicePairId, correlationKey ?? transactionId);
        if (!_pendingByKey.Remove(key, out var pending))
        {
            transaction = null;
            requestContext = default;
            return false;
        }

        var durationMs = (responseTimestampUtc - pending.TimestampUtc).TotalMilliseconds;
        requestContext = pending.RequestContext is TContext typed ? typed : default;

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
            StatusCode: statusCode);

        return true;
    }

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
            correlationKey);

    public IReadOnlyList<ProtocolTransactionRecord> FlushExpiredTimeouts(DateTime currentVirtualTime, bool isEndOfFile)
    {
        var results = new List<ProtocolTransactionRecord>();

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

            results.Add(new ProtocolTransactionRecord(
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
                StatusCode: statusCode));
        }

        return results;
    }
}
