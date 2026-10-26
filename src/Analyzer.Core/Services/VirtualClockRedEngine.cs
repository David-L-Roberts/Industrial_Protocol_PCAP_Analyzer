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
        short FunctionCode,
        object? RequestContext);

    private readonly int _timeoutThresholdMs;
    private readonly Dictionary<(Guid DevicePairId, string TransactionId), PendingRequest> _pendingByKey = new();
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
        TContext? requestContext)
    {
        var req = new PendingRequest(
            SessionId: sessionId,
            DevicePairId: devicePairId,
            FrameNumber: frameNumber,
            TimestampUtc: timestampUtc,
            TransactionId: transactionId,
            FunctionCode: functionCode,
            RequestContext: requestContext);

        _pendingByKey[(devicePairId, transactionId)] = req;
        _priorityQueue.Enqueue(req, timestampUtc);
    }

    public void RegisterRequest(
        Guid sessionId,
        Guid devicePairId,
        long frameNumber,
        DateTime timestampUtc,
        string transactionId,
        short functionCode) =>
        RegisterRequest<object>(sessionId, devicePairId, frameNumber, timestampUtc, transactionId, functionCode, null);

    public bool TryCompleteResponse<TContext>(
        Guid devicePairId,
        string transactionId,
        long responseFrameNumber,
        DateTime responseTimestampUtc,
        short responseFunctionCode,
        bool isException,
        string statusCode,
        [NotNullWhen(true)] out ProtocolTransactionRecord? transaction,
        out TContext? requestContext)
    {
        var key = (devicePairId, transactionId);
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
            ErrorType: isException ? "EXCEPTION" : "NONE",
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
        string statusCode,
        [NotNullWhen(true)] out ProtocolTransactionRecord? transaction) =>
        TryCompleteResponse<object>(
            devicePairId,
            transactionId,
            responseFrameNumber,
            responseTimestampUtc,
            responseFunctionCode,
            isException,
            statusCode,
            out transaction,
            out _);

    public IReadOnlyList<ProtocolTransactionRecord> FlushExpiredTimeouts(DateTime currentVirtualTime, bool isEndOfFile)
    {
        var results = new List<ProtocolTransactionRecord>();

        while (_priorityQueue.TryPeek(out var candidate, out var reqTimestamp))
        {
            var key = (candidate.DevicePairId, candidate.TransactionId);

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

            var errorType = elapsedMs > _timeoutThresholdMs ? "TIMEOUT" : "TIMEOUT_AT_EOF";
            var durationMs = errorType == "TIMEOUT" ? _timeoutThresholdMs : Math.Max(0.0, elapsedMs);

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
                StatusCode: errorType));
        }

        return results;
    }
}
