using System.Diagnostics.CodeAnalysis;
using Analyzer.Core.Domain;

namespace Analyzer.Decoders.Dnp3;

internal sealed record Dnp3EndpointSnapshot(
    Guid SessionId,
    Guid DevicePairId,
    string DevicePairName,
    string ClientEndpoint,
    string ServerEndpoint,
    string ClientIp,
    int ClientPort,
    string ServerIp,
    int ServerPort,
    ushort ClientDnp3Address,
    ushort ServerDnp3Address)
{
    public static Dnp3EndpointSnapshot FromMetadata(Dnp3FrameMetadata metadata)
    {
        bool isClientToServer = metadata.Direction == TrafficDirection.ClientToServer;
        string clientIp = (isClientToServer ? metadata.Frame.SourceIp : metadata.Frame.DestIp).ToString();
        int clientPort = isClientToServer ? metadata.Frame.SourcePort : metadata.Frame.DestPort;
        string serverIp = (isClientToServer ? metadata.Frame.DestIp : metadata.Frame.SourceIp).ToString();
        int serverPort = isClientToServer ? metadata.Frame.DestPort : metadata.Frame.SourcePort;

        ushort srcAddr = metadata.SourceAddress ?? 0;
        ushort dstAddr = metadata.DestinationAddress ?? 0;
        ushort clientDnp3Addr = isClientToServer ? srcAddr : dstAddr;
        ushort serverDnp3Addr = isClientToServer ? dstAddr : srcAddr;

        return new Dnp3EndpointSnapshot(
            SessionId: metadata.Pair.SessionId,
            DevicePairId: metadata.Pair.Id,
            DevicePairName: metadata.Pair.Name,
            ClientEndpoint: metadata.Pair.ResolveClientEndpoint(),
            ServerEndpoint: metadata.Pair.ResolveServerEndpoint(),
            ClientIp: clientIp,
            ClientPort: clientPort,
            ServerIp: serverIp,
            ServerPort: serverPort,
            ClientDnp3Address: clientDnp3Addr,
            ServerDnp3Address: serverDnp3Addr);
    }
}

internal sealed record PendingConfirmContext(
    Dnp3EndpointSnapshot Endpoint,
    TraceId TraceId,
    SpanId ParentSpanId,
    int AppSeq,
    bool IsUnsolicited,
    long ResponseFrameNumber,
    DateTime ResponseTimestampUtc)
{
    public static PendingConfirmContext FromMetadata(
        Dnp3FrameMetadata metadata,
        Dnp3AppControl appControl,
        TraceId traceId,
        SpanId parentSpanId,
        bool isUnsolicited) =>
        new(
            Endpoint: Dnp3EndpointSnapshot.FromMetadata(metadata),
            TraceId: traceId,
            ParentSpanId: parentSpanId,
            AppSeq: appControl.Seq,
            IsUnsolicited: isUnsolicited,
            ResponseFrameNumber: metadata.Frame.FrameNumber,
            ResponseTimestampUtc: metadata.Frame.TimestampUtc);
}

internal sealed class Dnp3SboTracker
{
    private sealed record PendingSboSelection(
        TraceId SelectTraceId,
        SpanId SelectSpanId,
        DateTime RequestTimestampUtc,
        DateTime AnchorUtc,
        bool IsSelectCompleted);

    private readonly int _sboWindowMs;
    private readonly int _requestTimeoutThresholdMs;
    private readonly Dictionary<(Guid DevicePairId, ProtocolAddress TargetAddress), PendingSboSelection> _pendingByKey = new();

    public Dnp3SboTracker(int sboWindowMs, int requestTimeoutThresholdMs)
    {
        if (sboWindowMs <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sboWindowMs), "SBO window must be positive.");
        }

        if (requestTimeoutThresholdMs <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(requestTimeoutThresholdMs), "Request timeout threshold must be positive.");
        }

        _sboWindowMs = sboWindowMs;
        _requestTimeoutThresholdMs = requestTimeoutThresholdMs;
    }

    public void RegisterSelect(
        Guid devicePairId,
        IReadOnlyList<ProtocolAddress> targetAddresses,
        TraceId selectTraceId,
        SpanId selectSpanId,
        DateTime requestTimestampUtc)
    {
        for (int i = 0; i < targetAddresses.Count; i++)
        {
            _pendingByKey[(devicePairId, targetAddresses[i])] = new PendingSboSelection(
                SelectTraceId: selectTraceId,
                SelectSpanId: selectSpanId,
                RequestTimestampUtc: requestTimestampUtc,
                AnchorUtc: requestTimestampUtc,
                IsSelectCompleted: false);
        }
    }

    public void OnSelectResponse(
        Guid devicePairId,
        IReadOnlyList<ProtocolAddress> targetAddresses,
        SpanId selectSpanId,
        DateTime responseTimestampUtc,
        bool isIinError)
    {
        for (int i = 0; i < targetAddresses.Count; i++)
        {
            var key = (devicePairId, targetAddresses[i]);
            if (!_pendingByKey.TryGetValue(key, out var entry) || entry.SelectSpanId != selectSpanId)
            {
                continue;
            }

            if (isIinError)
            {
                _pendingByKey.Remove(key);
            }
            else
            {
                _pendingByKey[key] = entry with
                {
                    AnchorUtc = responseTimestampUtc,
                    IsSelectCompleted = true
                };
            }
        }
    }

    public bool TryConsumeForOperate(
        Guid devicePairId,
        ProtocolAddress targetAddress,
        DateTime operateTimestampUtc,
        out TraceId selectTraceId,
        out SpanId selectSpanId)
    {
        if (!_pendingByKey.Remove((devicePairId, targetAddress), out var entry))
        {
            selectTraceId = default;
            selectSpanId = default;
            return false;
        }

        if (IsExpired(entry, operateTimestampUtc))
        {
            selectTraceId = default;
            selectSpanId = default;
            return false;
        }

        selectTraceId = entry.SelectTraceId;
        selectSpanId = entry.SelectSpanId;
        return true;
    }

    public void PruneExpired(
        DateTime currentVirtualTime,
        bool isEndOfFile,
        IReadOnlyList<TraceSpanRecord> flushedTimeoutSpans)
    {
        if (_pendingByKey.Count == 0)
        {
            return;
        }

        if (isEndOfFile)
        {
            _pendingByKey.Clear();
            return;
        }

        HashSet<SpanId>? flushedSpanIds = null;
        if (flushedTimeoutSpans.Count > 0)
        {
            flushedSpanIds = new HashSet<SpanId>(flushedTimeoutSpans.Count);
            for (int i = 0; i < flushedTimeoutSpans.Count; i++)
            {
                flushedSpanIds.Add(flushedTimeoutSpans[i].SpanId);
            }
        }

        List<(Guid DevicePairId, ProtocolAddress TargetAddress)>? keysToRemove = null;
        foreach (var kvp in _pendingByKey)
        {
            bool timedOutInFlush = flushedSpanIds is not null && flushedSpanIds.Contains(kvp.Value.SelectSpanId);
            if (timedOutInFlush || IsExpired(kvp.Value, currentVirtualTime))
            {
                keysToRemove ??= [];
                keysToRemove.Add(kvp.Key);
            }
        }

        if (keysToRemove is not null)
        {
            for (int i = 0; i < keysToRemove.Count; i++)
            {
                _pendingByKey.Remove(keysToRemove[i]);
            }
        }
    }

    private bool IsExpired(PendingSboSelection entry, DateTime virtualTimeUtc)
    {
        if (!entry.IsSelectCompleted &&
            (virtualTimeUtc - entry.RequestTimestampUtc).TotalMilliseconds > _requestTimeoutThresholdMs)
        {
            return true;
        }

        return (virtualTimeUtc - entry.AnchorUtc).TotalMilliseconds > _sboWindowMs;
    }
}

internal sealed class Dnp3ConfirmTracker
{
    private readonly int _timeoutThresholdMs;
    private readonly Dictionary<(Guid DevicePairId, int AppSeq, bool IsUnsolicited), PendingConfirmContext> _pendingByKey = new();
    private readonly PriorityQueue<PendingConfirmContext, DateTime> _priorityQueue = new();

    public Dnp3ConfirmTracker(int timeoutThresholdMs)
    {
        if (timeoutThresholdMs <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(timeoutThresholdMs), "Timeout threshold must be positive.");
        }

        _timeoutThresholdMs = timeoutThresholdMs;
    }

    public void Register(PendingConfirmContext pending)
    {
        _pendingByKey[(pending.Endpoint.DevicePairId, pending.AppSeq, pending.IsUnsolicited)] = pending;
        _priorityQueue.Enqueue(pending, pending.ResponseTimestampUtc);
    }

    public bool TryConsume(
        Guid devicePairId,
        int appSeq,
        bool isUnsolicited,
        [NotNullWhen(true)] out PendingConfirmContext? pending)
    {
        if (_pendingByKey.Remove((devicePairId, appSeq, isUnsolicited), out pending))
        {
            return true;
        }

        return _pendingByKey.Remove((devicePairId, appSeq, !isUnsolicited), out pending);
    }

    public List<TraceSpanRecord> FlushExpired(DateTime currentVirtualTime, bool isEndOfFile)
    {
        var timeoutSpans = new List<TraceSpanRecord>();

        while (_priorityQueue.TryPeek(out var candidate, out var responseTimestampUtc))
        {
            var key = (candidate.Endpoint.DevicePairId, candidate.AppSeq, candidate.IsUnsolicited);
            if (!_pendingByKey.TryGetValue(key, out var active) || !ReferenceEquals(active, candidate))
            {
                _priorityQueue.Dequeue();
                continue;
            }

            double elapsedMs = (currentVirtualTime - responseTimestampUtc).TotalMilliseconds;
            if (!isEndOfFile && elapsedMs <= _timeoutThresholdMs)
            {
                break;
            }

            _priorityQueue.Dequeue();
            _pendingByKey.Remove(key);

            bool isMidStreamTimeout = elapsedMs > _timeoutThresholdMs;
            timeoutSpans.Add(Dnp3SpanFactory.CreateConfirmTimeoutSpan(
                candidate,
                currentVirtualTime,
                _timeoutThresholdMs,
                isMidStreamTimeout));
        }

        return timeoutSpans;
    }
}
