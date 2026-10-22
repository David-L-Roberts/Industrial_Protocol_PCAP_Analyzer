using Analyzer.Core.Domain;

namespace Analyzer.Core.Interfaces;

public interface IFrameSource
{
    IAsyncEnumerable<DissectedFrame> ReadFramesAsync(string pcapFilePath, CancellationToken ct = default);
}

public interface IProtocolDecoder
{
    string Protocol { get; }
    ProtocolDecodeOutput ProcessFrame(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction);
    IReadOnlyList<ProtocolTransactionRecord> FlushExpiredTimeouts(DateTime currentVirtualTime, bool isEndOfFile);
}

public interface IDnp3ObjectGroupHandler
{
    ushort Group { get; }
    void ExtractObjects(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction,
        ushort variation,
        ReadOnlySpan<byte> objectData,
        ICollection<ExtractedDataPointRecord> dataPointsOut,
        ICollection<CapturedCommandEventRecord> commandsOut);
}

public interface IDataSink
{
    Task InitializeSessionAsync(TestSession session, IEnumerable<DeviceEndpointPair> pairs, IEnumerable<TagDefinition> tags, CancellationToken ct);
    Task WriteBatchAsync(ProtocolDecodeOutput batch, CancellationToken ct);
    Task UpdateTagInitialStatesAsync(Guid sessionId, CancellationToken ct);
    Task CompleteSessionAsync(Guid sessionId, string status, CancellationToken ct);
}

