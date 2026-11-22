using System.Buffers.Binary;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;

namespace Analyzer.Core.Pipeline;

public class IngestionPipelineOrchestrator
{
    public const int DefaultBatchSize = 5000;

    private readonly IFrameSource _frameSource;
    private readonly Dictionary<ProtocolType, IProtocolDecoder> _decodersByProtocol;
    private readonly IDataSink _dataSink;
    private readonly int _batchSize;

    public IngestionPipelineOrchestrator(
        IFrameSource frameSource,
        IEnumerable<IProtocolDecoder> decoders,
        IDataSink dataSink,
        int batchSize = DefaultBatchSize)
    {
        ArgumentNullException.ThrowIfNull(frameSource);
        ArgumentNullException.ThrowIfNull(decoders);
        ArgumentNullException.ThrowIfNull(dataSink);
        if (batchSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(batchSize), "Batch size must be positive.");
        }

        _frameSource = frameSource;
        _dataSink = dataSink;
        _batchSize = batchSize;
        _decodersByProtocol = new Dictionary<ProtocolType, IProtocolDecoder>();

        foreach (var decoder in decoders)
        {
            _decodersByProtocol[decoder.Protocol] = decoder;
        }
    }

    public async Task<PipelineExecutionSummary> RunAsync(
        TestSession session,
        IReadOnlyList<DeviceEndpointPair> devicePairs,
        IReadOnlyList<TagDefinition> tags,
        string pcapFilePath,
        CancellationToken ct = default,
        IProgress<PipelineProgress>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(devicePairs);
        ArgumentNullException.ThrowIfNull(tags);
        ArgumentException.ThrowIfNullOrWhiteSpace(pcapFilePath);

        try
        {
            progress?.Report(new PipelineProgress(PipelinePhase.InitializingSession));
            await _dataSink.InitializeSessionAsync(session, devicePairs, tags, ct);
            progress?.Report(new PipelineProgress(
                PipelinePhase.DissectingPackets,
                DevicePairCount: devicePairs.Count,
                TagCount: tags.Count));

            var buffer = new BatchBuffer();

            DateTime lastVirtualTime = DateTime.UnixEpoch;
            long totalFrames = 0;
            long matchedFrames = 0;
            long totalTransactions = 0;
            long successTransactions = 0;
            long errorTransactions = 0;
            long timeoutTransactions = 0;
            long exceptionTransactions = 0;
            long dataPointsPersisted = 0;
            long commandEventsPersisted = 0;
            long unmappedRegistersPersisted = 0;
            long traceSpansPersisted = 0;

            void TallyTransactions(IReadOnlyList<ProtocolTransactionRecord> txList)
            {
                for (int i = 0; i < txList.Count; i++)
                {
                    var tx = txList[i];
                    totalTransactions++;
                    if (tx.IsError)
                    {
                        errorTransactions++;
                    }
                    else
                    {
                        successTransactions++;
                    }

                    if (tx.ErrorType is TransactionErrorType.Timeout or TransactionErrorType.TimeoutAtEof)
                    {
                        timeoutTransactions++;
                    }
                    else if (tx.ErrorType == TransactionErrorType.Exception)
                    {
                        exceptionTransactions++;
                    }
                }
            }

            void AccumulateTraceSpans(IReadOnlyList<TraceSpanRecord> spans)
            {
                if (session.StoreTraceSpans && spans.Count > 0)
                {
                    buffer.TraceSpans.AddRange(spans);
                    traceSpansPersisted += spans.Count;
                }
            }

            void AccumulateTimeouts(TimeoutFlushOutput flushed)
            {
                if (flushed.Transactions.Count > 0)
                {
                    buffer.Transactions.AddRange(flushed.Transactions);
                    TallyTransactions(flushed.Transactions);
                }

                AccumulateTraceSpans(flushed.TraceSpans);
            }

            await foreach (var frame in _frameSource.ReadFramesAsync(pcapFilePath, ct))
            {
                totalFrames++;
                lastVirtualTime = frame.TimestampUtc;

                if (TryMatchDevicePair(frame, devicePairs, out var matchedPair, out var direction))
                {
                    matchedFrames++;

                    if (_decodersByProtocol.TryGetValue(matchedPair.Protocol, out var decoder))
                    {
                        foreach (var registeredDecoder in _decodersByProtocol.Values)
                        {
                            AccumulateTimeouts(registeredDecoder.FlushExpiredTimeouts(frame.TimestampUtc, isEndOfFile: false));
                        }

                        var output = decoder.ProcessFrame(frame, matchedPair, direction);
                        if (output.Transactions.Count > 0)
                        {
                            buffer.Transactions.AddRange(output.Transactions);
                            TallyTransactions(output.Transactions);
                        }

                        if (output.DataPoints.Count > 0)
                        {
                            buffer.DataPoints.AddRange(output.DataPoints);
                            dataPointsPersisted += output.DataPoints.Count;
                        }

                        if (output.CommandEvents.Count > 0)
                        {
                            buffer.CommandEvents.AddRange(output.CommandEvents);
                            commandEventsPersisted += output.CommandEvents.Count;
                        }

                        if (session.StoreUnmappedRegisters && output.UnmappedRegisters.Count > 0)
                        {
                            buffer.UnmappedRegisters.AddRange(output.UnmappedRegisters);
                            unmappedRegistersPersisted += output.UnmappedRegisters.Count;
                        }

                        AccumulateTraceSpans(output.TraceSpans);

                        if (buffer.TotalCount >= _batchSize)
                        {
                            await FlushBatchAsync(buffer, ct);
                        }
                    }
                }

                progress?.Report(new PipelineProgress(
                    Phase: PipelinePhase.DissectingPackets,
                    DevicePairCount: devicePairs.Count,
                    TagCount: tags.Count,
                    TotalFramesProcessed: totalFrames,
                    MatchedFramesProcessed: matchedFrames,
                    TotalTransactions: totalTransactions,
                    TotalRecordsPersisted: dataPointsPersisted + commandEventsPersisted + unmappedRegistersPersisted + traceSpansPersisted,
                    LatestFrameTimestampUtc: lastVirtualTime));
            }

            foreach (var decoder in _decodersByProtocol.Values)
            {
                AccumulateTimeouts(decoder.FlushExpiredTimeouts(lastVirtualTime, isEndOfFile: true));
            }

            if (buffer.TotalCount > 0)
            {
                await FlushBatchAsync(buffer, ct);
            }

            progress?.Report(new PipelineProgress(PipelinePhase.FinalizingSession));
            await _dataSink.UpdateTagInitialStatesAsync(session.Id, ct);
            await _dataSink.CompleteSessionAsync(session.Id, SessionStatus.Completed, ct);

            return new PipelineExecutionSummary(
                TotalFramesProcessed: totalFrames,
                MatchedFramesProcessed: matchedFrames,
                TotalTransactions: totalTransactions,
                SuccessTransactions: successTransactions,
                ErrorTransactions: errorTransactions,
                TimeoutTransactions: timeoutTransactions,
                ExceptionTransactions: exceptionTransactions,
                DataPointsPersisted: dataPointsPersisted,
                CommandEventsPersisted: commandEventsPersisted,
                UnmappedRegistersPersisted: unmappedRegistersPersisted,
                SessionId: session.Id,
                S3ObjectKey: session.S3ObjectKey,
                TraceSpansPersisted: traceSpansPersisted);
        }
        catch (Exception)
        {
            try
            {
                await _dataSink.CompleteSessionAsync(session.Id, SessionStatus.Failed, CancellationToken.None);
            }
            catch
            {
                // Suppress secondary exception to preserve original exception
            }

            throw;
        }
    }

    private async Task FlushBatchAsync(BatchBuffer buffer, CancellationToken ct)
    {
        await _dataSink.WriteBatchAsync(buffer.DrainToOutput(), ct);
    }

    private sealed class BatchBuffer
    {
        public List<ProtocolTransactionRecord> Transactions { get; } = [];
        public List<ExtractedDataPointRecord> DataPoints { get; } = [];
        public List<CapturedCommandEventRecord> CommandEvents { get; } = [];
        public List<ModbusUnmappedRecord> UnmappedRegisters { get; } = [];
        public List<TraceSpanRecord> TraceSpans { get; } = [];

        public int TotalCount =>
            Transactions.Count +
            DataPoints.Count +
            CommandEvents.Count +
            UnmappedRegisters.Count +
            TraceSpans.Count;

        public ProtocolDecodeOutput DrainToOutput()
        {
            var batch = new ProtocolDecodeOutput(
                Transactions: Transactions.ToArray(),
                DataPoints: DataPoints.ToArray(),
                CommandEvents: CommandEvents.ToArray(),
                UnmappedRegisters: UnmappedRegisters.ToArray(),
                TraceSpans: TraceSpans.ToArray());

            Transactions.Clear();
            DataPoints.Clear();
            CommandEvents.Clear();
            UnmappedRegisters.Clear();
            TraceSpans.Clear();
            return batch;
        }
    }

    private static bool TryMatchDevicePair(
        DissectedFrame frame,
        IReadOnlyList<DeviceEndpointPair> pairs,
        out DeviceEndpointPair matchedPair,
        out TrafficDirection direction)
    {
        foreach (var pair in pairs)
        {
            if (pair.Protocol != frame.ProtocolName)
            {
                continue;
            }

            TrafficDirection candidateDirection;
            if (frame.SourceIp.Equals(pair.ClientIp) && frame.DestIp.Equals(pair.ServerIp))
            {
                candidateDirection = TrafficDirection.ClientToServer;
            }
            else if (frame.SourceIp.Equals(pair.ServerIp) && frame.DestIp.Equals(pair.ClientIp))
            {
                candidateDirection = TrafficDirection.ServerToClient;
            }
            else
            {
                continue;
            }

            if (!MatchesProtocolAddresses(frame, pair, candidateDirection))
            {
                continue;
            }

            matchedPair = pair;
            direction = candidateDirection;
            return true;
        }

        matchedPair = default!;
        direction = default;
        return false;
    }

    private static bool MatchesProtocolAddresses(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction)
    {
        TryExtractProtocolAddresses(frame, direction, frame.ProtocolName, out var clientAddr, out var serverAddr);

        if (pair.ClientProtocolAddressId.HasValue &&
            pair.ClientProtocolAddressId.Value != clientAddr)
        {
            return false;
        }

        if (pair.ServerProtocolAddressId.HasValue &&
            pair.ServerProtocolAddressId.Value != serverAddr)
        {
            return false;
        }

        return true;
    }

    private static void TryExtractProtocolAddresses(
        DissectedFrame frame,
        TrafficDirection direction,
        ProtocolType protocol,
        out int? clientAddress,
        out int? serverAddress)
    {
        clientAddress = null;
        serverAddress = null;

        if (frame.DissectedFields is not null)
        {
            if (TryGetIntField(frame.DissectedFields, ["client_protocol_address_id", "client_address"], out var explicitClient))
            {
                clientAddress = explicitClient;
            }

            if (TryGetIntField(frame.DissectedFields, ["server_protocol_address_id", "server_address", "unit_id", "modbus.unit_id", "mbtcp.unit_id"], out var explicitServer))
            {
                serverAddress = explicitServer;
            }

            if (TryGetIntField(frame.DissectedFields, ["dnp3.src", "source_address", "src_addr"], out var srcAddr) &&
                TryGetIntField(frame.DissectedFields, ["dnp3.dst", "destination_address", "dst_addr"], out var dstAddr))
            {
                AssignDirectionalAddresses(direction, srcAddr, dstAddr, ref clientAddress, ref serverAddress);
            }
        }

        var payload = frame.RawApplicationPayload;
        if (payload is null || payload.Length == 0)
        {
            return;
        }

        if (protocol == ProtocolType.ModbusTcp)
        {
            if (serverAddress is null && payload.Length >= 7)
            {
                serverAddress = payload[6];
            }
        }
        else if (protocol == ProtocolType.Dnp3)
        {
            if (payload.Length >= 8 && payload[0] == 0x05 && payload[1] == 0x64)
            {
                int dst = BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(4, 2));
                int src = BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(6, 2));
                AssignDirectionalAddresses(direction, src, dst, ref clientAddress, ref serverAddress);
            }
        }
    }

    private static void AssignDirectionalAddresses(
        TrafficDirection direction,
        int sourceAddress,
        int destinationAddress,
        ref int? clientAddress,
        ref int? serverAddress)
    {
        if (direction == TrafficDirection.ClientToServer)
        {
            clientAddress ??= sourceAddress;
            serverAddress ??= destinationAddress;
        }
        else
        {
            serverAddress ??= sourceAddress;
            clientAddress ??= destinationAddress;
        }
    }

    private static bool TryGetIntField(
        IReadOnlyDictionary<string, string> fields,
        ReadOnlySpan<string> keys,
        out int value)
    {
        foreach (var key in keys)
        {
            if (fields.TryGetValue(key, out var raw) && int.TryParse(raw, out value))
            {
                return true;
            }
        }

        value = default;
        return false;
    }
}
