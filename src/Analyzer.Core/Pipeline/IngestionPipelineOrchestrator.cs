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
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(devicePairs);
        ArgumentNullException.ThrowIfNull(tags);
        ArgumentException.ThrowIfNullOrWhiteSpace(pcapFilePath);

        try
        {
            await _dataSink.InitializeSessionAsync(session, devicePairs, tags, ct);

            var transactions = new List<ProtocolTransactionRecord>();
            var dataPoints = new List<ExtractedDataPointRecord>();
            var commandEvents = new List<CapturedCommandEventRecord>();
            var unmappedRegisters = new List<ModbusUnmappedRecord>();

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

            await foreach (var frame in _frameSource.ReadFramesAsync(pcapFilePath, ct))
            {
                totalFrames++;
                lastVirtualTime = frame.TimestampUtc;

                if (!TryMatchDevicePair(frame, devicePairs, out var matchedPair, out var direction))
                {
                    continue;
                }

                matchedFrames++;

                if (!_decodersByProtocol.TryGetValue(matchedPair.Protocol, out var decoder))
                {
                    continue;
                }

                foreach (var registeredDecoder in _decodersByProtocol.Values)
                {
                    var expiredTimeouts = registeredDecoder.FlushExpiredTimeouts(frame.TimestampUtc, isEndOfFile: false);
                    if (expiredTimeouts.Count > 0)
                    {
                        transactions.AddRange(expiredTimeouts);
                        TallyTransactions(expiredTimeouts);
                    }
                }

                var output = decoder.ProcessFrame(frame, matchedPair, direction);
                if (output.Transactions.Count > 0)
                {
                    transactions.AddRange(output.Transactions);
                    TallyTransactions(output.Transactions);
                }

                if (output.DataPoints.Count > 0)
                {
                    dataPoints.AddRange(output.DataPoints);
                    dataPointsPersisted += output.DataPoints.Count;
                }

                if (output.CommandEvents.Count > 0)
                {
                    commandEvents.AddRange(output.CommandEvents);
                    commandEventsPersisted += output.CommandEvents.Count;
                }

                if (session.StoreUnmappedRegisters && output.UnmappedRegisters.Count > 0)
                {
                    unmappedRegisters.AddRange(output.UnmappedRegisters);
                    unmappedRegistersPersisted += output.UnmappedRegisters.Count;
                }

                int totalBuffered = transactions.Count + dataPoints.Count + commandEvents.Count + unmappedRegisters.Count;
                if (totalBuffered >= _batchSize)
                {
                    await FlushBatchAsync(transactions, dataPoints, commandEvents, unmappedRegisters, ct);
                }
            }

            foreach (var decoder in _decodersByProtocol.Values)
            {
                var eofTimeouts = decoder.FlushExpiredTimeouts(lastVirtualTime, isEndOfFile: true);
                if (eofTimeouts.Count > 0)
                {
                    transactions.AddRange(eofTimeouts);
                    TallyTransactions(eofTimeouts);
                }
            }

            if (transactions.Count > 0 || dataPoints.Count > 0 || commandEvents.Count > 0 || unmappedRegisters.Count > 0)
            {
                await FlushBatchAsync(transactions, dataPoints, commandEvents, unmappedRegisters, ct);
            }

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
                UnmappedRegistersPersisted: unmappedRegistersPersisted);
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

    private async Task FlushBatchAsync(
        List<ProtocolTransactionRecord> transactions,
        List<ExtractedDataPointRecord> dataPoints,
        List<CapturedCommandEventRecord> commandEvents,
        List<ModbusUnmappedRecord> unmappedRegisters,
        CancellationToken ct)
    {
        var batch = new ProtocolDecodeOutput(
            Transactions: transactions.ToArray(),
            DataPoints: dataPoints.ToArray(),
            CommandEvents: commandEvents.ToArray(),
            UnmappedRegisters: unmappedRegisters.ToArray());

        await _dataSink.WriteBatchAsync(batch, ct);

        transactions.Clear();
        dataPoints.Clear();
        commandEvents.Clear();
        unmappedRegisters.Clear();
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
