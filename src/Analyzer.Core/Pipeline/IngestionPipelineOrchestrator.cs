using System.Buffers.Binary;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;

namespace Analyzer.Core.Pipeline;

public class IngestionPipelineOrchestrator
{
    public const int DefaultBatchSize = 5000;

    private readonly IFrameSource _frameSource;
    private readonly Dictionary<string, IProtocolDecoder> _decodersByProtocol;
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
        _decodersByProtocol = new Dictionary<string, IProtocolDecoder>(StringComparer.OrdinalIgnoreCase);

        foreach (var decoder in decoders)
        {
            _decodersByProtocol[NormalizeProtocol(decoder.Protocol)] = decoder;
        }
    }

    public async Task RunAsync(
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

        await _dataSink.InitializeSessionAsync(session, devicePairs, tags, ct);

        var transactions = new List<ProtocolTransactionRecord>();
        var dataPoints = new List<ExtractedDataPointRecord>();
        var commandEvents = new List<CapturedCommandEventRecord>();
        var unmappedRegisters = new List<ModbusUnmappedRecord>();

        DateTime lastVirtualTime = DateTime.UnixEpoch;

        await foreach (var frame in _frameSource.ReadFramesAsync(pcapFilePath, ct))
        {
            lastVirtualTime = frame.TimestampUtc;

            if (!TryMatchDevicePair(frame, devicePairs, out var matchedPair, out var direction))
            {
                continue;
            }

            if (!_decodersByProtocol.TryGetValue(NormalizeProtocol(matchedPair.Protocol), out var decoder))
            {
                continue;
            }

            foreach (var registeredDecoder in _decodersByProtocol.Values)
            {
                var expiredTimeouts = registeredDecoder.FlushExpiredTimeouts(frame.TimestampUtc, isEndOfFile: false);
                if (expiredTimeouts.Count > 0)
                {
                    transactions.AddRange(expiredTimeouts);
                }
            }

            var output = decoder.ProcessFrame(frame, matchedPair, direction);
            if (output.Transactions.Count > 0)
            {
                transactions.AddRange(output.Transactions);
            }

            if (output.DataPoints.Count > 0)
            {
                dataPoints.AddRange(output.DataPoints);
            }

            if (output.CommandEvents.Count > 0)
            {
                commandEvents.AddRange(output.CommandEvents);
            }

            if (session.StoreUnmappedRegisters && output.UnmappedRegisters.Count > 0)
            {
                unmappedRegisters.AddRange(output.UnmappedRegisters);
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
            }
        }

        if (transactions.Count > 0 || dataPoints.Count > 0 || commandEvents.Count > 0 || unmappedRegisters.Count > 0)
        {
            await FlushBatchAsync(transactions, dataPoints, commandEvents, unmappedRegisters, ct);
        }

        await _dataSink.UpdateTagInitialStatesAsync(session.Id, ct);
        await _dataSink.CompleteSessionAsync(session.Id, "COMPLETED", ct);
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
        var normalizedFrameProtocol = NormalizeProtocol(frame.ProtocolName);

        foreach (var pair in pairs)
        {
            if (!string.Equals(NormalizeProtocol(pair.Protocol), normalizedFrameProtocol, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            TrafficDirection candidateDirection;
            if (string.Equals(frame.SourceIp, pair.ClientIp, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(frame.DestIp, pair.ServerIp, StringComparison.OrdinalIgnoreCase))
            {
                candidateDirection = TrafficDirection.ClientToServer;
            }
            else if (string.Equals(frame.SourceIp, pair.ServerIp, StringComparison.OrdinalIgnoreCase) &&
                     string.Equals(frame.DestIp, pair.ClientIp, StringComparison.OrdinalIgnoreCase))
            {
                candidateDirection = TrafficDirection.ServerToClient;
            }
            else
            {
                continue;
            }

            if (!MatchesProtocolAddresses(frame, pair, candidateDirection, normalizedFrameProtocol))
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
        TrafficDirection direction,
        string normalizedProtocol)
    {
        TryExtractProtocolAddresses(frame, direction, normalizedProtocol, out var clientAddr, out var serverAddr);

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
        string normalizedProtocol,
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

        if (string.Equals(normalizedProtocol, "ModbusTCP", StringComparison.OrdinalIgnoreCase))
        {
            if (serverAddress is null && payload.Length >= 7)
            {
                serverAddress = payload[6];
            }
        }
        else if (string.Equals(normalizedProtocol, "DNP3", StringComparison.OrdinalIgnoreCase))
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

    private static string NormalizeProtocol(string protocol)
    {
        if (string.IsNullOrWhiteSpace(protocol))
        {
            return string.Empty;
        }

        var trimmed = protocol.Trim();
        if (trimmed.Equals("modbus", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("mbtcp", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("modbustcp", StringComparison.OrdinalIgnoreCase))
        {
            return "ModbusTCP";
        }

        if (trimmed.Equals("dnp3", StringComparison.OrdinalIgnoreCase))
        {
            return "DNP3";
        }

        return trimmed;
    }
}

