using System.Net;
using System.Runtime.CompilerServices;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Pipeline;
using Analyzer.Core.Services;

namespace Analyzer.Core.Tests;

public class IngestionPipelineOrchestratorTests
{
    [Fact]
    public async Task RunAsync_ProcessesMatchedFramesSweepsVirtualClockTimeoutsAndFlushesEofToDataSink()
    {
        var sessionId = Guid.NewGuid();
        var pairId = Guid.NewGuid();
        var tagId = Guid.NewGuid();
        var clientIp = IPAddress.Parse("10.0.1.10");
        var serverIp = IPAddress.Parse("10.0.1.20");
        var unmatchedIp = IPAddress.Parse("192.168.1.99");

        var session = new TestSession(
            Id: sessionId,
            Name: "SAT_Feeder1",
            PcapFileName: "synthetic.pcap",
            S3ObjectKey: null,
            TimeoutThresholdMs: 1000,
            StoreUnmappedRegisters: false);

        var pair = new DeviceEndpointPair(
            Id: pairId,
            SessionId: sessionId,
            Name: "RTAC_to_Relay",
            Protocol: ProtocolType.ModbusTcp,
            ClientIp: clientIp,
            ServerIp: serverIp,
            ClientProtocolAddressId: null,
            ServerProtocolAddressId: 1);

        var tag = new TagDefinition(
            Id: tagId,
            DevicePairId: pairId,
            TagName: "Bus_Volts_A",
            ProtocolAddress: ProtocolAddress.Parse("HR:40001"),
            DataType: TagDataType.UInt16,
            ScaleMultiplier: 0.1,
            ScaleOffset: 0.0,
            EngineeringUnits: "kV",
            Description: "Bus Voltage");

        var t0 = new DateTime(2026, 10, 26, 14, 0, 0, DateTimeKind.Utc);

        var frames = new List<DissectedFrame>
        {
            // Frame 1: Unmatched IP -> should be ignored completely
            new(
                FrameNumber: 1,
                TimestampUtc: t0,
                SourceIp: unmatchedIp,
                SourcePort: 50000,
                DestIp: serverIp,
                DestPort: 502,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03]),

            // Frame 2: Matched IPs but wrong Modbus Unit ID (Unit ID 2 != 1) -> should be ignored
            new(
                FrameNumber: 2,
                TimestampUtc: t0.AddMilliseconds(10),
                SourceIp: clientIp,
                SourcePort: 50001,
                DestIp: serverIp,
                DestPort: 502,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x99, 0x00, 0x00, 0x00, 0x06, 0x02, 0x03]),

            // Frame 3: ClientToServer request TX-1 at T + 100ms (will never be answered -> expires mid-stream)
            new(
                FrameNumber: 3,
                TimestampUtc: t0.AddMilliseconds(100),
                SourceIp: clientIp,
                SourcePort: 50001,
                DestIp: serverIp,
                DestPort: 502,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03],
                DissectedFields: new Dictionary<string, string> { ["tx_id"] = "TX-1", ["fc"] = "3" }),

            // Frame 4: ClientToServer request TX-2 at T + 1200ms (triggers timeout of TX-1 since 1200 - 100 = 1100 > 1000ms)
            new(
                FrameNumber: 4,
                TimestampUtc: t0.AddMilliseconds(1200),
                SourceIp: clientIp,
                SourcePort: 50001,
                DestIp: serverIp,
                DestPort: 502,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03],
                DissectedFields: new Dictionary<string, string> { ["tx_id"] = "TX-2", ["fc"] = "3" }),

            // Frame 5: ServerToClient response for TX-2 at T + 1250ms (duration = 50ms, emits tag HR:40001 = 1380 -> 138.0 kV)
            new(
                FrameNumber: 5,
                TimestampUtc: t0.AddMilliseconds(1250),
                SourceIp: serverIp,
                SourcePort: 502,
                DestIp: clientIp,
                DestPort: 50001,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x05, 0x64],
                DissectedFields: new Dictionary<string, string>
                {
                    ["tx_id"] = "TX-2",
                    ["fc"] = "3",
                    ["address"] = "HR:40001",
                    ["value"] = "1380",
                    ["raw_hex"] = "0564"
                }),

            // Frame 6: ClientToServer request TX-3 at T + 1300ms (remains unanswered at EOF -> TIMEOUT_AT_EOF)
            new(
                FrameNumber: 6,
                TimestampUtc: t0.AddMilliseconds(1300),
                SourceIp: clientIp,
                SourcePort: 50001,
                DestIp: serverIp,
                DestPort: 502,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x03, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03],
                DissectedFields: new Dictionary<string, string> { ["tx_id"] = "TX-3", ["fc"] = "3" })
        };

        var frameSource = new SyntheticFrameSource(frames);
        var redEngine = new VirtualClockRedEngine(session.TimeoutThresholdMs);
        var tagEngine = new TagResolutionEngine([tag]);
        var decoder = new SyntheticModbusDecoder(redEngine, tagEngine);
        var dataSink = new InMemoryDataSink();

        var orchestrator = new IngestionPipelineOrchestrator(frameSource, [decoder], dataSink);

        var summary = await orchestrator.RunAsync(session, [pair], [tag], "synthetic.pcap");

        Assert.Equal(sessionId, dataSink.InitializedSession?.Id);
        Assert.True(dataSink.InitialStatesUpdated);
        Assert.Equal(SessionStatus.Completed, dataSink.CompletedStatus);

        Assert.NotNull(summary);
        Assert.Equal(6, summary.TotalFramesProcessed);
        Assert.Equal(4, summary.MatchedFramesProcessed);
        Assert.Equal(3, summary.TotalTransactions);
        Assert.Equal(1, summary.SuccessTransactions);
        Assert.Equal(2, summary.ErrorTransactions);
        Assert.Equal(2, summary.TimeoutTransactions);
        Assert.Equal(0, summary.ExceptionTransactions);
        Assert.Equal(1, summary.DataPointsPersisted);
        Assert.Equal(0, summary.CommandEventsPersisted);
        Assert.Equal(0, summary.UnmappedRegistersPersisted);

        // Verify 3 RED transactions in exact order:
        // 1. TX-1 mid-stream TIMEOUT
        // 2. TX-2 ServerToClient SUCCESS (duration 50ms)
        // 3. TX-3 TIMEOUT_AT_EOF (duration 1300 - 1300 = 0ms)
        Assert.Equal(3, dataSink.Transactions.Count);

        var tx1 = dataSink.Transactions[0];
        Assert.Equal("TX-1", tx1.TransactionId);
        Assert.Equal(TrafficDirection.ClientToServer, tx1.Direction);
        Assert.True(tx1.IsError);
        Assert.Equal(TransactionErrorType.Timeout, tx1.ErrorType);
        Assert.Equal(1000.0, tx1.DurationMs!.Value, precision: 5);

        var tx2 = dataSink.Transactions[1];
        Assert.Equal("TX-2", tx2.TransactionId);
        Assert.Equal(TrafficDirection.ServerToClient, tx2.Direction);
        Assert.False(tx2.IsError);
        Assert.Equal(TransactionErrorType.None, tx2.ErrorType);
        Assert.Equal(TransactionStatusCode.Success, tx2.StatusCode);
        Assert.Equal(50.0, tx2.DurationMs!.Value, precision: 5);

        var tx3 = dataSink.Transactions[2];
        Assert.Equal("TX-3", tx3.TransactionId);
        Assert.Equal(TrafficDirection.ClientToServer, tx3.Direction);
        Assert.True(tx3.IsError);
        Assert.Equal(TransactionErrorType.TimeoutAtEof, tx3.ErrorType);

        // Verify decoded data point and T0 initial state
        var dp = Assert.Single(dataSink.DataPoints);
        Assert.Equal(tagId, dp.TagId);
        Assert.Equal(1380.0, dp.UnscaledNumericValue);
        Assert.Equal(138.0, dp.ScaledNumericValue!.Value, precision: 5);
        Assert.True(dp.IsValueChange);
        Assert.True(tagEngine.GetInitialStates().ContainsKey(tagId));
    }

    [Fact]
    public async Task RunAsync_OnUnhandledException_MarksSessionFailedAndRethrows()
    {
        var sessionId = Guid.NewGuid();
        var session = new TestSession(
            Id: sessionId,
            Name: "FaultySession",
            PcapFileName: "faulty.pcap",
            S3ObjectKey: null);

        var dataSink = new InMemoryDataSink();
        var failingFrameSource = new ThrowingFrameSource();
        var orchestrator = new IngestionPipelineOrchestrator(failingFrameSource, [], dataSink);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            orchestrator.RunAsync(session, [], [], "faulty.pcap"));

        Assert.Equal("Frame read exploded", ex.Message);
        Assert.Equal(SessionStatus.Failed, dataSink.CompletedStatus);
    }

    private sealed class ThrowingFrameSource : IFrameSource
    {
        public async IAsyncEnumerable<DissectedFrame> ReadFramesAsync(
            string pcapFilePath,
            [EnumeratorCancellation] CancellationToken ct = default)
        {
            await Task.Yield();
            if (!string.IsNullOrEmpty(pcapFilePath))
            {
                throw new InvalidOperationException("Frame read exploded");
            }

            yield break;
        }
    }

    private sealed class SyntheticFrameSource(IReadOnlyList<DissectedFrame> frames) : IFrameSource
    {
        public async IAsyncEnumerable<DissectedFrame> ReadFramesAsync(
            string pcapFilePath,
            [EnumeratorCancellation] CancellationToken ct = default)
        {
            foreach (var frame in frames)
            {
                ct.ThrowIfCancellationRequested();
                await Task.Yield();
                yield return frame;
            }
        }
    }

    private sealed class SyntheticModbusDecoder(
        VirtualClockRedEngine redEngine,
        TagResolutionEngine tagEngine) : IProtocolDecoder
    {
        public ProtocolType Protocol => ProtocolType.ModbusTcp;

        public ProtocolDecodeOutput ProcessFrame(
            DissectedFrame frame,
            DeviceEndpointPair pair,
            TrafficDirection direction)
        {
            var transactions = new List<ProtocolTransactionRecord>();
            var dataPoints = new List<ExtractedDataPointRecord>();

            if (frame.DissectedFields is null)
            {
                return new ProtocolDecodeOutput(transactions, dataPoints, [], []);
            }

            var txId = frame.DissectedFields["tx_id"];
            var fc = short.Parse(frame.DissectedFields["fc"]);

            if (direction == TrafficDirection.ClientToServer)
            {
                redEngine.RegisterRequest(
                    pair.SessionId,
                    pair.Id,
                    frame.FrameNumber,
                    frame.TimestampUtc,
                    txId,
                    fc);
            }
            else
            {
                if (redEngine.TryCompleteResponse(
                        pair.Id,
                        txId,
                        frame.FrameNumber,
                        frame.TimestampUtc,
                        fc,
                        isException: false,
                        statusCode: TransactionStatusCode.Success,
                        out var tx))
                {
                    transactions.Add(tx);
                }

                if (frame.DissectedFields.TryGetValue("address", out var addressStr) &&
                    ProtocolAddress.TryParse(addressStr, out var address) &&
                    frame.DissectedFields.TryGetValue("value", out var valStr) &&
                    double.TryParse(valStr, out var unscaled))
                {
                    var rawHex = frame.DissectedFields.GetValueOrDefault("raw_hex", "0000");
                    if (tagEngine.TryResolveAndProject(
                            pair.SessionId,
                            pair.Id,
                            address,
                            frame.TimestampUtc,
                            eventTimestamp: null,
                            frame.FrameNumber,
                            direction,
                            unscaledNumericValue: unscaled,
                            booleanValue: null,
                            rawHex: rawHex,
                            qualityFlags: PointQualityFlags.Online,
                            out var dp))
                    {
                        dataPoints.Add(dp);
                    }
                }
            }

            return new ProtocolDecodeOutput(transactions, dataPoints, [], []);
        }

        public IReadOnlyList<ProtocolTransactionRecord> FlushExpiredTimeouts(DateTime currentVirtualTime, bool isEndOfFile) =>
            redEngine.FlushExpiredTimeouts(currentVirtualTime, isEndOfFile);
    }

    private sealed class InMemoryDataSink : IDataSink
    {
        public TestSession? InitializedSession { get; private set; }
        public List<ProtocolTransactionRecord> Transactions { get; } = [];
        public List<ExtractedDataPointRecord> DataPoints { get; } = [];
        public List<CapturedCommandEventRecord> CommandEvents { get; } = [];
        public List<ModbusUnmappedRecord> UnmappedRegisters { get; } = [];
        public bool InitialStatesUpdated { get; private set; }
        public SessionStatus? CompletedStatus { get; private set; }

        public Task InitializeSessionAsync(
            TestSession session,
            IEnumerable<DeviceEndpointPair> pairs,
            IEnumerable<TagDefinition> tags,
            CancellationToken ct)
        {
            InitializedSession = session;
            return Task.CompletedTask;
        }

        public Task WriteBatchAsync(ProtocolDecodeOutput batch, CancellationToken ct)
        {
            Transactions.AddRange(batch.Transactions);
            DataPoints.AddRange(batch.DataPoints);
            CommandEvents.AddRange(batch.CommandEvents);
            UnmappedRegisters.AddRange(batch.UnmappedRegisters);
            return Task.CompletedTask;
        }

        public Task UpdateTagInitialStatesAsync(Guid sessionId, CancellationToken ct)
        {
            InitialStatesUpdated = true;
            return Task.CompletedTask;
        }

        public Task CompleteSessionAsync(Guid sessionId, SessionStatus status, CancellationToken ct)
        {
            CompletedStatus = status;
            return Task.CompletedTask;
        }
    }
}
