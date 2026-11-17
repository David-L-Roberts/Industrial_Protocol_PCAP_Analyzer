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
            S3ObjectKey: $"captures/{sessionId:D}/synthetic.pcap",
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
        Assert.Equal(sessionId, summary.SessionId);
        Assert.Equal($"captures/{sessionId:D}/synthetic.pcap", summary.S3ObjectKey);
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

    [Fact]
    public async Task RunAsync_ReportsLifecyclePhaseTransitionsInOrderAroundDataSinkOperations()
    {
        var sessionId = Guid.NewGuid();
        var pair1Id = Guid.NewGuid();
        var pair2Id = Guid.NewGuid();
        var clientIp = IPAddress.Parse("10.0.1.10");
        var serverIp = IPAddress.Parse("10.0.1.20");

        var session = new TestSession(
            Id: sessionId,
            Name: "ProgressSession",
            PcapFileName: "progress.pcap",
            S3ObjectKey: null,
            TimeoutThresholdMs: 1000,
            StoreUnmappedRegisters: false);

        var pairs = new List<DeviceEndpointPair>
        {
            new(pair1Id, sessionId, "Pair1", ProtocolType.ModbusTcp, clientIp, serverIp, null, 1),
            new(pair2Id, sessionId, "Pair2", ProtocolType.ModbusTcp, clientIp, serverIp, null, 2)
        };

        var tags = new List<TagDefinition>
        {
            new(Guid.NewGuid(), pair1Id, "Tag1", ProtocolAddress.Parse("HR:40001"), TagDataType.UInt16, 1.0, 0.0, "V", null),
            new(Guid.NewGuid(), pair1Id, "Tag2", ProtocolAddress.Parse("HR:40002"), TagDataType.UInt16, 1.0, 0.0, "A", null),
            new(Guid.NewGuid(), pair2Id, "Tag3", ProtocolAddress.Parse("HR:40001"), TagDataType.UInt16, 1.0, 0.0, "W", null)
        };

        var t0 = new DateTime(2026, 10, 26, 14, 0, 0, DateTimeKind.Utc);
        var frames = new List<DissectedFrame>
        {
            new(
                FrameNumber: 1,
                TimestampUtc: t0,
                SourceIp: clientIp,
                SourcePort: 50001,
                DestIp: serverIp,
                DestPort: 502,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03],
                DissectedFields: new Dictionary<string, string> { ["tx_id"] = "TX-1", ["fc"] = "3" })
        };

        var events = new List<string>();
        var progressSnapshots = new List<PipelineProgress>();
        var progress = new SynchronousProgress<PipelineProgress>(p =>
        {
            progressSnapshots.Add(p);
            if (p.TotalFramesProcessed == 0)
            {
                events.Add($"Phase:{p.Phase}");
            }
        });

        var frameSource = new SyntheticFrameSource(frames);
        var redEngine = new VirtualClockRedEngine(session.TimeoutThresholdMs);
        var tagEngine = new TagResolutionEngine(tags);
        var decoder = new SyntheticModbusDecoder(redEngine, tagEngine);
        var dataSink = new InMemoryDataSink(events);

        var orchestrator = new IngestionPipelineOrchestrator(frameSource, [decoder], dataSink);

        await orchestrator.RunAsync(session, pairs, tags, "progress.pcap", progress: progress);

        Assert.Equal(
            [
                new PipelineProgress(PipelinePhase.InitializingSession),
                new PipelineProgress(PipelinePhase.DissectingPackets, DevicePairCount: 2, TagCount: 3),
                new PipelineProgress(
                    PipelinePhase.DissectingPackets,
                    DevicePairCount: 2,
                    TagCount: 3,
                    TotalFramesProcessed: 1,
                    MatchedFramesProcessed: 1,
                    TotalTransactions: 0,
                    TotalRecordsPersisted: 0,
                    LatestFrameTimestampUtc: t0),
                new PipelineProgress(PipelinePhase.FinalizingSession)
            ],
            progressSnapshots);

        Assert.Equal(
            [
                "Phase:InitializingSession",
                "Sink:InitializeSession",
                "Phase:DissectingPackets",
                "Sink:WriteBatch",
                "Phase:FinalizingSession",
                "Sink:UpdateTagInitialStates",
                "Sink:CompleteSession:Completed"
            ],
            events);
    }

    [Fact]
    public async Task RunAsync_DuringDissectingPackets_EmitsPerFrameProgressWithRunningCountsAndVirtualClock()
    {
        var sessionId = Guid.NewGuid();
        var pairId = Guid.NewGuid();
        var tagId = Guid.NewGuid();
        var clientIp = IPAddress.Parse("10.0.1.10");
        var serverIp = IPAddress.Parse("10.0.1.20");
        var unmatchedIp = IPAddress.Parse("192.168.1.99");

        var pair = new DeviceEndpointPair(pairId, sessionId, "Pair1", ProtocolType.ModbusTcp, clientIp, serverIp, null, 1);
        var tag = new TagDefinition(tagId, pairId, "Bus_Volts_A", ProtocolAddress.Parse("HR:40001"), TagDataType.UInt16, 0.1, 0.0, "kV", null);

        var t0 = new DateTime(2026, 10, 26, 14, 0, 0, DateTimeKind.Utc);
        var t1 = t0.AddMilliseconds(100);
        var t2 = t0.AddMilliseconds(150);

        var frames = new List<DissectedFrame>
        {
            new(1, t0, unmatchedIp, 50000, serverIp, 502, ProtocolType.ModbusTcp, [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03]),
            new(2, t1, clientIp, 50001, serverIp, 502, ProtocolType.ModbusTcp, [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03]),
            new(3, t2, serverIp, 502, clientIp, 50001, ProtocolType.ModbusTcp, [0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x05, 0x64])
        };

        var outputsByFrame = new Dictionary<long, ProtocolDecodeOutput>
        {
            [2] = new([], [], [], []),
            [3] = new(
                Transactions:
                [
                    new ProtocolTransactionRecord(t2, sessionId, pairId, 3, TrafficDirection.ServerToClient, "1", 3, 50.0, false, TransactionErrorType.None, TransactionStatusCode.Success)
                ],
                DataPoints:
                [
                    new ExtractedDataPointRecord(t2, null, sessionId, tagId, 3, TrafficDirection.ServerToClient, 1380, 138.0, null, "0564", PointQualityFlags.Online, true)
                ],
                CommandEvents:
                [
                    new CapturedCommandEventRecord(t2, sessionId, pairId, 3, TrafficDirection.ClientToServer, ProtocolType.ModbusTcp, 6, CommandType.ModbusWriteSingleReg, ProtocolAddress.Parse("HR:40001"), null, 1, null, null, 100, [0x06, 0x00, 0x00, 0x00, 0x64])
                ],
                UnmappedRegisters:
                [
                    new ModbusUnmappedRecord(t2, sessionId, pairId, 3, TrafficDirection.ServerToClient, 1, ModbusRegisterType.Holding, 100, "270F")
                ])
        };

        foreach (bool storeUnmapped in new[] { false, true })
        {
            var session = new TestSession(
                Id: sessionId,
                Name: $"ProgressCounts_{storeUnmapped}",
                PcapFileName: "counts.pcap",
                S3ObjectKey: null,
                TimeoutThresholdMs: 1000,
                StoreUnmappedRegisters: storeUnmapped);

            var frameSnapshots = new List<PipelineProgress>();
            var progress = new SynchronousProgress<PipelineProgress>(p =>
            {
                if (p.Phase == PipelinePhase.DissectingPackets && p.TotalFramesProcessed > 0)
                {
                    frameSnapshots.Add(p);
                }
            });

            var orchestrator = new IngestionPipelineOrchestrator(
                new SyntheticFrameSource(frames),
                [new FrameMapDecoder(outputsByFrame)],
                new InMemoryDataSink());

            await orchestrator.RunAsync(session, [pair], [tag], "counts.pcap", progress: progress);

            long expectedFrame3Records = storeUnmapped ? 3 : 2;
            Assert.Equal(
                [
                    new PipelineProgress(PipelinePhase.DissectingPackets, 1, 1, 1, 0, 0, 0, t0),
                    new PipelineProgress(PipelinePhase.DissectingPackets, 1, 1, 2, 1, 0, 0, t1),
                    new PipelineProgress(PipelinePhase.DissectingPackets, 1, 1, 3, 2, 1, expectedFrame3Records, t2)
                ],
                frameSnapshots);
        }
    }

    private sealed class FrameMapDecoder(IReadOnlyDictionary<long, ProtocolDecodeOutput> outputsByFrame) : IProtocolDecoder
    {
        public ProtocolType Protocol => ProtocolType.ModbusTcp;

        public ProtocolDecodeOutput ProcessFrame(DissectedFrame frame, DeviceEndpointPair pair, TrafficDirection direction) =>
            outputsByFrame.TryGetValue(frame.FrameNumber, out var output)
                ? output
                : new ProtocolDecodeOutput([], [], [], []);

        public IReadOnlyList<ProtocolTransactionRecord> FlushExpiredTimeouts(DateTime currentVirtualTime, bool isEndOfFile) => [];
    }

    private sealed class SynchronousProgress<T>(Action<T> handler) : IProgress<T>
    {
        public void Report(T value) => handler(value);
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

    private sealed class InMemoryDataSink(List<string>? events = null) : IDataSink
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
            events?.Add("Sink:InitializeSession");
            return Task.CompletedTask;
        }

        public Task WriteBatchAsync(ProtocolDecodeOutput batch, CancellationToken ct)
        {
            Transactions.AddRange(batch.Transactions);
            DataPoints.AddRange(batch.DataPoints);
            CommandEvents.AddRange(batch.CommandEvents);
            UnmappedRegisters.AddRange(batch.UnmappedRegisters);
            events?.Add("Sink:WriteBatch");
            return Task.CompletedTask;
        }

        public Task UpdateTagInitialStatesAsync(Guid sessionId, CancellationToken ct)
        {
            InitialStatesUpdated = true;
            events?.Add("Sink:UpdateTagInitialStates");
            return Task.CompletedTask;
        }

        public Task CompleteSessionAsync(Guid sessionId, SessionStatus status, CancellationToken ct)
        {
            CompletedStatus = status;
            events?.Add($"Sink:CompleteSession:{status}");
            return Task.CompletedTask;
        }
    }
}
