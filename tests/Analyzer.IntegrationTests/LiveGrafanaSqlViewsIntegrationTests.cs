using System.Net;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;
using Analyzer.Infrastructure.Persistence;
using Analyzer.IntegrationTests.Attributes;
using Analyzer.IntegrationTests.Configuration;
using Analyzer.IntegrationTests.Persistence;
using Npgsql;

namespace Analyzer.IntegrationTests;

[Collection(TimescaleDbCollection.Name)]
[IntegrationTrait]
public class LiveGrafanaSqlViewsIntegrationTests : IAsyncLifetime
{
    private readonly IntegrationTestConfig _config = IntegrationTestConfig.Load();
    private readonly List<Guid> _trackedSessionIds = [];
    private NpgsqlDataSource _dataSource = default!;

    public Task InitializeAsync()
    {
        _dataSource = NpgsqlDataSource.Create(_config.TimescaleConnectionString);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        try
        {
            await TimescaleTestDatabaseCleaner.CleanupSessionsIfEnabledAsync(
                _dataSource,
                _trackedSessionIds,
                _config.KeepTestData);
        }
        finally
        {
            await _dataSource.DisposeAsync();
        }
    }

    [IntegrationFact]
    public async Task GrafanaViews_ProjectStatusCodesAndRouteServerToClientUnsolicitedEdges()
    {
        var sessionId = Guid.NewGuid();
        _trackedSessionIds.Add(sessionId);

        var pairId = Guid.NewGuid();
        var baseTime = new DateTime(2026, 11, 22, 9, 0, 0, DateTimeKind.Utc);

        await using var writer = new NpgsqlPostgresWriter(_dataSource);
        var sink = new TimescaleDbBatchSink(writer);

        var session = new TestSession(
            Id: sessionId,
            Name: "Grafana_Views_Direction_Test",
            PcapFileName: "direction_test.pcap",
            S3ObjectKey: null,
            TimeoutThresholdMs: 2000,
            StoreUnmappedRegisters: false,
            StoreTraceSpans: true,
            SboWindowMs: 10000);

        var pair = new DeviceEndpointPair(
            Id: pairId,
            SessionId: sessionId,
            Name: "SCADA_To_Outstation1",
            Protocol: ProtocolType.Dnp3,
            ClientIp: IPAddress.Parse("10.0.1.5"),
            ServerIp: IPAddress.Parse("10.0.1.20"),
            ClientProtocolAddressId: 4,
            ServerProtocolAddressId: 3,
            ClientName: "SCADA_Master",
            ServerName: "Outstation_1");

        await sink.InitializeSessionAsync(session, [pair], [], CancellationToken.None);

        var okSpan = new TraceSpanRecord(
            StartTimeUtc: baseTime,
            EndTimeUtc: baseTime.AddMilliseconds(12.5),
            DurationMs: 12.5,
            SessionId: sessionId,
            DevicePairId: pairId,
            TraceId: DeterministicTraceIdGenerator.CreateTraceId(sessionId, pairId, 1, SpanCorrelationRole.Transaction),
            SpanId: DeterministicTraceIdGenerator.CreateSpanId(sessionId, pairId, 1, SpanCorrelationRole.Transaction),
            ParentSpanId: null,
            ServiceName: "Outstation_1",
            OperationName: "DNP3 FC01 Read",
            SpanKind: SpanKind.Client,
            OriginKind: SpanOriginKind.RequestResponse,
            StatusCode: SpanStatusCode.Ok,
            StatusMessage: null,
            Protocol: ProtocolType.Dnp3,
            ClientEndpoint: "SCADA_Master",
            ServerEndpoint: "Outstation_1",
            Direction: TrafficDirection.ClientToServer,
            RequestFrameNumber: 1,
            ResponseFrameNumber: 2,
            TransactionId: "1",
            FunctionCode: 1,
            Attributes: new Dictionary<string, object?> { ["dnp3.src"] = 4, ["dnp3.dst"] = 3 },
            Events: []);

        var unsolErrorSpan = new TraceSpanRecord(
            StartTimeUtc: baseTime.AddSeconds(1),
            EndTimeUtc: baseTime.AddSeconds(1),
            DurationMs: 0.0,
            SessionId: sessionId,
            DevicePairId: pairId,
            TraceId: DeterministicTraceIdGenerator.CreateTraceId(sessionId, pairId, 3, SpanCorrelationRole.UnsolicitedResponse),
            SpanId: DeterministicTraceIdGenerator.CreateSpanId(sessionId, pairId, 3, SpanCorrelationRole.UnsolicitedResponse),
            ParentSpanId: null,
            ServiceName: "SCADA_Master",
            OperationName: "DNP3 FC130 UnsolicitedResponse",
            SpanKind: SpanKind.Consumer,
            OriginKind: SpanOriginKind.Unsolicited,
            StatusCode: SpanStatusCode.Error,
            StatusMessage: "DNP3_IIN_PARAM_ERR",
            Protocol: ProtocolType.Dnp3,
            ClientEndpoint: "SCADA_Master",
            ServerEndpoint: "Outstation_1",
            Direction: TrafficDirection.ServerToClient,
            RequestFrameNumber: null,
            ResponseFrameNumber: 3,
            TransactionId: "2",
            FunctionCode: 130,
            Attributes: new Dictionary<string, object?> { ["dnp3.uns"] = true },
            Events: []);

        var orphanUnsetSpan = new TraceSpanRecord(
            StartTimeUtc: baseTime.AddSeconds(2),
            EndTimeUtc: baseTime.AddSeconds(2),
            DurationMs: 0.0,
            SessionId: sessionId,
            DevicePairId: pairId,
            TraceId: DeterministicTraceIdGenerator.CreateTraceId(sessionId, pairId, 4, SpanCorrelationRole.OrphanResponse),
            SpanId: DeterministicTraceIdGenerator.CreateSpanId(sessionId, pairId, 4, SpanCorrelationRole.OrphanResponse),
            ParentSpanId: null,
            ServiceName: "SCADA_Master",
            OperationName: "DNP3 FC129 Response",
            SpanKind: SpanKind.Consumer,
            OriginKind: SpanOriginKind.OrphanResponse,
            StatusCode: SpanStatusCode.Unset,
            StatusMessage: "ORPHAN_RESPONSE",
            Protocol: ProtocolType.Dnp3,
            ClientEndpoint: "SCADA_Master",
            ServerEndpoint: "Outstation_1",
            Direction: TrafficDirection.ServerToClient,
            RequestFrameNumber: null,
            ResponseFrameNumber: 4,
            TransactionId: "3",
            FunctionCode: 129,
            Attributes: new Dictionary<string, object?> { ["protocol.unpaired"] = true },
            Events: []);

        await sink.WriteBatchAsync(
            new ProtocolDecodeOutput([], [], [], [], [okSpan, unsolErrorSpan, orphanUnsetSpan]),
            CancellationToken.None);
        await sink.CompleteSessionAsync(sessionId, SessionStatus.Completed, CancellationToken.None);

        await using var conn = await _dataSource.OpenConnectionAsync();
        var views = await GrafanaViewsVerifier.AssertGrafanaViewsForSessionAsync(
            conn,
            sessionId,
            expectedSpanCount: 3,
            expectedProtocol: ProtocolType.Dnp3,
            expectedNodeCount: 2,
            expectedEdgeCount: 2);

        Assert.Equal([1, 2, 0], views.Traces.Select(t => t.StatusCode).ToArray());

        var clientToServerEdge = Assert.Single(views.Edges, e => e.Id == "SCADA_Master->Outstation_1:DNP3");
        Assert.Equal("SCADA_Master", clientToServerEdge.Source);
        Assert.Equal("Outstation_1", clientToServerEdge.Target);
        Assert.Equal(1L, clientToServerEdge.DetailSpanCount);
        Assert.Equal(0L, clientToServerEdge.DetailErrorCount);
        Assert.Equal(12.5, clientToServerEdge.DetailAvgDurationMs, precision: 2);

        var serverToClientEdge = Assert.Single(views.Edges, e => e.Id == "Outstation_1->SCADA_Master:DNP3");
        Assert.Equal("Outstation_1", serverToClientEdge.Source);
        Assert.Equal("SCADA_Master", serverToClientEdge.Target);
        Assert.Equal(2L, serverToClientEdge.DetailSpanCount);
        Assert.Equal(1L, serverToClientEdge.DetailErrorCount);

        Assert.All(views.Nodes, node =>
        {
            Assert.Equal(3L, node.MainStat);
            Assert.Equal(2.0 / 3.0, node.ArcSuccess, precision: 6);
            Assert.Equal(1.0 / 3.0, node.ArcError, precision: 6);
        });
    }
}
