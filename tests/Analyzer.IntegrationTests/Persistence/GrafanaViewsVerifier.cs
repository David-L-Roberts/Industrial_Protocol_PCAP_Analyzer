using System.Text.Json;
using Analyzer.Core.Domain;
using Analyzer.IntegrationTests.Configuration;
using Npgsql;

namespace Analyzer.IntegrationTests.Persistence;

internal sealed record VerifiedGrafanaTraceRow(
    TraceId TraceId,
    SpanId SpanId,
    SpanId? ParentSpanId,
    ProtocolType Protocol,
    int StatusCode,
    string StatusMessage);

internal sealed record VerifiedNodeGraphNode(
    string Id,
    string Title,
    string SubTitle,
    long MainStat,
    double SecondaryStat,
    double ArcSuccess,
    double ArcError);

internal sealed record VerifiedNodeGraphEdge(
    string Id,
    string Source,
    string Target,
    string MainStat,
    string SecondaryStat,
    ProtocolType DetailProtocol,
    long DetailSpanCount,
    long DetailErrorCount,
    double DetailAvgDurationMs,
    double DetailP95DurationMs);

internal sealed record VerifiedGrafanaViewsResult(
    IReadOnlyList<VerifiedGrafanaTraceRow> Traces,
    IReadOnlyList<VerifiedNodeGraphNode> Nodes,
    IReadOnlyList<VerifiedNodeGraphEdge> Edges);

internal static class GrafanaViewsVerifier
{
    private const long MigrationAdvisoryLockId = 88002;
    private static readonly SemaphoreSlim MigrationGate = new(1, 1);
    private static bool _migrationAppliedInProcess;

    private static readonly string[] ExpectedServiceTagKeys =
    [
        "protocol",
        "device.pair.name",
        "endpoint.client",
        "endpoint.server",
        "span.kind",
        "span.origin_kind"
    ];

    public static async Task EnsureTraceSpansMigrationAppliedAsync(
        NpgsqlConnection conn,
        bool forceReapply = false,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conn);

        await MigrationGate.WaitAsync(ct);
        try
        {
            if (!forceReapply && _migrationAppliedInProcess)
            {
                return;
            }

            var repoRoot = IntegrationTestConfig.FindRepoRootOrThrow();
            var migrationPath = Path.Combine(repoRoot, "docker", "sql", "002_add_trace_spans.sql");
            Assert.True(File.Exists(migrationPath), $"Expected migration file at '{migrationPath}'.");

            string migrationSql = await File.ReadAllTextAsync(migrationPath, ct);

            await using (var lockCmd = new NpgsqlCommand($"SELECT pg_advisory_lock({MigrationAdvisoryLockId});", conn))
            {
                await lockCmd.ExecuteNonQueryAsync(ct);
            }

            try
            {
                await using var applyCmd = new NpgsqlCommand(migrationSql, conn);
                await applyCmd.ExecuteNonQueryAsync(ct);
                _migrationAppliedInProcess = true;
            }
            finally
            {
                await using var unlockCmd = new NpgsqlCommand($"SELECT pg_advisory_unlock({MigrationAdvisoryLockId});", conn);
                await unlockCmd.ExecuteNonQueryAsync(CancellationToken.None);
            }
        }
        finally
        {
            MigrationGate.Release();
        }
    }

    public static async Task<VerifiedGrafanaViewsResult> AssertGrafanaViewsForSessionAsync(
        NpgsqlConnection conn,
        Guid sessionId,
        long expectedSpanCount,
        ProtocolType expectedProtocol,
        int expectedNodeCount,
        int expectedEdgeCount,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(conn);
        await EnsureTraceSpansMigrationAppliedAsync(conn, forceReapply: false, ct);

        string expectedWireProtocol = ToWireProtocol(expectedProtocol);
        var traces = await QueryAndAssertTracesViewAsync(conn, sessionId, expectedSpanCount, expectedProtocol, expectedWireProtocol, ct);
        await AssertTimeWindowWaterfallQueryAsync(conn, sessionId, expectedSpanCount, ct);
        var nodes = await QueryAndAssertNodesViewAsync(conn, sessionId, expectedNodeCount, ct);
        var edges = await QueryAndAssertEdgesViewAsync(conn, sessionId, expectedProtocol, expectedWireProtocol, expectedEdgeCount, nodes, ct);

        return new VerifiedGrafanaViewsResult(traces, nodes, edges);
    }

    private static async Task<List<VerifiedGrafanaTraceRow>> QueryAndAssertTracesViewAsync(
        NpgsqlConnection conn,
        Guid sessionId,
        long expectedSpanCount,
        ProtocolType expectedProtocol,
        string expectedWireProtocol,
        CancellationToken ct)
    {
        var traces = new List<VerifiedGrafanaTraceRow>();

        await using var cmd = new NpgsqlCommand(
            """
            SELECT
                session_id,
                device_pair_id,
                start_time_utc,
                origin_kind,
                protocol,
                "traceID",
                "spanID",
                "parentSpanID",
                "operationName",
                "serviceName",
                "startTime",
                "duration",
                "statusCode",
                "statusMessage",
                "serviceTags"::text,
                "tags"::text,
                "logs"::text
            FROM v_grafana_traces
            WHERE session_id = @id
            ORDER BY "startTime" ASC;
            """,
            conn);
        cmd.Parameters.AddWithValue("id", sessionId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            Assert.Equal(sessionId, reader.GetGuid(0));
            Assert.NotEqual(Guid.Empty, reader.GetGuid(1));
            Assert.True(reader.GetDateTime(2) > DateTime.UnixEpoch);
            Assert.False(string.IsNullOrWhiteSpace(reader.GetString(3)));
            Assert.Equal(expectedWireProtocol, reader.GetString(4));

            var traceId = AssertCanonicalTraceId(reader.GetString(5));
            var spanId = AssertCanonicalSpanId(reader.GetString(6));
            string parentRaw = reader.GetString(7);
            SpanId? parentSpanId = string.IsNullOrEmpty(parentRaw) ? null : AssertCanonicalSpanId(parentRaw);

            Assert.False(string.IsNullOrWhiteSpace(reader.GetString(8)));
            Assert.False(string.IsNullOrWhiteSpace(reader.GetString(9)));

            double startTimeMs = reader.GetDouble(10);
            double durationMs = reader.GetDouble(11);
            int statusCode = reader.GetInt32(12);
            string statusMessage = reader.GetString(13);

            Assert.True(double.IsFinite(startTimeMs) && startTimeMs > 0.0);
            Assert.True(double.IsFinite(durationMs) && durationMs >= 0.0);
            Assert.Contains(statusCode, new[] { 0, 1, 2 });
            Assert.NotNull(statusMessage);

            AssertServiceTagsJson(reader.GetString(14));
            AssertJsonArray(reader.GetString(15));
            AssertJsonArray(reader.GetString(16));

            traces.Add(new VerifiedGrafanaTraceRow(
                traceId,
                spanId,
                parentSpanId,
                expectedProtocol,
                statusCode,
                statusMessage));
        }

        Assert.Equal(expectedSpanCount, traces.Count);
        return traces;
    }

    private static async Task AssertTimeWindowWaterfallQueryAsync(
        NpgsqlConnection conn,
        Guid sessionId,
        long expectedSpanCount,
        CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(
            """
            SELECT
                md5(session_id::text || ':' || time_bucket(INTERVAL '5s', start_time_utc)::text) AS "traceID",
                "spanID",
                "parentSpanID",
                "operationName",
                "serviceName",
                "startTime",
                "duration",
                "statusCode",
                "statusMessage",
                "serviceTags"::text,
                "tags"::text,
                "logs"::text
            FROM v_grafana_traces
            WHERE session_id = @id
            ORDER BY "startTime" ASC
            LIMIT 250;
            """,
            conn);
        cmd.Parameters.AddWithValue("id", sessionId);

        long rowCount = 0;
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rowCount++;
            AssertCanonicalTraceId(reader.GetString(0));
            AssertCanonicalSpanId(reader.GetString(1));
        }

        Assert.Equal(Math.Min(expectedSpanCount, 250L), rowCount);
    }

    private static async Task<List<VerifiedNodeGraphNode>> QueryAndAssertNodesViewAsync(
        NpgsqlConnection conn,
        Guid sessionId,
        int expectedNodeCount,
        CancellationToken ct)
    {
        var nodes = new List<VerifiedNodeGraphNode>();
        var seenIds = new HashSet<string>(StringComparer.Ordinal);

        await using var cmd = new NpgsqlCommand(
            """
            SELECT id, title, "subTitle", "mainStat", "secondaryStat", arc__success, arc__error
            FROM v_grafana_node_graph_nodes
            WHERE session_id = @id
            ORDER BY id ASC;
            """,
            conn);
        cmd.Parameters.AddWithValue("id", sessionId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            string id = reader.GetString(0);
            string title = reader.GetString(1);
            string subTitle = reader.GetString(2);
            long mainStat = reader.GetInt64(3);
            double secondaryStat = reader.GetDouble(4);
            double arcSuccess = reader.GetDouble(5);
            double arcError = reader.GetDouble(6);

            Assert.False(string.IsNullOrWhiteSpace(id));
            Assert.True(seenIds.Add(id), $"Duplicate node id '{id}'.");
            Assert.Equal(id, title);
            Assert.False(string.IsNullOrWhiteSpace(subTitle));
            Assert.True(mainStat > 0);
            Assert.True(double.IsFinite(secondaryStat) && secondaryStat >= 0.0);
            Assert.InRange(arcSuccess, 0.0, 1.0);
            Assert.InRange(arcError, 0.0, 1.0);
            Assert.True(Math.Abs((arcSuccess + arcError) - 1.0) < 1e-6, $"Arc sum was {arcSuccess + arcError} for node '{id}'.");

            nodes.Add(new VerifiedNodeGraphNode(id, title, subTitle, mainStat, secondaryStat, arcSuccess, arcError));
        }

        Assert.Equal(expectedNodeCount, nodes.Count);
        return nodes;
    }

    private static async Task<List<VerifiedNodeGraphEdge>> QueryAndAssertEdgesViewAsync(
        NpgsqlConnection conn,
        Guid sessionId,
        ProtocolType expectedProtocol,
        string expectedWireProtocol,
        int expectedEdgeCount,
        IReadOnlyList<VerifiedNodeGraphNode> nodes,
        CancellationToken ct)
    {
        var nodeIds = nodes.Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
        var edges = new List<VerifiedNodeGraphEdge>();
        var seenEdgeIds = new HashSet<string>(StringComparer.Ordinal);

        await using var cmd = new NpgsqlCommand(
            """
            SELECT id, source, target, "mainStat", "secondaryStat", detail__protocol, detail__span_count, detail__error_count, detail__avg_duration_ms, detail__p95_duration_ms
            FROM v_grafana_node_graph_edges
            WHERE session_id = @id
            ORDER BY id ASC;
            """,
            conn);
        cmd.Parameters.AddWithValue("id", sessionId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            string id = reader.GetString(0);
            string source = reader.GetString(1);
            string target = reader.GetString(2);
            string mainStat = reader.GetString(3);
            string secondaryStat = reader.GetString(4);
            string detailProtocolWire = reader.GetString(5);
            long spanCount = reader.GetInt64(6);
            long errorCount = reader.GetInt64(7);
            double avgDurationMs = reader.GetDouble(8);
            double p95DurationMs = reader.GetDouble(9);

            Assert.True(seenEdgeIds.Add(id), $"Duplicate edge id '{id}'.");
            Assert.Equal($"{source}->{target}:{detailProtocolWire}", id);
            Assert.Contains(source, nodeIds);
            Assert.Contains(target, nodeIds);
            Assert.Contains("spans", mainStat, StringComparison.Ordinal);
            Assert.Contains("ms", mainStat, StringComparison.Ordinal);
            Assert.Contains("% err", secondaryStat, StringComparison.Ordinal);
            Assert.Equal(expectedWireProtocol, detailProtocolWire);
            Assert.True(spanCount > 0);
            Assert.True(errorCount >= 0 && errorCount <= spanCount);
            Assert.True(double.IsFinite(avgDurationMs) && avgDurationMs >= 0.0);
            Assert.True(double.IsFinite(p95DurationMs) && p95DurationMs >= 0.0);

            edges.Add(new VerifiedNodeGraphEdge(
                id,
                source,
                target,
                mainStat,
                secondaryStat,
                expectedProtocol,
                spanCount,
                errorCount,
                avgDurationMs,
                p95DurationMs));
        }

        Assert.Equal(expectedEdgeCount, edges.Count);
        return edges;
    }

    private static TraceId AssertCanonicalTraceId(string raw)
    {
        Assert.True(TraceId.TryParse(raw, out var parsed) && parsed.Value == raw, $"Invalid canonical TraceId '{raw}'.");
        return parsed;
    }

    private static SpanId AssertCanonicalSpanId(string raw)
    {
        Assert.True(SpanId.TryParse(raw, out var parsed) && parsed.Value == raw, $"Invalid canonical SpanId '{raw}'.");
        return parsed;
    }

    private static string ToWireProtocol(ProtocolType protocol) => protocol switch
    {
        ProtocolType.ModbusTcp => "ModbusTCP",
        ProtocolType.Dnp3 => "DNP3",
        _ => throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "Unsupported protocol.")
    };

    private static void AssertServiceTagsJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
        var keys = doc.RootElement
            .EnumerateArray()
            .Select(el => el.GetProperty("key").GetString()!)
            .ToHashSet(StringComparer.Ordinal);

        foreach (string expectedKey in ExpectedServiceTagKeys)
        {
            Assert.Contains(expectedKey, keys);
        }
    }

    private static void AssertJsonArray(string json)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
    }
}
