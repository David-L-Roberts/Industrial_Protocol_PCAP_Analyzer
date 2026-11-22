using System.Text.Json;
using System.Text.RegularExpressions;
using Analyzer.IntegrationTests.Configuration;

namespace Analyzer.IntegrationTests;

public class GrafanaDashboardAndSqlViewContractTests
{
    private static string GetRepoRoot() =>
        IntegrationTestConfig.FindRepoRoot(AppContext.BaseDirectory)
        ?? throw new InvalidOperationException("Could not locate repository root.");

    [Fact]
    public void TraceSpansMigrationSql_DefinesAllThreeGrafanaViewsIdempotently()
    {
        var sqlPath = Path.Combine(GetRepoRoot(), "docker", "sql", "002_add_trace_spans.sql");
        Assert.True(File.Exists(sqlPath), $"Expected migration SQL file at '{sqlPath}'.");

        string sql = File.ReadAllText(sqlPath);

        Assert.Matches(new Regex(@"CREATE\s+OR\s+REPLACE\s+VIEW\s+v_grafana_traces\b", RegexOptions.IgnoreCase), sql);
        Assert.Matches(new Regex(@"CREATE\s+OR\s+REPLACE\s+VIEW\s+v_grafana_node_graph_nodes\b", RegexOptions.IgnoreCase), sql);
        Assert.Matches(new Regex(@"CREATE\s+OR\s+REPLACE\s+VIEW\s+v_grafana_node_graph_edges\b", RegexOptions.IgnoreCase), sql);

        // v_grafana_traces contract columns
        string[] traceColumns =
        [
            "session_id",
            "device_pair_id",
            "start_time_utc",
            "origin_kind",
            "protocol",
            "\"traceID\"",
            "\"spanID\"",
            "\"parentSpanID\"",
            "\"operationName\"",
            "\"serviceName\"",
            "\"startTime\"",
            "\"duration\"",
            "\"statusCode\"",
            "\"statusMessage\"",
            "\"serviceTags\"",
            "\"tags\"",
            "\"logs\""
        ];

        foreach (string column in traceColumns)
        {
            Assert.Contains(column, sql, StringComparison.Ordinal);
        }

        // v_grafana_node_graph_nodes contract columns
        string[] nodeColumns =
        [
            "\"subTitle\"",
            "\"mainStat\"",
            "\"secondaryStat\"",
            "arc__success",
            "arc__error"
        ];

        foreach (string column in nodeColumns)
        {
            Assert.Contains(column, sql, StringComparison.Ordinal);
        }

        // v_grafana_node_graph_edges contract columns & SERVER_TO_CLIENT routing
        string[] edgeColumns =
        [
            "detail__protocol",
            "detail__span_count",
            "detail__error_count",
            "detail__avg_duration_ms",
            "detail__p95_duration_ms",
            "SERVER_TO_CLIENT"
        ];

        foreach (string column in edgeColumns)
        {
            Assert.Contains(column, sql, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TraceTopologyDashboard_IsValidJsonWithExpectedUidVariablesPanelsAndDataLinks()
    {
        var dashboardPath = Path.Combine(
            GetRepoRoot(),
            "docker",
            "grafana",
            "dashboards",
            "trace_topology_explorer.json");

        Assert.True(File.Exists(dashboardPath), $"Expected dashboard JSON at '{dashboardPath}'.");

        using var doc = JsonDocument.Parse(File.ReadAllText(dashboardPath));
        var root = doc.RootElement;

        Assert.Equal("industrial-protocol-traces", root.GetProperty("uid").GetString());
        Assert.Equal("Industrial Protocol Trace & Topology Explorer", root.GetProperty("title").GetString());

        var variables = root.GetProperty("templating").GetProperty("list").EnumerateArray().ToList();
        var variableNames = variables.Select(v => v.GetProperty("name").GetString()).ToHashSet(StringComparer.Ordinal);
        string[] expectedVars = ["session", "device_pair", "protocol", "status", "trace_id", "window_bucket"];
        foreach (string expectedVar in expectedVars)
        {
            Assert.Contains(expectedVar, variableNames);
        }

        var traceIdVar = Assert.Single(variables, v => v.GetProperty("name").GetString() == "trace_id");
        Assert.Equal("textbox", traceIdVar.GetProperty("type").GetString());

        var windowBucketVar = Assert.Single(variables, v => v.GetProperty("name").GetString() == "window_bucket");
        string windowBucketQuery = windowBucketVar.GetProperty("query").GetString() ?? string.Empty;
        foreach (string bucket in new[] { "1s", "5s", "10s", "30s" })
        {
            Assert.Contains(bucket, windowBucketQuery, StringComparison.Ordinal);
        }

        var topLevelPanels = root.GetProperty("panels").EnumerateArray().ToList();

        // 1. Node Graph panel
        var nodeGraphPanel = Assert.Single(topLevelPanels, p => p.GetProperty("type").GetString() == "nodeGraph");
        var nodeGraphTargets = nodeGraphPanel.GetProperty("targets").EnumerateArray().ToList();
        var nodesTarget = Assert.Single(nodeGraphTargets, t => t.GetProperty("refId").GetString() == "nodes");
        var edgesTarget = Assert.Single(nodeGraphTargets, t => t.GetProperty("refId").GetString() == "edges");
        Assert.Equal("table", nodesTarget.GetProperty("format").GetString());
        Assert.Equal("table", edgesTarget.GetProperty("format").GetString());
        Assert.Contains("v_grafana_node_graph_nodes", nodesTarget.GetProperty("rawSql").GetString()!, StringComparison.Ordinal);
        Assert.Contains("v_grafana_node_graph_edges", edgesTarget.GetProperty("rawSql").GetString()!, StringComparison.Ordinal);

        // 2. Trace & Span Explorer table panel
        var explorerPanel = Assert.Single(
            topLevelPanels,
            p => p.GetProperty("type").GetString() == "table" &&
                 p.GetProperty("title").GetString() == "Trace & Span Explorer");
        string explorerSql = explorerPanel.GetProperty("targets")[0].GetProperty("rawSql").GetString()!;
        Assert.Contains("FROM trace_spans", explorerSql, StringComparison.Ordinal);
        Assert.Contains("$session", explorerSql, StringComparison.Ordinal);
        Assert.Contains("$device_pair", explorerSql, StringComparison.Ordinal);
        Assert.Contains("$protocol", explorerSql, StringComparison.Ordinal);
        Assert.Contains("$status", explorerSql, StringComparison.Ordinal);
        Assert.Contains("$__timeFilter", explorerSql, StringComparison.Ordinal);
        AssertDataLinkOnTraceId(explorerPanel, expectedUrlPrefix: "/d/industrial-protocol-traces", requireSessionVar: true);

        // 3. Trace Waterfall panel (12 Grafana Traces columns)
        var traceWaterfallPanel = Assert.Single(topLevelPanels, p => p.GetProperty("type").GetString() == "traces");
        string traceWaterfallSql = traceWaterfallPanel.GetProperty("targets")[0].GetProperty("rawSql").GetString()!;
        Assert.Contains("v_grafana_traces", traceWaterfallSql, StringComparison.Ordinal);
        Assert.Contains("$session", traceWaterfallSql, StringComparison.Ordinal);
        Assert.Contains("$trace_id", traceWaterfallSql, StringComparison.Ordinal);
        foreach (string col in new[]
        {
            "\"traceID\"", "\"spanID\"", "\"parentSpanID\"", "\"operationName\"", "\"serviceName\"",
            "\"startTime\"", "\"duration\"", "\"statusCode\"", "\"statusMessage\"", "\"serviceTags\"", "\"tags\"", "\"logs\""
        })
        {
            Assert.Contains(col, traceWaterfallSql, StringComparison.Ordinal);
        }

        // 4. Collapsible Time-Window Capture Waterfall row + nested traces panel
        var collapsedRow = Assert.Single(
            topLevelPanels,
            p => p.GetProperty("type").GetString() == "row" && p.GetProperty("collapsed").GetBoolean());
        var nestedPanels = collapsedRow.GetProperty("panels").EnumerateArray().ToList();
        var timeWindowTracesPanel = Assert.Single(nestedPanels, p => p.GetProperty("type").GetString() == "traces");
        string timeWindowSql = timeWindowTracesPanel.GetProperty("targets")[0].GetProperty("rawSql").GetString()!;
        Assert.Contains("v_grafana_traces", timeWindowSql, StringComparison.Ordinal);
        Assert.Contains("time_bucket(INTERVAL '$window_bucket', start_time_utc)", timeWindowSql, StringComparison.Ordinal);
        Assert.Contains("AS \"traceID\"", timeWindowSql, StringComparison.Ordinal);

        // 5. Correlated Telemetry & Commands detail tables
        var tagValuesPanel = Assert.Single(
            topLevelPanels,
            p => p.GetProperty("type").GetString() == "table" &&
                 p.GetProperty("title").GetString() == "Correlated Telemetry (tag_values)");
        string tagValuesSql = tagValuesPanel.GetProperty("targets")[0].GetProperty("rawSql").GetString()!;
        Assert.Contains("FROM tag_values", tagValuesSql, StringComparison.Ordinal);
        Assert.Contains("$session", tagValuesSql, StringComparison.Ordinal);
        Assert.Contains("$trace_id", tagValuesSql, StringComparison.Ordinal);

        var commandsPanel = Assert.Single(
            topLevelPanels,
            p => p.GetProperty("type").GetString() == "table" &&
                 p.GetProperty("title").GetString() == "Correlated Control Commands (captured_command_events)");
        string commandsSql = commandsPanel.GetProperty("targets")[0].GetProperty("rawSql").GetString()!;
        Assert.Contains("FROM captured_command_events", commandsSql, StringComparison.Ordinal);
        Assert.Contains("$session", commandsSql, StringComparison.Ordinal);
        Assert.Contains("$trace_id", commandsSql, StringComparison.Ordinal);
    }

    [Fact]
    public void AnalyzerDashboard_ProjectsTraceIdAndWiresDataLinksToTraceExplorer()
    {
        var dashboardPath = Path.Combine(
            GetRepoRoot(),
            "docker",
            "grafana",
            "dashboards",
            "industrial_protocol_analyzer.json");

        Assert.True(File.Exists(dashboardPath), $"Expected dashboard JSON at '{dashboardPath}'.");

        using var doc = JsonDocument.Parse(File.ReadAllText(dashboardPath));
        var panels = doc.RootElement.GetProperty("panels").EnumerateArray().ToList();

        int[] targetPanelIds = [18, 23, 29];
        foreach (int panelId in targetPanelIds)
        {
            var panel = Assert.Single(panels, p => p.GetProperty("id").GetInt32() == panelId);
            Assert.Equal("table", panel.GetProperty("type").GetString());

            string rawSql = panel.GetProperty("targets")[0].GetProperty("rawSql").GetString()!;
            Assert.Matches(new Regex(@"\btrace_id\b"), rawSql);

            AssertDataLinkOnTraceId(
                panel,
                expectedUrlPrefix: "/d/industrial-protocol-traces?var-session=${session}&var-trace_id=${__data.fields.trace_id}&from=${__from}&to=${__to}",
                requireSessionVar: true);
        }
    }

    private static void AssertDataLinkOnTraceId(JsonElement panel, string expectedUrlPrefix, bool requireSessionVar)
    {
        var overrides = panel.GetProperty("fieldConfig").GetProperty("overrides").EnumerateArray().ToList();
        var traceIdOverride = Assert.Single(
            overrides,
            o => o.GetProperty("matcher").GetProperty("id").GetString() == "byName" &&
                 o.GetProperty("matcher").GetProperty("options").GetString() == "trace_id");

        var linksProp = Assert.Single(
            traceIdOverride.GetProperty("properties").EnumerateArray(),
            p => p.GetProperty("id").GetString() == "links");

        var link = linksProp.GetProperty("value").EnumerateArray().First();
        string url = link.GetProperty("url").GetString()!;
        Assert.StartsWith(expectedUrlPrefix, url, StringComparison.Ordinal);
        Assert.Contains("var-trace_id=${__data.fields.trace_id}", url, StringComparison.Ordinal);
        if (requireSessionVar)
        {
            Assert.Contains("var-session=${session}", url, StringComparison.Ordinal);
        }
    }
}
