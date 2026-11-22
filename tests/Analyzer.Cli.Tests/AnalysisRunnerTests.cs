using System.Net;
using System.Text.Json;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Services;
using Analyzer.Infrastructure.Mapping;
using Analyzer.Infrastructure.Storage;
using Analyzer.Cli;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Analyzer.Cli.Tests;

public class AnalysisRunnerTests : IDisposable
{
    private readonly string _tempDir;

    public AnalysisRunnerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "AnalyzerCliTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            try
            {
                Directory.Delete(_tempDir, recursive: true);
            }
            catch
            {
                // Ignore cleanup errors
            }
        }
    }

    [Fact]
    public async Task RunAnalysisAsync_ExecutesPipelineAndReturnsSummary()
    {
        // 1. Arrange test files
        string pcapPath = Path.Combine(_tempDir, "sample.pcap");
        await File.WriteAllBytesAsync(pcapPath, [0x01, 0x02, 0x03]);

        string csvPath = Path.Combine(_tempDir, "tags.csv");
        string csvContent = """
            Protocol,Address,TagName,DataType,Endianness,ScaleMultiplier,ScaleOffset,Units,Description
            ModbusTCP,HR:40001,Bus_Volts_A,UINT16,,0.1,0.0,kV,Phase A Bus Voltage
            """;
        await File.WriteAllTextAsync(csvPath, csvContent);

        string manifestPath = Path.Combine(_tempDir, "manifest.json");
        var manifestObj = new
        {
            session_name = "FAT_Substation_1",
            pcap_file = "sample.pcap",
            timeout_threshold_ms = 1000,
            store_unmapped_registers = false,
            device_pairs = new[]
            {
                new
                {
                    name = "RTAC_to_Relay",
                    protocol = "ModbusTCP",
                    client_ip = "10.0.1.10",
                    server_ip = "10.0.1.20",
                    client_protocol_address_id = (int?)null,
                    server_protocol_address_id = (int?)1,
                    tag_mapping_csv = "tags.csv"
                }
            }
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifestObj));

        // Frames to process: 1 request + 1 response
        var clientIp = IPAddress.Parse("10.0.1.10");
        var serverIp = IPAddress.Parse("10.0.1.20");
        var t0 = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

        var frames = new List<DissectedFrame>
        {
            // Frame 1: Modbus Read Holding Registers Request (TxId=1, Unit=1, Start=0, Qty=1)
            new(
                FrameNumber: 1,
                TimestampUtc: t0,
                SourceIp: clientIp,
                SourcePort: 50000,
                DestIp: serverIp,
                DestPort: 502,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01]),

            // Frame 2: Modbus Response with value 1380 -> 138.0 kV
            new(
                FrameNumber: 2,
                TimestampUtc: t0.AddMilliseconds(50),
                SourceIp: serverIp,
                SourcePort: 502,
                DestIp: clientIp,
                DestPort: 50000,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x05, 0x64])
        };

        var fakeSink = new FakeDataSink();
        var fakeSource = new FakeFrameSource(frames);
        var fakeArchiver = new FakePcapArchiver();

        var infraFactory = new FakeInfraFactory(fakeSink, fakeSource, fakeArchiver);

        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();
        services.AddSingleton<IAnalysisInfrastructureFactory>(infraFactory);
        var sp = services.BuildServiceProvider();

        var runner = sp.GetRequiredService<IAnalysisRunner>();

        var options = new AnalysisOptions(
            ManifestPath: manifestPath,
            DbConnectionString: "Host=localhost;Database=test",
            S3Endpoint: "http://localhost:9000");

        using var progressWriter = new StringWriter();

        // 2. Act
        var summary = await runner.RunAnalysisAsync(options, progressWriter);

        // 3. Assert
        Assert.NotNull(summary);
        Assert.Equal(2, summary.TotalFramesProcessed);
        Assert.Equal(2, summary.MatchedFramesProcessed);
        Assert.Equal(1, summary.TotalTransactions);
        Assert.Equal(1, summary.SuccessTransactions);
        Assert.Equal(0, summary.ErrorTransactions);
        Assert.Equal(1, summary.DataPointsPersisted);

        Assert.NotNull(fakeSink.InitializedSession);
        Assert.Equal("FAT_Substation_1", fakeSink.InitializedSession.Name);
        Assert.Equal("captures/archived_sample.pcap", fakeSink.InitializedSession.S3ObjectKey);
        Assert.True(fakeSink.InitializedSession.StoreTraceSpans);
        Assert.Equal(10000, fakeSink.InitializedSession.SboWindowMs);
        Assert.Equal(SessionStatus.Completed, fakeSink.CompletedStatus);

        string outputText = progressWriter.ToString();
        Assert.Contains("FAT_Substation_1", outputText);
        Assert.Contains("Total frames processed: 2", outputText);
        Assert.Contains("Transactions: 1", outputText);
        Assert.Contains("Trace spans persisted: 0", outputText);
    }

    [Fact]
    public async Task RunAnalysisAsync_WithDisableTracesOption_OverridesManifestAndOmitsTraceSpansSummary()
    {
        string pcapPath = Path.Combine(_tempDir, "no_traces_cli.pcap");
        await File.WriteAllBytesAsync(pcapPath, [0x01, 0x02]);

        string manifestPath = Path.Combine(_tempDir, "manifest_no_traces_cli.json");
        var manifestObj = new
        {
            session_name = "SAT_NoTraces_CLI",
            pcap_file = "no_traces_cli.pcap",
            store_trace_spans = true,
            device_pairs = Array.Empty<object>()
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifestObj));

        var fakeSink = new FakeDataSink();
        var infraFactory = new FakeInfraFactory(fakeSink, new FakeFrameSource([]), null);

        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();
        services.AddSingleton<IAnalysisInfrastructureFactory>(infraFactory);
        var sp = services.BuildServiceProvider();

        var runner = sp.GetRequiredService<IAnalysisRunner>();
        var options = new AnalysisOptions(
            ManifestPath: manifestPath,
            DbConnectionString: "Host=localhost;Database=test",
            DisableTraces: true);

        using var progressWriter = new StringWriter();
        var summary = await runner.RunAnalysisAsync(options, progressWriter);

        Assert.NotNull(fakeSink.InitializedSession);
        Assert.False(fakeSink.InitializedSession.StoreTraceSpans);
        Assert.Equal(0, summary.TraceSpansPersisted);
        Assert.DoesNotContain("Trace spans persisted:", progressWriter.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAnalysisAsync_WithManifestStoreTraceSpansFalse_PersistsOptOutAndOmitsTraceSpansSummary()
    {
        string pcapPath = Path.Combine(_tempDir, "no_traces_manifest.pcap");
        await File.WriteAllBytesAsync(pcapPath, [0x01, 0x02]);

        string manifestPath = Path.Combine(_tempDir, "manifest_no_traces.json");
        var manifestObj = new
        {
            session_name = "SAT_NoTraces_Manifest",
            pcap_file = "no_traces_manifest.pcap",
            store_trace_spans = false,
            device_pairs = Array.Empty<object>()
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifestObj));

        var fakeSink = new FakeDataSink();
        var infraFactory = new FakeInfraFactory(fakeSink, new FakeFrameSource([]), null);

        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();
        services.AddSingleton<IAnalysisInfrastructureFactory>(infraFactory);
        var sp = services.BuildServiceProvider();

        var runner = sp.GetRequiredService<IAnalysisRunner>();
        var options = new AnalysisOptions(
            ManifestPath: manifestPath,
            DbConnectionString: "Host=localhost;Database=test");

        using var progressWriter = new StringWriter();
        var summary = await runner.RunAnalysisAsync(options, progressWriter);

        Assert.NotNull(fakeSink.InitializedSession);
        Assert.False(fakeSink.InitializedSession.StoreTraceSpans);
        Assert.Equal(0, summary.TraceSpansPersisted);
        Assert.DoesNotContain("Trace spans persisted:", progressWriter.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAnalysisAsync_WithUnmappedRegistersEnabled_PersistsUnmappedRegisters()
    {
        string pcapPath = Path.Combine(_tempDir, "unmapped.pcap");
        await File.WriteAllBytesAsync(pcapPath, [0x01, 0x02]);

        string manifestPath = Path.Combine(_tempDir, "manifest_unmapped.json");
        var manifestObj = new
        {
            session_name = "SAT_Unmapped_Run",
            pcap_file = "unmapped.pcap",
            timeout_threshold_ms = 1000,
            store_unmapped_registers = true,
            device_pairs = new[]
            {
                new
                {
                    name = "ModbusPair",
                    protocol = "ModbusTCP",
                    client_ip = "10.0.1.10",
                    server_ip = "10.0.1.20",
                    client_protocol_address_id = (int?)null,
                    server_protocol_address_id = (int?)1,
                    tag_mapping_csv = (string?)null
                }
            }
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifestObj));

        var clientIp = IPAddress.Parse("10.0.1.10");
        var serverIp = IPAddress.Parse("10.0.1.20");
        var t0 = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

        var frames = new List<DissectedFrame>
        {
            // Frame 1: Modbus Read Holding Registers Request (TxId=1, Unit=1, Start=100, Qty=1)
            new(
                FrameNumber: 1,
                TimestampUtc: t0,
                SourceIp: clientIp,
                SourcePort: 50000,
                DestIp: serverIp,
                DestPort: 502,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x01]),

            // Frame 2: Modbus Response with value 9999 (offset 100 is not mapped -> unmapped record)
            new(
                FrameNumber: 2,
                TimestampUtc: t0.AddMilliseconds(20),
                SourceIp: serverIp,
                SourcePort: 502,
                DestIp: clientIp,
                DestPort: 50000,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x27, 0x0F])
        };

        var fakeSink = new FakeDataSink();
        var fakeSource = new FakeFrameSource(frames);
        var infraFactory = new FakeInfraFactory(fakeSink, fakeSource, null);

        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();
        services.AddSingleton<IAnalysisInfrastructureFactory>(infraFactory);
        var sp = services.BuildServiceProvider();

        var runner = sp.GetRequiredService<IAnalysisRunner>();
        var options = new AnalysisOptions(
            ManifestPath: manifestPath,
            DbConnectionString: "Host=localhost;Database=test");

        using var progressWriter = new StringWriter();
        var summary = await runner.RunAnalysisAsync(options, progressWriter);

        Assert.Equal(2, summary.TotalFramesProcessed);
        Assert.Equal(1, summary.TotalTransactions);
        Assert.Equal(1, summary.UnmappedRegistersPersisted);
        Assert.Single(fakeSink.UnmappedRegisters);
        Assert.Equal(100, fakeSink.UnmappedRegisters[0].RegisterOffset);
        Assert.Contains("Unmapped registers persisted: 1", progressWriter.ToString());
    }

    [Fact]
    public async Task RunAnalysisAsync_MissingManifest_ThrowsFileNotFoundException()
    {
        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();
        services.AddSingleton<IAnalysisInfrastructureFactory>(new FakeInfraFactory(new FakeDataSink(), new FakeFrameSource([]), null));
        var sp = services.BuildServiceProvider();

        var runner = sp.GetRequiredService<IAnalysisRunner>();
        var options = new AnalysisOptions(
            ManifestPath: Path.Combine(_tempDir, "nonexistent.json"),
            DbConnectionString: "Host=localhost;Database=test");

        await Assert.ThrowsAsync<FileNotFoundException>(() => runner.RunAnalysisAsync(options));
    }

    [Fact]
    public async Task RunAnalysisAsync_WritesLifecyclePhaseMilestonesInOrderBeforeCompletionBanner()
    {
        string pcapPath = Path.Combine(_tempDir, "milestones.pcap");
        await File.WriteAllBytesAsync(pcapPath, [0x01, 0x02]);

        string csvPath1 = Path.Combine(_tempDir, "pair1_tags.csv");
        string csvContent1 = """
            Protocol,Address,TagName,DataType,Endianness,ScaleMultiplier,ScaleOffset,Units,Description
            ModbusTCP,HR:40001,Bus_Volts_A,UINT16,,0.1,0.0,kV,Phase A Voltage
            ModbusTCP,HR:40002,Bus_Volts_B,UINT16,,0.1,0.0,kV,Phase B Voltage
            """;
        await File.WriteAllTextAsync(csvPath1, csvContent1);

        string csvPath2 = Path.Combine(_tempDir, "pair2_tags.csv");
        string csvContent2 = """
            Protocol,Address,TagName,DataType,Endianness,ScaleMultiplier,ScaleOffset,Units,Description
            ModbusTCP,HR:40001,Feeder_Current,UINT16,,1.0,0.0,A,Feeder Current
            """;
        await File.WriteAllTextAsync(csvPath2, csvContent2);

        string manifestPath = Path.Combine(_tempDir, "manifest_milestones.json");
        var manifestObj = new
        {
            session_name = "SAT_Milestones_Run",
            pcap_file = "milestones.pcap",
            timeout_threshold_ms = 1000,
            store_unmapped_registers = false,
            device_pairs = new[]
            {
                new
                {
                    name = "Pair_1",
                    protocol = "ModbusTCP",
                    client_ip = "10.0.1.10",
                    server_ip = "10.0.1.20",
                    client_protocol_address_id = (int?)null,
                    server_protocol_address_id = (int?)1,
                    tag_mapping_csv = "pair1_tags.csv"
                },
                new
                {
                    name = "Pair_2",
                    protocol = "ModbusTCP",
                    client_ip = "10.0.1.10",
                    server_ip = "10.0.1.21",
                    client_protocol_address_id = (int?)null,
                    server_protocol_address_id = (int?)1,
                    tag_mapping_csv = "pair2_tags.csv"
                }
            }
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifestObj));

        var fakeSink = new FakeDataSink();
        var fakeSource = new FakeFrameSource([]);
        var infraFactory = new FakeInfraFactory(fakeSink, fakeSource, null);

        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();
        services.AddSingleton<IAnalysisInfrastructureFactory>(infraFactory);
        var sp = services.BuildServiceProvider();

        var runner = sp.GetRequiredService<IAnalysisRunner>();
        var options = new AnalysisOptions(
            ManifestPath: manifestPath,
            DbConnectionString: "Host=localhost;Database=test");

        using var progressWriter = new StringWriter();
        await runner.RunAnalysisAsync(options, progressWriter);

        string output = progressWriter.ToString();
        int startingIdx = output.IndexOf("Starting analysis session 'SAT_Milestones_Run'", StringComparison.Ordinal);
        int dissectingIdx = output.IndexOf("Initialized session with 2 device pair(s) and 3 tag(s). Dissecting packets...", StringComparison.Ordinal);
        int finalizingIdx = output.IndexOf("Packet stream complete. Finalizing initial tag states in database...", StringComparison.Ordinal);
        int completedIdx = output.IndexOf("Session Completed: SAT_Milestones_Run", StringComparison.Ordinal);

        Assert.True(startingIdx >= 0, "Expected starting session line.");
        Assert.True(dissectingIdx > startingIdx, "Expected DissectingPackets milestone after starting session line.");
        Assert.True(finalizingIdx > dissectingIdx, "Expected FinalizingSession milestone after DissectingPackets milestone.");
        Assert.True(completedIdx > finalizingIdx, "Expected Session Completed banner after FinalizingSession milestone.");
    }

    [Fact]
    public async Task RunAnalysisAsync_ThrottlesDissectingPacketsProgressToFiveSecondIntervalsAndFormatsMetrics()
    {
        string pcapPath = Path.Combine(_tempDir, "throttled.pcap");
        await File.WriteAllBytesAsync(pcapPath, [0x01, 0x02]);

        string csvPath = Path.Combine(_tempDir, "throttled_tags.csv");
        string csvContent = """
            Protocol,Address,TagName,DataType,Endianness,ScaleMultiplier,ScaleOffset,Units,Description
            ModbusTCP,HR:40001,Bus_Volts_A,UINT16,,0.1,0.0,kV,Phase A Voltage
            """;
        await File.WriteAllTextAsync(csvPath, csvContent);

        string manifestPath = Path.Combine(_tempDir, "manifest_throttled.json");
        var manifestObj = new
        {
            session_name = "SAT_Throttled_Run",
            pcap_file = "throttled.pcap",
            timeout_threshold_ms = 1000,
            store_unmapped_registers = true,
            device_pairs = new[]
            {
                new
                {
                    name = "RTAC_to_Relay",
                    protocol = "ModbusTCP",
                    client_ip = "10.0.1.10",
                    server_ip = "10.0.1.20",
                    client_protocol_address_id = (int?)null,
                    server_protocol_address_id = (int?)1,
                    tag_mapping_csv = "throttled_tags.csv"
                }
            }
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifestObj));

        var clientIp = IPAddress.Parse("10.0.1.10");
        var serverIp = IPAddress.Parse("10.0.1.20");
        var unmatchedIp = IPAddress.Parse("192.168.1.99");
        var captureBase = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

        var frames = new List<DissectedFrame>
        {
            // Frame 1: unmatched at +2s wall-clock (suppressed)
            new(1, captureBase.AddSeconds(1), unmatchedIp, 50000, serverIp, 502, ProtocolType.ModbusTcp, [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03]),
            // Frame 2: matched request TxId=1 at +5s wall-clock (emits [00:05])
            new(2, captureBase.AddSeconds(5), clientIp, 50000, serverIp, 502, ProtocolType.ModbusTcp, [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01]),
            // Frame 3: matched response TxId=1 HR:40001 at +8s wall-clock (suppressed: 3s < 5s)
            new(3, captureBase.AddSeconds(6), serverIp, 502, clientIp, 50000, ProtocolType.ModbusTcp, [0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x05, 0x64]),
            // Frame 4: matched request TxId=2 (unmapped HR:40101) at +10s wall-clock (emits [00:10])
            new(4, captureBase.AddSeconds(10), clientIp, 50000, serverIp, 502, ProtocolType.ModbusTcp, [0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x01]),
            // Frame 5: matched response TxId=2 (unmapped) 50ms after Frame 4 at +1h05m00s wall-clock (emits [01:05:00])
            new(5, captureBase.AddSeconds(10).AddMilliseconds(50), serverIp, 502, clientIp, 50000, ProtocolType.ModbusTcp, [0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x27, 0x0F])
        };

        var wallIncrementsByFrame = new Dictionary<long, TimeSpan>
        {
            [1] = TimeSpan.FromSeconds(2),
            [2] = TimeSpan.FromSeconds(3),
            [3] = TimeSpan.FromSeconds(3),
            [4] = TimeSpan.FromSeconds(2),
            [5] = TimeSpan.FromHours(1) + TimeSpan.FromMinutes(4) + TimeSpan.FromSeconds(50)
        };

        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2026, 10, 26, 12, 0, 0, TimeSpan.Zero));
        var fakeSink = new FakeDataSink();
        var fakeSource = new FakeFrameSource(frames, frame => fakeTime.Advance(wallIncrementsByFrame[frame.FrameNumber]));
        var infraFactory = new FakeInfraFactory(fakeSink, fakeSource, null);

        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();
        services.AddSingleton<IAnalysisInfrastructureFactory>(infraFactory);
        services.AddSingleton<TimeProvider>(fakeTime);
        var sp = services.BuildServiceProvider();

        var runner = sp.GetRequiredService<IAnalysisRunner>();
        var options = new AnalysisOptions(
            ManifestPath: manifestPath,
            DbConnectionString: "Host=localhost;Database=test");

        using var progressWriter = new StringWriter();
        await runner.RunAnalysisAsync(options, progressWriter);

        var lines = progressWriter
            .ToString()
            .Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);

        var statusLines = lines.Where(l => l.StartsWith("  [", StringComparison.Ordinal)).ToArray();
        Assert.Equal(
            [
                "  [00:05] Frames: 2 (1 matched) | Tx: 0 | Records: 0 | Capture time: 2026-10-26 12:00:05 UTC",
                "  [00:10] Frames: 4 (3 matched) | Tx: 1 | Records: 1 | Capture time: 2026-10-26 12:00:10 UTC",
                "  [01:05:00] Frames: 5 (4 matched) | Tx: 2 | Records: 2 | Capture time: 2026-10-26 12:00:10 UTC"
            ],
            statusLines);

        int dissectingIdx = Array.IndexOf(lines, "Initialized session with 1 device pair(s) and 1 tag(s). Dissecting packets...");
        int firstStatusIdx = Array.IndexOf(lines, statusLines[0]);
        int lastStatusIdx = Array.IndexOf(lines, statusLines[^1]);
        int finalizingIdx = Array.IndexOf(lines, "Packet stream complete. Finalizing initial tag states in database...");

        Assert.True(dissectingIdx >= 0);
        Assert.True(firstStatusIdx > dissectingIdx);
        Assert.True(finalizingIdx > lastStatusIdx);
    }

    [Fact]
    public async Task RunAnalysisAsync_FormatsLargeProgressCountersWithThousandsSeparators()
    {
        string pcapPath = Path.Combine(_tempDir, "large_counts.pcap");
        await File.WriteAllBytesAsync(pcapPath, [0x01, 0x02]);

        string manifestPath = Path.Combine(_tempDir, "manifest_large.json");
        var manifestObj = new
        {
            session_name = "SAT_Large_Counts",
            pcap_file = "large_counts.pcap",
            timeout_threshold_ms = 1000,
            store_unmapped_registers = false,
            device_pairs = new[]
            {
                new
                {
                    name = "ModbusPair",
                    protocol = "ModbusTCP",
                    client_ip = "10.0.1.10",
                    server_ip = "10.0.1.20",
                    client_protocol_address_id = (int?)null,
                    server_protocol_address_id = (int?)1,
                    tag_mapping_csv = (string?)null
                }
            }
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifestObj));

        var unmatchedIp = IPAddress.Parse("192.168.1.99");
        var serverIp = IPAddress.Parse("10.0.1.20");
        var captureBase = new DateTime(2026, 10, 26, 15, 0, 0, DateTimeKind.Utc);
        var frames = Enumerable.Range(1, 1000)
            .Select(i => new DissectedFrame(
                FrameNumber: i,
                TimestampUtc: captureBase.AddSeconds(i),
                SourceIp: unmatchedIp,
                SourcePort: 50000,
                DestIp: serverIp,
                DestPort: 502,
                ProtocolName: ProtocolType.ModbusTcp,
                RawApplicationPayload: [0x00, 0x01]))
            .ToList();

        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2026, 10, 26, 15, 0, 0, TimeSpan.Zero));
        var fakeSource = new FakeFrameSource(frames, frame =>
        {
            if (frame.FrameNumber == 1000)
            {
                fakeTime.Advance(TimeSpan.FromSeconds(5));
            }
        });

        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();
        services.AddSingleton<IAnalysisInfrastructureFactory>(new FakeInfraFactory(new FakeDataSink(), fakeSource, null));
        services.AddSingleton<TimeProvider>(fakeTime);
        var sp = services.BuildServiceProvider();

        var runner = sp.GetRequiredService<IAnalysisRunner>();
        var options = new AnalysisOptions(manifestPath, "Host=localhost;Database=test");

        using var progressWriter = new StringWriter();
        await runner.RunAnalysisAsync(options, progressWriter);

        Assert.Contains(
            "  [00:05] Frames: 1,000 (0 matched) | Tx: 0 | Records: 0 | Capture time: 2026-10-26 15:16:40 UTC",
            progressWriter.ToString());
    }

    private sealed class FakeTimeProvider(DateTimeOffset initialUtcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = initialUtcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan delta) => _utcNow = _utcNow.Add(delta);
    }

    private sealed class FakeInfraFactory(
        IDataSink sink,
        IFrameSource source,
        IPcapArchiveStorage? archiver) : IAnalysisInfrastructureFactory
    {
        public IDataSink CreateDataSink(string connectionString, int batchSize) => sink;
        public IFrameSource CreateFrameSource(AnalysisOptions options) => source;
        public IPcapArchiveStorage? CreateArchiver(AnalysisOptions options) => archiver;
    }

    private sealed class FakeFrameSource(
        IReadOnlyList<DissectedFrame> frames,
        Action<DissectedFrame>? onBeforeYield = null) : IFrameSource
    {
        public async IAsyncEnumerable<DissectedFrame> ReadFramesAsync(
            string pcapFilePath,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            foreach (var f in frames)
            {
                await Task.Yield();
                onBeforeYield?.Invoke(f);
                yield return f;
            }
        }
    }

    private sealed class FakeDataSink : IDataSink
    {
        public TestSession? InitializedSession { get; private set; }
        public List<ProtocolTransactionRecord> Transactions { get; } = [];
        public List<ExtractedDataPointRecord> DataPoints { get; } = [];
        public List<CapturedCommandEventRecord> CommandEvents { get; } = [];
        public List<ModbusUnmappedRecord> UnmappedRegisters { get; } = [];
        public List<TraceSpanRecord> TraceSpans { get; } = [];
        public SessionStatus? CompletedStatus { get; private set; }

        public Task InitializeSessionAsync(TestSession session, IEnumerable<DeviceEndpointPair> pairs, IEnumerable<TagDefinition> tags, CancellationToken ct)
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
            TraceSpans.AddRange(batch.TraceSpans);
            return Task.CompletedTask;
        }

        public Task UpdateTagInitialStatesAsync(Guid sessionId, CancellationToken ct) => Task.CompletedTask;

        public Task CompleteSessionAsync(Guid sessionId, SessionStatus status, CancellationToken ct)
        {
            CompletedStatus = status;
            return Task.CompletedTask;
        }
    }

    private sealed class FakePcapArchiver : IPcapArchiveStorage
    {
        public Task<string> ArchivePcapAsync(Guid sessionId, string pcapFilePath, CancellationToken ct)
        {
            return Task.FromResult("captures/archived_" + Path.GetFileName(pcapFilePath));
        }
    }
}
