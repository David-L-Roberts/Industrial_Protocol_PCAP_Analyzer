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
            Protocol,Address,TagName,DataType,ScaleMultiplier,ScaleOffset,Units,Description
            ModbusTCP,HR:40001,Bus_Volts_A,UINT16,0.1,0.0,kV,Phase A Bus Voltage
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
        Assert.Equal(SessionStatus.Completed, fakeSink.CompletedStatus);

        string outputText = progressWriter.ToString();
        Assert.Contains("FAT_Substation_1", outputText);
        Assert.Contains("Total frames processed: 2", outputText);
        Assert.Contains("Transactions: 1", outputText);
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

    private sealed class FakeInfraFactory(
        IDataSink sink,
        IFrameSource source,
        IPcapArchiveStorage? archiver) : IAnalysisInfrastructureFactory
    {
        public IDataSink CreateDataSink(string connectionString, int batchSize) => sink;
        public IFrameSource CreateFrameSource(AnalysisOptions options) => source;
        public IPcapArchiveStorage? CreateArchiver(AnalysisOptions options) => archiver;
    }

    private sealed class FakeFrameSource(IReadOnlyList<DissectedFrame> frames) : IFrameSource
    {
        public async IAsyncEnumerable<DissectedFrame> ReadFramesAsync(
            string pcapFilePath,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            foreach (var f in frames)
            {
                await Task.Yield();
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
