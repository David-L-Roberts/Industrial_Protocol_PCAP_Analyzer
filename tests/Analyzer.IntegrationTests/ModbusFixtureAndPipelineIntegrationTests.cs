using System.Net;
using Analyzer.Cli;
using Analyzer.Core.Domain;
using Analyzer.Infrastructure.Dissection;
using Analyzer.Infrastructure.Mapping;
using Analyzer.Infrastructure.Storage;
using Analyzer.IntegrationTests.Attributes;
using Analyzer.IntegrationTests.Configuration;
using Analyzer.IntegrationTests.Persistence;
using Analyzer.IntegrationTests.Storage;
using Microsoft.Extensions.DependencyInjection;
using Minio;
using Minio.DataModel.Args;
using Minio.Exceptions;
using Npgsql;

namespace Analyzer.IntegrationTests;

public class ModbusFixtureAndPipelineIntegrationTests : IAsyncLifetime
{
    private readonly IntegrationTestConfig _config = IntegrationTestConfig.Load();
    private readonly List<Guid> _createdSessionIds = [];
    private readonly List<string> _archivedObjectKeys = [];

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        if (_createdSessionIds.Count > 0)
        {
            await using var dataSource = NpgsqlDataSource.Create(_config.TimescaleConnectionString);
            await TimescaleTestDatabaseCleaner.CleanupSessionsIfEnabledAsync(
                dataSource,
                _createdSessionIds,
                _config.KeepTestData);
        }

        if (_archivedObjectKeys.Count > 0)
        {
            using var minioClient = MinioPcapStorageService.BuildMinioClient(_config.MinioOptions);
            await MinioTestObjectCleaner.CleanupObjectsIfEnabledAsync(
                minioClient,
                _config.MinioOptions.BucketName,
                _archivedObjectKeys,
                _config.KeepTestData);
        }
    }

    private static string GetModbusFixtureDirectory()
    {
        var repoRoot = IntegrationTestConfig.FindRepoRoot(AppContext.BaseDirectory)
            ?? throw new InvalidOperationException("Could not locate repository root.");

        return Path.Combine(repoRoot, "tests", "Analyzer.IntegrationTests", "Fixtures", "Modbus");
    }

    [Fact]
    public async Task ModbusFixtureFiles_ExistAndParseValidManifestAndTagMappings()
    {
        var fixtureDir = GetModbusFixtureDirectory();
        var manifestPath = Path.Combine(fixtureDir, "manifest.json");
        var tagsCsvPath = Path.Combine(fixtureDir, "tags.csv");
        var pcapPath = Path.Combine(fixtureDir, "ModbusSampleCapture.pcapng");

        Assert.True(File.Exists(manifestPath), $"Expected Modbus manifest fixture at '{manifestPath}'.");
        Assert.True(File.Exists(tagsCsvPath), $"Expected Modbus tags CSV fixture at '{tagsCsvPath}'.");
        Assert.True(File.Exists(pcapPath), $"Expected Modbus capture fixture at '{pcapPath}'.");

        var manifestParser = new ManifestParser();
        var parsedManifest = await manifestParser.ParseFileAsync(manifestPath);

        Assert.Equal("ModbusSampleCapture.pcapng", parsedManifest.Session.PcapFileName);
        Assert.True(parsedManifest.Session.StoreUnmappedRegisters);
        Assert.NotEmpty(parsedManifest.DevicePairs);

        var pairWithCsv = Assert.Single(parsedManifest.DevicePairs, p => !string.IsNullOrWhiteSpace(p.TagMappingCsvPath));
        Assert.Equal(ProtocolType.ModbusTcp, pairWithCsv.DevicePair.Protocol);
        Assert.Equal("tags.csv", pairWithCsv.TagMappingCsvPath);

        var csvLoader = new CsvTagMappingLoader();
        var tags = await csvLoader.LoadFileAsync(
            tagsCsvPath,
            pairWithCsv.DevicePair.Id,
            pairWithCsv.DevicePair.Protocol);

        Assert.NotEmpty(tags);
        Assert.Contains(tags, t => t.ProtocolAddress == ProtocolAddress.Parse("HR:10195") && t.DataType == TagDataType.Float32Swapped);
        Assert.Contains(tags, t => t.ProtocolAddress == ProtocolAddress.Parse("HR:10194") && t.DataType == TagDataType.UInt16);
        Assert.Contains(tags, t => t.ProtocolAddress == ProtocolAddress.Parse("IR:8500") && t.DataType == TagDataType.UInt16);
    }

    [IntegrationFact]
    [IntegrationTrait]
    public async Task TSharkStreamingFrameSource_DissectsRealModbusPcapngIntoModbusTcpFrames()
    {
        var pcapPath = Path.Combine(GetModbusFixtureDirectory(), "ModbusSampleCapture.pcapng");
        var frameSource = new TSharkStreamingFrameSource(tsharkExecutablePath: _config.TSharkExecutablePath);

        var frames = new List<DissectedFrame>();
        await foreach (var frame in frameSource.ReadFramesAsync(pcapPath))
        {
            frames.Add(frame);
        }

        Assert.NotEmpty(frames);
        Assert.All(frames, frame =>
        {
            Assert.Equal(ProtocolType.ModbusTcp, frame.ProtocolName);
            Assert.Equal(DateTimeKind.Utc, frame.TimestampUtc.Kind);
            Assert.True(frame.TimestampUtc > DateTime.UnixEpoch);
            Assert.True(frame.SourcePort > 0);
            Assert.True(frame.DestPort > 0);
            Assert.True(frame.RawApplicationPayload.Length >= 8);
            Assert.NotNull(frame.DissectedFields);
            Assert.True(frame.DissectedFields!.ContainsKey("mbtcp.unit_id"));
            Assert.True(frame.DissectedFields.ContainsKey("modbus.func_code"));
        });

        var firstFrame = frames[0];
        Assert.Equal(1L, firstFrame.FrameNumber);
        Assert.Equal(IPAddress.Parse("10.20.188.9"), firstFrame.SourceIp);
        Assert.Equal(52875, firstFrame.SourcePort);
        Assert.Equal(IPAddress.Parse("10.20.188.2"), firstFrame.DestIp);
        Assert.Equal(502, firstFrame.DestPort);
        Assert.Equal(
            new byte[] { 0x60, 0xE2, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x34, 0x00, 0x00, 0x1E },
            firstFrame.RawApplicationPayload);
    }

    [IntegrationFact]
    [IntegrationTrait]
    public async Task AnalysisRunner_IngestsRealModbusFixtureIntoTimescaleDbAndMinio()
    {
        var fixtureDir = GetModbusFixtureDirectory();
        var manifestPath = Path.Combine(fixtureDir, "manifest.json");
        var pcapPath = Path.Combine(fixtureDir, "ModbusSampleCapture.pcapng");
        var expectedPcapBytes = new FileInfo(pcapPath).Length;

        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();
        await using var serviceProvider = services.BuildServiceProvider();
        var runner = serviceProvider.GetRequiredService<IAnalysisRunner>();

        var options = new AnalysisOptions(
            ManifestPath: manifestPath,
            DbConnectionString: _config.TimescaleConnectionString,
            S3Endpoint: _config.MinioOptions.Endpoint,
            S3Bucket: _config.MinioOptions.BucketName,
            S3AccessKey: _config.MinioOptions.AccessKey,
            S3SecretKey: _config.MinioOptions.SecretKey,
            S3WithSsl: _config.MinioOptions.WithSsl,
            TSharkPath: _config.TSharkExecutablePath);

        using var progressWriter = new StringWriter();
        var summary = await runner.RunAnalysisAsync(options, progressWriter);

        Assert.NotEqual(Guid.Empty, summary.SessionId);
        _createdSessionIds.Add(summary.SessionId);

        Assert.False(string.IsNullOrWhiteSpace(summary.S3ObjectKey));
        _archivedObjectKeys.Add(summary.S3ObjectKey!);

        Assert.True(summary.TotalFramesProcessed > 0);
        Assert.True(summary.MatchedFramesProcessed > 0);
        Assert.True(summary.TotalTransactions > 0);
        Assert.True(summary.SuccessTransactions > 0);
        Assert.Equal(0, summary.ErrorTransactions);
        Assert.True(summary.DataPointsPersisted > 0);
        Assert.True(summary.CommandEventsPersisted > 0);
        Assert.True(summary.UnmappedRegistersPersisted > 0);

        // Verify PCAP object archived in MinIO
        using var minioClient = MinioPcapStorageService.BuildMinioClient(_config.MinioOptions);
        var objectStat = await minioClient.StatObjectAsync(
            new StatObjectArgs()
                .WithBucket(_config.MinioOptions.BucketName)
                .WithObject(summary.S3ObjectKey));
        Assert.Equal(expectedPcapBytes, objectStat.Size);

        // Verify persisted records in TimescaleDB
        await using var conn = new NpgsqlConnection(_config.TimescaleConnectionString);
        await conn.OpenAsync();

        await using (var sessionCmd = new NpgsqlCommand(
            "SELECT status, s3_object_key, pcap_file_name, store_unmapped_registers FROM test_sessions WHERE id = @id;",
            conn))
        {
            sessionCmd.Parameters.AddWithValue("id", summary.SessionId);
            await using var reader = await sessionCmd.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync(), "Expected test_sessions row to exist.");
            Assert.Equal("COMPLETED", reader.GetString(0));
            Assert.Equal(summary.S3ObjectKey, reader.GetString(1));
            Assert.Equal("ModbusSampleCapture.pcapng", reader.GetString(2));
            Assert.True(reader.GetBoolean(3));
        }

        await using (var pairCmd = new NpgsqlCommand(
            "SELECT COUNT(*) FROM device_pairs WHERE session_id = @id;",
            conn))
        {
            pairCmd.Parameters.AddWithValue("id", summary.SessionId);
            Assert.Equal(2L, Convert.ToInt64(await pairCmd.ExecuteScalarAsync()));
        }

        // Verify all 4 tag definitions have T0 initial states populated
        await using (var tagCmd = new NpgsqlCommand(
            """
            SELECT t.protocol_address, t.initial_unscaled_numeric_value, t.initial_scaled_numeric_value, t.initial_raw_hex
            FROM tag_definitions t
            JOIN device_pairs dp ON dp.id = t.device_pair_id
            WHERE dp.session_id = @id;
            """,
            conn))
        {
            tagCmd.Parameters.AddWithValue("id", summary.SessionId);
            await using var reader = await tagCmd.ExecuteReaderAsync();
            var initialStatesByAddress = new Dictionary<string, (double? Unscaled, double? Scaled, string? RawHex)>(StringComparer.OrdinalIgnoreCase);
            while (await reader.ReadAsync())
            {
                var addr = reader.GetString(0);
                double? unscaled = reader.IsDBNull(1) ? null : reader.GetDouble(1);
                double? scaled = reader.IsDBNull(2) ? null : reader.GetDouble(2);
                string? rawHex = reader.IsDBNull(3) ? null : reader.GetString(3);
                initialStatesByAddress[addr] = (unscaled, scaled, rawHex);
            }

            Assert.Equal(4, initialStatesByAddress.Count);
            Assert.All(initialStatesByAddress.Values, state =>
            {
                Assert.NotNull(state.Unscaled);
                Assert.NotNull(state.Scaled);
                Assert.False(string.IsNullOrWhiteSpace(state.RawHex));
            });

            Assert.Equal(50.0, initialStatesByAddress["HR:10195"].Unscaled!.Value, precision: 3);
            Assert.Equal("00004248", initialStatesByAddress["HR:10195"].RawHex);
        }

        await using (var redCmd = new NpgsqlCommand(
            "SELECT COUNT(*) FROM red_transactions WHERE session_id = @id AND status_code = 'SUCCESS';",
            conn))
        {
            redCmd.Parameters.AddWithValue("id", summary.SessionId);
            Assert.Equal(summary.SuccessTransactions, Convert.ToInt64(await redCmd.ExecuteScalarAsync()));
        }

        await using (var tvCmd = new NpgsqlCommand(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE is_value_change = TRUE) FROM tag_values WHERE session_id = @id;",
            conn))
        {
            tvCmd.Parameters.AddWithValue("id", summary.SessionId);
            await using var reader = await tvCmd.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(summary.DataPointsPersisted, reader.GetInt64(0));
            Assert.True(reader.GetInt64(1) >= 4, "Expected at least 4 initial value-change rows in tag_values.");
        }

        await using (var cmdEventsCmd = new NpgsqlCommand(
            """
            SELECT command_type, target_address, unscaled_command_value, octet_length(raw_pdu_bytes)
            FROM captured_command_events
            WHERE session_id = @id
            ORDER BY frame_number ASC;
            """,
            conn))
        {
            cmdEventsCmd.Parameters.AddWithValue("id", summary.SessionId);
            await using var reader = await cmdEventsCmd.ExecuteReaderAsync();
            var events = new List<(string CommandType, string TargetAddress, double? Value, int PduLength)>();
            while (await reader.ReadAsync())
            {
                events.Add((
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetDouble(2),
                    reader.GetInt32(3)));
            }

            Assert.Equal(summary.CommandEventsPersisted, events.Count);
            Assert.Contains(events, e => e.CommandType == "MODBUS_WRITE_MULTI_REGS" && e.TargetAddress == "HR:10195" && e.Value == 50.0 && e.PduLength > 8);
            Assert.Contains(events, e => e.CommandType == "MODBUS_WRITE_SINGLE_REG" && e.TargetAddress == "HR:10194" && e.PduLength >= 12);
        }

        await using (var unmappedCmd = new NpgsqlCommand(
            "SELECT COUNT(*) FROM modbus_raw_unmapped WHERE session_id = @id;",
            conn))
        {
            unmappedCmd.Parameters.AddWithValue("id", summary.SessionId);
            Assert.Equal(summary.UnmappedRegistersPersisted, Convert.ToInt64(await unmappedCmd.ExecuteScalarAsync()));
        }

        if (!_config.KeepTestData)
        {
            await using var dataSource = NpgsqlDataSource.Create(_config.TimescaleConnectionString);
            await TimescaleTestDatabaseCleaner.CleanupSessionsIfEnabledAsync(
                dataSource,
                [summary.SessionId],
                keepTestData: false);
            _createdSessionIds.Remove(summary.SessionId);

            await MinioTestObjectCleaner.CleanupObjectsIfEnabledAsync(
                minioClient,
                _config.MinioOptions.BucketName,
                [summary.S3ObjectKey!],
                keepTestData: false);
            _archivedObjectKeys.Remove(summary.S3ObjectKey!);

            await using var verifyDeletedCmd = new NpgsqlCommand(
                "SELECT COUNT(*) FROM test_sessions WHERE id = @id;",
                conn);
            verifyDeletedCmd.Parameters.AddWithValue("id", summary.SessionId);
            Assert.Equal(0L, Convert.ToInt64(await verifyDeletedCmd.ExecuteScalarAsync()));

            await Assert.ThrowsAsync<ObjectNotFoundException>(() =>
                minioClient.StatObjectAsync(
                    new StatObjectArgs()
                        .WithBucket(_config.MinioOptions.BucketName)
                        .WithObject(summary.S3ObjectKey)));
        }
    }
}

