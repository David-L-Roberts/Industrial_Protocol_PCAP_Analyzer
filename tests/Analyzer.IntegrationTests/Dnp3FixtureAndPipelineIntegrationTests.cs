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

public class Dnp3FixtureAndPipelineIntegrationTests : IAsyncLifetime
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

    private static string GetDnp3FixtureDirectory()
    {
        var repoRoot = IntegrationTestConfig.FindRepoRoot(AppContext.BaseDirectory)
            ?? throw new InvalidOperationException("Could not locate repository root.");

        return Path.Combine(repoRoot, "tests", "Analyzer.IntegrationTests", "Fixtures", "Dnp3");
    }

    [Fact]
    public async Task Dnp3FixtureFiles_ExistAndParseValidManifestAndTagMappings()
    {
        var fixtureDir = GetDnp3FixtureDirectory();
        var manifestPath = Path.Combine(fixtureDir, "manifest.json");
        var tagsCsvPath = Path.Combine(fixtureDir, "tags.csv");
        var pcapPath = Path.Combine(fixtureDir, "Dnp3SampleCapture.pcap");

        Assert.True(File.Exists(manifestPath), $"Expected DNP3 manifest fixture at '{manifestPath}'.");
        Assert.True(File.Exists(tagsCsvPath), $"Expected DNP3 tags CSV fixture at '{tagsCsvPath}'.");
        Assert.True(File.Exists(pcapPath), $"Expected DNP3 capture fixture at '{pcapPath}'.");

        var manifestParser = new ManifestParser();
        var parsedManifest = await manifestParser.ParseFileAsync(manifestPath);

        Assert.Equal("Dnp3SampleCapture.pcap", parsedManifest.Session.PcapFileName);
        Assert.NotEmpty(parsedManifest.DevicePairs);

        var pairWithCsv = Assert.Single(parsedManifest.DevicePairs);
        Assert.Equal(ProtocolType.Dnp3, pairWithCsv.DevicePair.Protocol);
        Assert.Equal(IPAddress.Parse("127.0.0.1"), pairWithCsv.DevicePair.ClientIp);
        Assert.Equal(IPAddress.Parse("127.0.0.1"), pairWithCsv.DevicePair.ServerIp);
        Assert.Equal(4, pairWithCsv.DevicePair.ClientProtocolAddressId);
        Assert.Equal(3, pairWithCsv.DevicePair.ServerProtocolAddressId);
        Assert.Equal("tags.csv", pairWithCsv.TagMappingCsvPath);

        var csvLoader = new CsvTagMappingLoader();
        var tags = await csvLoader.LoadFileAsync(
            tagsCsvPath,
            pairWithCsv.DevicePair.Id,
            pairWithCsv.DevicePair.Protocol);

        Assert.NotEmpty(tags);
        Assert.Contains(tags, t => t.ProtocolAddress == ProtocolAddress.Parse("G12V01:Idx1") && t.DataType == TagDataType.Bool);
    }

    [IntegrationFact]
    [IntegrationTrait]
    public async Task TSharkStreamingFrameSource_DissectsRealDnp3PcapIntoDnp3Frames()
    {
        var pcapPath = Path.Combine(GetDnp3FixtureDirectory(), "Dnp3SampleCapture.pcap");
        var frameSource = new TSharkStreamingFrameSource(tsharkExecutablePath: _config.TSharkExecutablePath);

        var frames = new List<DissectedFrame>();
        await foreach (var frame in frameSource.ReadFramesAsync(pcapPath))
        {
            frames.Add(frame);
        }

        Assert.Equal(4, frames.Count);
        Assert.All(frames, frame =>
        {
            Assert.Equal(ProtocolType.Dnp3, frame.ProtocolName);
            Assert.Equal(DateTimeKind.Utc, frame.TimestampUtc.Kind);
            Assert.True(frame.TimestampUtc > DateTime.UnixEpoch);
            Assert.Equal(IPAddress.Parse("127.0.0.1"), frame.SourceIp);
            Assert.Equal(IPAddress.Parse("127.0.0.1"), frame.DestIp);
            Assert.True(frame.SourcePort > 0);
            Assert.Equal(20000, frame.DestPort);
            Assert.True(frame.RawApplicationPayload.Length >= 10);
            Assert.Equal(0x05, frame.RawApplicationPayload[0]);
            Assert.Equal(0x64, frame.RawApplicationPayload[1]);
            Assert.NotNull(frame.DissectedFields);
            Assert.Equal("4", frame.DissectedFields!["dnp3.src"]);
            Assert.Equal("3", frame.DissectedFields["dnp3.dst"]);
            Assert.True(frame.DissectedFields.ContainsKey("dnp3.al.func"));
        });

        Assert.Equal([4L, 12L, 16L, 24L], frames.Select(f => f.FrameNumber).ToArray());

        var selectFrame = frames[1];
        Assert.Equal(12L, selectFrame.FrameNumber);
        Assert.Equal(64825, selectFrame.SourcePort);
        Assert.Equal("3", selectFrame.DissectedFields!["dnp3.al.func"]);
        Assert.Equal(
            Convert.FromHexString("05641AC403000400C9B7C1C1030C0128010001000301640000007B5E6400000000005B"),
            selectFrame.RawApplicationPayload);

        var operateFrame = frames[2];
        Assert.Equal(16L, operateFrame.FrameNumber);
        Assert.Equal(64825, operateFrame.SourcePort);
        Assert.Equal("4", operateFrame.DissectedFields!["dnp3.al.func"]);
        Assert.Equal(
            Convert.FromHexString("05641AC403000400C9B7C1C2040C01280100010003016400000083546400000000005B"),
            operateFrame.RawApplicationPayload);
    }

    [IntegrationFact]
    [IntegrationTrait]
    public async Task AnalysisRunner_IngestsRealDnp3FixtureIntoTimescaleDbAndMinio()
    {
        var fixtureDir = GetDnp3FixtureDirectory();
        var manifestPath = Path.Combine(fixtureDir, "manifest.json");
        var pcapPath = Path.Combine(fixtureDir, "Dnp3SampleCapture.pcap");
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

        Assert.Equal(4, summary.TotalFramesProcessed);
        Assert.Equal(4, summary.MatchedFramesProcessed);
        Assert.Equal(2, summary.TotalTransactions);
        Assert.Equal(0, summary.SuccessTransactions);
        Assert.Equal(2, summary.ErrorTransactions);
        Assert.Equal(2, summary.TimeoutTransactions);
        Assert.Equal(2, summary.DataPointsPersisted);
        Assert.Equal(2, summary.CommandEventsPersisted);
        Assert.Equal(0, summary.UnmappedRegistersPersisted);

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
            Assert.Equal("Dnp3SampleCapture.pcap", reader.GetString(2));
            Assert.False(reader.GetBoolean(3));
        }

        await using (var pairCmd = new NpgsqlCommand(
            "SELECT protocol, host(client_ip), host(server_ip), client_protocol_address_id, server_protocol_address_id FROM device_pairs WHERE session_id = @id;",
            conn))
        {
            pairCmd.Parameters.AddWithValue("id", summary.SessionId);
            await using var reader = await pairCmd.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync(), "Expected device_pairs row to exist.");
            Assert.Equal("DNP3", reader.GetString(0));
            Assert.Equal("127.0.0.1", reader.GetString(1));
            Assert.Equal("127.0.0.1", reader.GetString(2));
            Assert.Equal(4, reader.GetInt32(3));
            Assert.Equal(3, reader.GetInt32(4));
            Assert.False(await reader.ReadAsync());
        }

        // Verify tag definition has T0 initial state populated from the first CROB command
        await using (var tagCmd = new NpgsqlCommand(
            """
            SELECT t.protocol_address, t.initial_boolean_value, t.initial_raw_hex
            FROM tag_definitions t
            JOIN device_pairs dp ON dp.id = t.device_pair_id
            WHERE dp.session_id = @id;
            """,
            conn))
        {
            tagCmd.Parameters.AddWithValue("id", summary.SessionId);
            await using var reader = await tagCmd.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync(), "Expected tag_definitions row to exist.");
            Assert.Equal("G12V01:Idx1", reader.GetString(0));
            Assert.False(reader.IsDBNull(1));
            Assert.True(reader.GetBoolean(1));
            Assert.Equal("0301640000006400000000", reader.GetString(2));
            Assert.False(await reader.ReadAsync());
        }

        await using (var redCmd = new NpgsqlCommand(
            """
            SELECT frame_number, transaction_id, function_code, is_error, error_type, status_code
            FROM red_transactions
            WHERE session_id = @id
            ORDER BY frame_number ASC;
            """,
            conn))
        {
            redCmd.Parameters.AddWithValue("id", summary.SessionId);
            await using var reader = await redCmd.ExecuteReaderAsync();
            var txs = new List<(long FrameNumber, string TransactionId, short FunctionCode, bool IsError, string ErrorType, string StatusCode)>();
            while (await reader.ReadAsync())
            {
                txs.Add((
                    reader.GetInt64(0),
                    reader.GetString(1),
                    reader.GetInt16(2),
                    reader.GetBoolean(3),
                    reader.GetString(4),
                    reader.GetString(5)));
            }

            Assert.Equal(2, txs.Count);
            Assert.Equal((16L, "2", (short)4, true, "TIMEOUT_AT_EOF", "TIMEOUT_AT_EOF"), txs[0]);
            Assert.Equal((24L, "1", (short)1, true, "TIMEOUT_AT_EOF", "TIMEOUT_AT_EOF"), txs[1]);
        }

        await using (var tvCmd = new NpgsqlCommand(
            """
            SELECT frame_number, boolean_value, raw_hex, quality_flags, is_value_change
            FROM tag_values
            WHERE session_id = @id
            ORDER BY frame_number ASC;
            """,
            conn))
        {
            tvCmd.Parameters.AddWithValue("id", summary.SessionId);
            await using var reader = await tvCmd.ExecuteReaderAsync();
            var points = new List<(long FrameNumber, bool? BoolVal, string RawHex, string? Quality, bool IsValueChange)>();
            while (await reader.ReadAsync())
            {
                points.Add((
                    reader.GetInt64(0),
                    reader.IsDBNull(1) ? null : reader.GetBoolean(1),
                    reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.GetBoolean(4)));
            }

            Assert.Equal(2, points.Count);
            Assert.Equal((12L, true, "0301640000006400000000", "ONLINE", true), points[0]);
            Assert.Equal((16L, true, "0301640000006400000000", "ONLINE", false), points[1]);
        }

        await using (var cmdEventsCmd = new NpgsqlCommand(
            """
            SELECT frame_number, protocol, function_code, command_type, target_address, control_action, command_count, pulse_on_ms, pulse_off_ms, unscaled_command_value, raw_pdu_bytes
            FROM captured_command_events
            WHERE session_id = @id
            ORDER BY frame_number ASC;
            """,
            conn))
        {
            cmdEventsCmd.Parameters.AddWithValue("id", summary.SessionId);
            await using var reader = await cmdEventsCmd.ExecuteReaderAsync();
            var events = new List<(
                long FrameNumber,
                string Protocol,
                short FunctionCode,
                string CommandType,
                string TargetAddress,
                string? ControlAction,
                short? CommandCount,
                long? PulseOnMs,
                long? PulseOffMs,
                double? Value,
                byte[] RawPduBytes)>();

            while (await reader.ReadAsync())
            {
                events.Add((
                    reader.GetInt64(0),
                    reader.GetString(1),
                    reader.GetInt16(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetInt16(6),
                    reader.IsDBNull(7) ? null : reader.GetInt64(7),
                    reader.IsDBNull(8) ? null : reader.GetInt64(8),
                    reader.IsDBNull(9) ? null : reader.GetDouble(9),
                    (byte[])reader.GetValue(10)));
            }

            Assert.Equal(2, events.Count);

            var selectEvent = events[0];
            Assert.Equal(12L, selectEvent.FrameNumber);
            Assert.Equal("DNP3", selectEvent.Protocol);
            Assert.Equal((short)3, selectEvent.FunctionCode);
            Assert.Equal("DNP3_CROB_SELECT", selectEvent.CommandType);
            Assert.Equal("G12V01:Idx1", selectEvent.TargetAddress);
            Assert.Equal("LATCH_ON", selectEvent.ControlAction);
            Assert.Equal((short)1, selectEvent.CommandCount);
            Assert.Equal(100L, selectEvent.PulseOnMs);
            Assert.Equal(100L, selectEvent.PulseOffMs);
            Assert.Equal(1.0, selectEvent.Value);
            Assert.Equal(
                Convert.FromHexString("05641AC403000400C9B7C1C1030C0128010001000301640000007B5E6400000000005B"),
                selectEvent.RawPduBytes);

            var operateEvent = events[1];
            Assert.Equal(16L, operateEvent.FrameNumber);
            Assert.Equal("DNP3", operateEvent.Protocol);
            Assert.Equal((short)4, operateEvent.FunctionCode);
            Assert.Equal("DNP3_CROB_OPERATE", operateEvent.CommandType);
            Assert.Equal("G12V01:Idx1", operateEvent.TargetAddress);
            Assert.Equal("LATCH_ON", operateEvent.ControlAction);
            Assert.Equal((short)1, operateEvent.CommandCount);
            Assert.Equal(100L, operateEvent.PulseOnMs);
            Assert.Equal(100L, operateEvent.PulseOffMs);
            Assert.Equal(1.0, operateEvent.Value);
            Assert.Equal(
                Convert.FromHexString("05641AC403000400C9B7C1C2040C01280100010003016400000083546400000000005B"),
                operateEvent.RawPduBytes);
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


