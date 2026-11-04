using System.Net;
using Analyzer.Core.Domain;
using Analyzer.Infrastructure.Persistence;
using Analyzer.IntegrationTests.Attributes;
using Analyzer.IntegrationTests.Configuration;
using Analyzer.IntegrationTests.Persistence;
using Npgsql;

namespace Analyzer.IntegrationTests;

[IntegrationTrait]
public class LiveTimescaleDbBatchSinkTests : IAsyncLifetime
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
    public async Task FullSessionLifecycle_PersistsMetadataHypertableBatchesT0InitialStatesAndStatusToTimescaleDb()
    {
        var sessionId = TrackSession(Guid.NewGuid());
        var pairId = Guid.NewGuid();
        var numericTagId = Guid.NewGuid();
        var boolTagId = Guid.NewGuid();
        var baseTime = new DateTime(2026, 10, 29, 12, 0, 0, DateTimeKind.Utc);

        await using var writer = new NpgsqlPostgresWriter(_dataSource);
        var sink = new TimescaleDbBatchSink(writer, batchSize: 2);

        var session = new TestSession(
            Id: sessionId,
            Name: "Live_Integration_Subst_1",
            PcapFileName: "substation1.pcapng",
            S3ObjectKey: $"captures/{sessionId:D}/substation1.pcapng",
            TimeoutThresholdMs: 2500,
            StoreUnmappedRegisters: true);

        var pair = new DeviceEndpointPair(
            Id: pairId,
            SessionId: sessionId,
            Name: "RTAC_To_Relay1",
            Protocol: ProtocolType.ModbusTcp,
            ClientIp: IPAddress.Parse("10.20.188.9"),
            ServerIp: IPAddress.Parse("10.20.188.25"),
            ClientProtocolAddressId: null,
            ServerProtocolAddressId: 247);

        var numericTag = new TagDefinition(
            Id: numericTagId,
            DevicePairId: pairId,
            TagName: "Feeder_Voltage_kV",
            ProtocolAddress: ProtocolAddress.Parse("HR:40001"),
            DataType: TagDataType.Float32Be,
            ScaleMultiplier: 0.1,
            ScaleOffset: 2.5,
            EngineeringUnits: "kV",
            Description: "Feeder Phase A Voltage");

        var boolTag = new TagDefinition(
            Id: boolTagId,
            DevicePairId: pairId,
            TagName: "Breaker_52A_Closed",
            ProtocolAddress: ProtocolAddress.Parse("COIL:00001"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: "Breaker Status");

        // 1. Initialize Session, DevicePairs, and TagDefinitions
        await sink.InitializeSessionAsync(session, [pair], [numericTag, boolTag], CancellationToken.None);

        await AssertSessionRowAsync(session, expectedWireStatus: "PROCESSING");
        await AssertDevicePairRowAsync(pair, expectedWireProtocol: "ModbusTCP");
        await AssertTagDefinitionMetadataAsync(numericTag, expectedWireDataType: "FLOAT32_BE");
        await AssertTagDefinitionMetadataAsync(boolTag, expectedWireDataType: "BOOL");

        // 2. Write Batch 1 across all four hypertables
        var tx1 = new ProtocolTransactionRecord(
            Timestamp: baseTime,
            SessionId: sessionId,
            DevicePairId: pairId,
            FrameNumber: 10,
            Direction: TrafficDirection.ServerToClient,
            TransactionId: "101",
            FunctionCode: 3,
            DurationMs: 14.25,
            IsError: false,
            ErrorType: TransactionErrorType.None,
            StatusCode: TransactionStatusCode.Success);

        var tx2 = new ProtocolTransactionRecord(
            Timestamp: baseTime.AddMilliseconds(50),
            SessionId: sessionId,
            DevicePairId: pairId,
            FrameNumber: 12,
            Direction: TrafficDirection.ServerToClient,
            TransactionId: "102",
            FunctionCode: 16,
            DurationMs: 28.5,
            IsError: true,
            ErrorType: TransactionErrorType.Exception,
            StatusCode: TransactionStatusCode.ModbusEx02);

        var dp1Numeric = new ExtractedDataPointRecord(
            PacketTimestamp: baseTime,
            EventTimestamp: baseTime.AddMilliseconds(-5),
            SessionId: sessionId,
            TagId: numericTagId,
            FrameNumber: 10,
            Direction: TrafficDirection.ServerToClient,
            UnscaledNumericValue: 1100.0,
            ScaledNumericValue: 112.5,
            BooleanValue: null,
            RawHex: "44898000",
            QualityFlags: PointQualityFlags.Online,
            IsValueChange: true);

        var dp1Bool = new ExtractedDataPointRecord(
            PacketTimestamp: baseTime.AddMilliseconds(10),
            EventTimestamp: null,
            SessionId: sessionId,
            TagId: boolTagId,
            FrameNumber: 11,
            Direction: TrafficDirection.ServerToClient,
            UnscaledNumericValue: null,
            ScaledNumericValue: null,
            BooleanValue: true,
            RawHex: "01",
            QualityFlags: PointQualityFlags.None,
            IsValueChange: true);

        byte[] rawPdu = [0x10, 0x27, 0xD3, 0x00, 0x02, 0x04, 0x00, 0x64, 0x00, 0xC8];
        var cmdEvent = new CapturedCommandEventRecord(
            Timestamp: baseTime.AddMilliseconds(25),
            SessionId: sessionId,
            DevicePairId: pairId,
            FrameNumber: 14,
            Direction: TrafficDirection.ClientToServer,
            Protocol: ProtocolType.ModbusTcp,
            FunctionCode: 16,
            CommandType: CommandType.ModbusWriteMultiRegs,
            TargetAddress: ProtocolAddress.Parse("HR:40001"),
            ControlAction: null,
            CommandCount: 2,
            PulseOnMs: null,
            PulseOffMs: null,
            UnscaledCommandValue: 100.0,
            RawPduBytes: rawPdu);

        var unmapped = new ModbusUnmappedRecord(
            Timestamp: baseTime.AddMilliseconds(30),
            SessionId: sessionId,
            DevicePairId: pairId,
            FrameNumber: 15,
            Direction: TrafficDirection.ServerToClient,
            UnitId: 247,
            RegisterType: ModbusRegisterType.Holding,
            RegisterOffset: 49999,
            RawValueHex: "ABCD");

        await sink.WriteBatchAsync(
            new ProtocolDecodeOutput([tx1, tx2], [dp1Numeric, dp1Bool], [cmdEvent], [unmapped]),
            CancellationToken.None);

        // 3. Write Batch 2 with subsequent tag values (must NOT overwrite T0 initial state)
        var dp2Numeric = dp1Numeric with
        {
            PacketTimestamp = baseTime.AddSeconds(1),
            FrameNumber = 20,
            UnscaledNumericValue = 2200.0,
            ScaledNumericValue = 222.5,
            RawHex = "45098000",
            IsValueChange = true
        };

        await sink.WriteBatchAsync(
            new ProtocolDecodeOutput([], [dp2Numeric], [], []),
            CancellationToken.None);

        // 4. Update T0 Initial States & Complete Session
        await sink.UpdateTagInitialStatesAsync(sessionId, CancellationToken.None);
        await sink.CompleteSessionAsync(sessionId, SessionStatus.Completed, CancellationToken.None);

        // 5. Verify persisted hypertable counts and values
        await AssertSessionRowAsync(session, expectedWireStatus: "COMPLETED");
        Assert.Equal(2, await CountRowsBySessionAsync("red_transactions", sessionId));
        Assert.Equal(3, await CountRowsBySessionAsync("tag_values", sessionId));
        Assert.Equal(1, await CountRowsBySessionAsync("captured_command_events", sessionId));
        Assert.Equal(1, await CountRowsBySessionAsync("modbus_raw_unmapped", sessionId));

        await AssertTagInitialStateAsync(numericTagId, expectedUnscaled: 1100.0, expectedScaled: 112.5, expectedBool: null, expectedHex: "44898000");
        await AssertTagInitialStateAsync(boolTagId, expectedUnscaled: null, expectedScaled: null, expectedBool: true, expectedHex: "01");
        await AssertCapturedCommandPduAsync(sessionId, rawPdu);
    }

    [IntegrationFact]
    public async Task CompleteSessionAsync_WithFailedStatus_TransitionsSessionToFailed()
    {
        var sessionId = TrackSession(Guid.NewGuid());
        await using var writer = new NpgsqlPostgresWriter(_dataSource);
        var sink = new TimescaleDbBatchSink(writer);

        var session = new TestSession(
            Id: sessionId,
            Name: "Failed_Session_Test",
            PcapFileName: "substation1.pcapng",
            S3ObjectKey: $"captures/{sessionId:D}/substation1.pcapng",
            TimeoutThresholdMs: 2500,
            StoreUnmappedRegisters: true);

        await sink.InitializeSessionAsync(session, [], [], CancellationToken.None);
        await sink.CompleteSessionAsync(sessionId, SessionStatus.Failed, CancellationToken.None);

        await AssertSessionRowAsync(session, expectedWireStatus: "FAILED");
    }

    [IntegrationFact]
    public async Task DeleteTestSession_CascadesRemovalAcrossAllMetadataAndHypertables()
    {
        var sessionId = TrackSession(Guid.NewGuid());
        var pairId = Guid.NewGuid();
        var tagId = Guid.NewGuid();
        var baseTime = new DateTime(2026, 10, 29, 14, 0, 0, DateTimeKind.Utc);

        await using var writer = new NpgsqlPostgresWriter(_dataSource);
        var sink = new TimescaleDbBatchSink(writer);

        var session = new TestSession(
            Id: sessionId,
            Name: "Cascade_Delete_Session",
            PcapFileName: "cascade.pcap",
            S3ObjectKey: null,
            TimeoutThresholdMs: 2000,
            StoreUnmappedRegisters: true);

        var pair = new DeviceEndpointPair(
            Id: pairId,
            SessionId: sessionId,
            Name: "Cascade_Pair",
            Protocol: ProtocolType.Dnp3,
            ClientIp: IPAddress.Parse("127.0.0.1"),
            ServerIp: IPAddress.Parse("127.0.0.1"),
            ClientProtocolAddressId: 4,
            ServerProtocolAddressId: 3);

        var tag = new TagDefinition(
            Id: tagId,
            DevicePairId: pairId,
            TagName: "Cascade_Tag",
            ProtocolAddress: ProtocolAddress.Parse("G30V02:Idx0"),
            DataType: TagDataType.Int16,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        await sink.InitializeSessionAsync(session, [pair], [tag], CancellationToken.None);

        var tx = new ProtocolTransactionRecord(
            Timestamp: baseTime,
            SessionId: sessionId,
            DevicePairId: pairId,
            FrameNumber: 1,
            Direction: TrafficDirection.ClientToServer,
            TransactionId: "1",
            FunctionCode: 1,
            DurationMs: null,
            IsError: false,
            ErrorType: TransactionErrorType.None,
            StatusCode: TransactionStatusCode.Success);

        var dp = new ExtractedDataPointRecord(
            PacketTimestamp: baseTime,
            EventTimestamp: null,
            SessionId: sessionId,
            TagId: tagId,
            FrameNumber: 2,
            Direction: TrafficDirection.ServerToClient,
            UnscaledNumericValue: 42.0,
            ScaledNumericValue: 42.0,
            BooleanValue: null,
            RawHex: "002A",
            QualityFlags: PointQualityFlags.Online,
            IsValueChange: true);

        var cmd = new CapturedCommandEventRecord(
            Timestamp: baseTime,
            SessionId: sessionId,
            DevicePairId: pairId,
            FrameNumber: 3,
            Direction: TrafficDirection.ClientToServer,
            Protocol: ProtocolType.Dnp3,
            FunctionCode: 3,
            CommandType: CommandType.Dnp3CrobSelect,
            TargetAddress: ProtocolAddress.Parse("G12V01:Idx1"),
            ControlAction: Dnp3ControlAction.LatchOn,
            CommandCount: 1,
            PulseOnMs: 100,
            PulseOffMs: 100,
            UnscaledCommandValue: null,
            RawPduBytes: [0xC1, 0x03]);

        var unmapped = new ModbusUnmappedRecord(
            Timestamp: baseTime,
            SessionId: sessionId,
            DevicePairId: pairId,
            FrameNumber: 4,
            Direction: TrafficDirection.ServerToClient,
            UnitId: 1,
            RegisterType: ModbusRegisterType.Input,
            RegisterOffset: 30001,
            RawValueHex: "0001");

        await sink.WriteBatchAsync(new ProtocolDecodeOutput([tx], [dp], [cmd], [unmapped]), CancellationToken.None);

        // Verify keepTestData: true preserves the rows
        await TimescaleTestDatabaseCleaner.CleanupSessionsIfEnabledAsync(_dataSource, [sessionId], keepTestData: true);
        Assert.Equal(1, await CountRowsByIdAsync("test_sessions", "id", sessionId));

        // Verify keepTestData: false invokes SELECT delete_test_session(@sessionId) and cascades across all 7 tables
        await TimescaleTestDatabaseCleaner.CleanupSessionsIfEnabledAsync(_dataSource, [sessionId], keepTestData: false);

        Assert.Equal(0, await CountRowsByIdAsync("test_sessions", "id", sessionId));
        Assert.Equal(0, await CountRowsBySessionAsync("device_pairs", sessionId));
        Assert.Equal(0, await CountRowsByIdAsync("tag_definitions", "id", tagId));
        Assert.Equal(0, await CountRowsBySessionAsync("red_transactions", sessionId));
        Assert.Equal(0, await CountRowsBySessionAsync("tag_values", sessionId));
        Assert.Equal(0, await CountRowsBySessionAsync("captured_command_events", sessionId));
        Assert.Equal(0, await CountRowsBySessionAsync("modbus_raw_unmapped", sessionId));
    }

    private Guid TrackSession(Guid sessionId)
    {
        _trackedSessionIds.Add(sessionId);
        return sessionId;
    }

    private async Task<long> CountRowsBySessionAsync(string tableName, Guid sessionId) =>
        await CountRowsByIdAsync(tableName, "session_id", sessionId);

    private async Task<long> CountRowsByIdAsync(string tableName, string columnName, Guid id)
    {
        await using var conn = await _dataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand($"SELECT COUNT(*) FROM {tableName} WHERE {columnName} = @id;", conn);
        cmd.Parameters.AddWithValue("id", id);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }

    private async Task AssertSessionRowAsync(TestSession expectedSession, string expectedWireStatus)
    {
        await using var conn = await _dataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT name, pcap_file_name, s3_object_key, timeout_threshold_ms, store_unmapped_registers, status FROM test_sessions WHERE id = @id;",
            conn);
        cmd.Parameters.AddWithValue("id", expectedSession.Id);

        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), $"Expected test_sessions row for {expectedSession.Id}.");
        Assert.Equal(expectedSession.Name, reader.GetString(0));
        Assert.Equal(expectedSession.PcapFileName, reader.GetString(1));
        Assert.Equal(expectedSession.S3ObjectKey, reader.IsDBNull(2) ? null : reader.GetString(2));
        Assert.Equal(expectedSession.TimeoutThresholdMs, reader.GetInt32(3));
        Assert.Equal(expectedSession.StoreUnmappedRegisters, reader.GetBoolean(4));
        Assert.Equal(expectedWireStatus, reader.GetString(5));
    }

    private async Task AssertDevicePairRowAsync(DeviceEndpointPair expectedPair, string expectedWireProtocol)
    {
        await using var conn = await _dataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT session_id, name, protocol, client_ip, server_ip, client_protocol_address_id, server_protocol_address_id FROM device_pairs WHERE id = @id;",
            conn);
        cmd.Parameters.AddWithValue("id", expectedPair.Id);

        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), $"Expected device_pairs row for {expectedPair.Id}.");
        Assert.Equal(expectedPair.SessionId, reader.GetGuid(0));
        Assert.Equal(expectedPair.Name, reader.GetString(1));
        Assert.Equal(expectedWireProtocol, reader.GetString(2));
        Assert.Equal(expectedPair.ClientIp, reader.GetFieldValue<IPAddress>(3));
        Assert.Equal(expectedPair.ServerIp, reader.GetFieldValue<IPAddress>(4));
        Assert.Equal(expectedPair.ClientProtocolAddressId, reader.IsDBNull(5) ? null : reader.GetInt32(5));
        Assert.Equal(expectedPair.ServerProtocolAddressId, reader.IsDBNull(6) ? null : reader.GetInt32(6));
    }

    private async Task AssertTagDefinitionMetadataAsync(TagDefinition expectedTag, string expectedWireDataType)
    {
        await using var conn = await _dataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            """
            SELECT device_pair_id, tag_name, protocol_address, data_type, scale_multiplier, scale_offset, engineering_units, description
            FROM tag_definitions
            WHERE id = @id;
            """,
            conn);
        cmd.Parameters.AddWithValue("id", expectedTag.Id);

        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), $"Expected tag_definitions row for {expectedTag.Id}.");
        Assert.Equal(expectedTag.DevicePairId, reader.GetGuid(0));
        Assert.Equal(expectedTag.TagName, reader.GetString(1));
        Assert.Equal(expectedTag.ProtocolAddress.Value, reader.GetString(2));
        Assert.Equal(expectedWireDataType, reader.GetString(3));
        Assert.Equal(expectedTag.ScaleMultiplier, reader.GetDouble(4));
        Assert.Equal(expectedTag.ScaleOffset, reader.GetDouble(5));
        Assert.Equal(expectedTag.EngineeringUnits, reader.IsDBNull(6) ? null : reader.GetString(6));
        Assert.Equal(expectedTag.Description, reader.IsDBNull(7) ? null : reader.GetString(7));
    }

    private async Task AssertTagInitialStateAsync(
        Guid tagId,
        double? expectedUnscaled,
        double? expectedScaled,
        bool? expectedBool,
        string expectedHex)
    {
        await using var conn = await _dataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            """
            SELECT initial_unscaled_numeric_value, initial_scaled_numeric_value, initial_boolean_value, initial_raw_hex
            FROM tag_definitions
            WHERE id = @id;
            """,
            conn);
        cmd.Parameters.AddWithValue("id", tagId);

        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), $"Expected tag_definitions row for {tagId}.");

        double? actualUnscaled = reader.IsDBNull(0) ? null : reader.GetDouble(0);
        double? actualScaled = reader.IsDBNull(1) ? null : reader.GetDouble(1);
        bool? actualBool = reader.IsDBNull(2) ? null : reader.GetBoolean(2);
        string? actualHex = reader.IsDBNull(3) ? null : reader.GetString(3);

        Assert.Equal(expectedUnscaled, actualUnscaled);
        Assert.Equal(expectedScaled, actualScaled);
        Assert.Equal(expectedBool, actualBool);
        Assert.Equal(expectedHex, actualHex);
    }

    private async Task AssertCapturedCommandPduAsync(Guid sessionId, byte[] expectedPdu)
    {
        await using var conn = await _dataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT command_type, target_address, raw_pdu_bytes FROM captured_command_events WHERE session_id = @sessionId;",
            conn);
        cmd.Parameters.AddWithValue("sessionId", sessionId);

        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), "Expected captured_command_events row.");
        Assert.Equal("MODBUS_WRITE_MULTI_REGS", reader.GetString(0));
        Assert.Equal("HR:40001", reader.GetString(1));
        Assert.Equal(expectedPdu, reader.GetFieldValue<byte[]>(2));
    }
}
