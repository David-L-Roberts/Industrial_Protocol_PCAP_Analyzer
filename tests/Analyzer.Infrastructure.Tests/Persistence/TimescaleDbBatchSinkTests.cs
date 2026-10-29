using System.Net;
using Analyzer.Core.Domain;
using Analyzer.Infrastructure.Persistence;

namespace Analyzer.Infrastructure.Tests.Persistence;

public class TimescaleDbBatchSinkTests
{
    private static readonly Guid SessionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid PairId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly DateTime T = new(2026, 10, 29, 1, 2, 3, 456, DateTimeKind.Utc);
    private static readonly Guid TagA = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid TagB = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002");

    private readonly RecordingPostgresWriter _writer = new();

    [Fact]
    public async Task InitializeSessionAsync_InsertsSessionAndCopiesDevicePairsAndTagsInSingleTransaction()
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var session = new TestSession(
            Id: SessionId,
            Name: "FAT_Feeder1",
            PcapFileName: "feeder1.pcap",
            S3ObjectKey: "captures/feeder1.pcap",
            TimeoutThresholdMs: 1500,
            StoreUnmappedRegisters: true);

        var pair = new DeviceEndpointPair(
            Id: PairId,
            SessionId: SessionId,
            Name: "RTAC_Relay",
            Protocol: ProtocolType.ModbusTcp,
            ClientIp: IPAddress.Parse("10.0.1.10"),
            ServerIp: IPAddress.Parse("10.0.1.20"),
            ClientProtocolAddressId: null,
            ServerProtocolAddressId: 1);

        var tag = new TagDefinition(
            Id: TagA,
            DevicePairId: PairId,
            TagName: "Bus_Volts_A",
            ProtocolAddress: ProtocolAddress.Parse("HR:40001"),
            DataType: TagDataType.Float32Be,
            ScaleMultiplier: 0.1,
            ScaleOffset: 5.0,
            EngineeringUnits: "kV",
            Description: "Phase A Bus Voltage");

        await sink.InitializeSessionAsync(session, [pair], [tag], CancellationToken.None);

        var tx = Assert.Single(_writer.Transactions);
        Assert.True(tx.Committed);

        var stmt = Assert.Single(_writer.Statements);
        Assert.Contains("INSERT INTO test_sessions", stmt.Sql, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(SessionId, stmt["@id"]);
        Assert.Equal("FAT_Feeder1", stmt["@name"]);
        Assert.Equal("feeder1.pcap", stmt["@pcap_file_name"]);
        Assert.Equal("captures/feeder1.pcap", stmt["@s3_object_key"]);
        Assert.Equal(1500, stmt["@timeout_threshold_ms"]);
        Assert.Equal(true, stmt["@store_unmapped_registers"]);
        Assert.Equal("PROCESSING", stmt["@status"]);

        var copies = _writer.Copies.ToArray();
        Assert.Equal(2, copies.Length);

        var pairCopy = copies[0];
        Assert.Equal("device_pairs", pairCopy.TableName);
        Assert.Equal(
            new[] { "id", "session_id", "name", "protocol", "client_ip", "server_ip", "client_protocol_address_id", "server_protocol_address_id" },
            pairCopy.ColumnNames);
        Assert.Equal(
            new object?[] { PairId, SessionId, "RTAC_Relay", "ModbusTCP", IPAddress.Parse("10.0.1.10"), IPAddress.Parse("10.0.1.20"), null, 1 },
            pairCopy.Rows.Single());

        var tagCopy = copies[1];
        Assert.Equal("tag_definitions", tagCopy.TableName);
        Assert.Equal(
            new[] { "id", "device_pair_id", "tag_name", "protocol_address", "data_type", "scale_multiplier", "scale_offset", "engineering_units", "description", "initial_unscaled_numeric_value", "initial_scaled_numeric_value", "initial_boolean_value", "initial_raw_hex" },
            tagCopy.ColumnNames);
        Assert.Equal(
            new object?[] { TagA, PairId, "Bus_Volts_A", "HR:40001", "FLOAT32_BE", 0.1, 5.0, "kV", "Phase A Bus Voltage", null, null, null, null },
            tagCopy.Rows.Single());
    }

    [Fact]
    public async Task UpdateTagInitialStatesAsync_PersistsFirstSeenValuesAcrossBatches()
    {
        var sink = new TimescaleDbBatchSink(_writer);

        // Batch 1: first appearance of TagA and TagB
        var dp1A = DataPoint(TagA, frameNumber: 1, unscaled: 100.0, scaled: 10.0, booleanValue: null, rawHex: "0064");
        var dp1B = DataPoint(TagB, frameNumber: 2, unscaled: null, scaled: null, booleanValue: true, rawHex: "01");
        await sink.WriteBatchAsync(Batch(dataPoints: [dp1A, dp1B]), CancellationToken.None);

        // Batch 2: second appearance of TagA with modified values - must NOT overwrite T0
        var dp2A = DataPoint(TagA, frameNumber: 3, unscaled: 200.0, scaled: 20.0, booleanValue: null, rawHex: "00C8");
        await sink.WriteBatchAsync(Batch(dataPoints: [dp2A]), CancellationToken.None);

        // Clear recorded transactions to isolate UpdateTagInitialStatesAsync
        _writer.Transactions.Clear();

        await sink.UpdateTagInitialStatesAsync(SessionId, CancellationToken.None);

        var tx = Assert.Single(_writer.Transactions);
        Assert.True(tx.Committed);

        var stmt = Assert.Single(_writer.Statements);
        Assert.Contains("UPDATE tag_definitions", stmt.Sql, StringComparison.OrdinalIgnoreCase);

        var tagIds = Assert.IsAssignableFrom<Guid[]>(stmt["@tag_ids"]);
        var unscaledValues = Assert.IsAssignableFrom<double?[]>(stmt["@unscaled_values"]);
        var scaledValues = Assert.IsAssignableFrom<double?[]>(stmt["@scaled_values"]);
        var boolValues = Assert.IsAssignableFrom<bool?[]>(stmt["@boolean_values"]);
        var rawHexes = Assert.IsAssignableFrom<string?[]>(stmt["@raw_hexes"]);

        Assert.Equal(2, tagIds.Length);

        // TagA T0 must match first appearance (unscaled 100, scaled 10, hex 0064)
        int idxA = Array.IndexOf(tagIds, TagA);
        Assert.True(idxA >= 0);
        Assert.Equal(100.0, unscaledValues[idxA]);
        Assert.Equal(10.0, scaledValues[idxA]);
        Assert.Null(boolValues[idxA]);
        Assert.Equal("0064", rawHexes[idxA]);

        // TagB T0 must match first appearance (bool true, hex 01)
        int idxB = Array.IndexOf(tagIds, TagB);
        Assert.True(idxB >= 0);
        Assert.Null(unscaledValues[idxB]);
        Assert.Null(scaledValues[idxB]);
        Assert.Equal(true, boolValues[idxB]);
        Assert.Equal("01", rawHexes[idxB]);
    }

    [Fact]
    public async Task UpdateTagInitialStatesAsync_WithNoDataPoints_DoesNotExecuteStatements()
    {
        var sink = new TimescaleDbBatchSink(_writer);

        await sink.UpdateTagInitialStatesAsync(SessionId, CancellationToken.None);

        Assert.Empty(_writer.Transactions);
    }

    [Theory]
    [InlineData(SessionStatus.Completed, "COMPLETED")]
    [InlineData(SessionStatus.Failed, "FAILED")]
    public async Task CompleteSessionAsync_UpdatesTestSessionStatusInTransaction(SessionStatus status, string expectedWireStatus)
    {
        var sink = new TimescaleDbBatchSink(_writer);

        await sink.CompleteSessionAsync(SessionId, status, CancellationToken.None);

        var tx = Assert.Single(_writer.Transactions);
        Assert.True(tx.Committed);

        var stmt = Assert.Single(_writer.Statements);
        Assert.Contains("UPDATE test_sessions", stmt.Sql, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(expectedWireStatus, stmt["@status"]);
        Assert.Equal(SessionId, stmt["@id"]);
    }

    [Fact]
    public async Task WriteBatchAsync_CopiesTransactionIntoRedTransactionsWithWireFormatColumns()
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var transaction = new ProtocolTransactionRecord(
            Timestamp: T,
            SessionId: SessionId,
            DevicePairId: PairId,
            FrameNumber: 42,
            Direction: TrafficDirection.ServerToClient,
            TransactionId: "17",
            FunctionCode: 3,
            DurationMs: 12.5,
            IsError: true,
            ErrorType: TransactionErrorType.Exception,
            StatusCode: TransactionStatusCode.ModbusEx02);

        await sink.WriteBatchAsync(Batch(transactions: [transaction]), CancellationToken.None);

        var copy = Assert.Single(_writer.Copies);
        Assert.Equal("red_transactions", copy.TableName);
        Assert.Equal(
            new[] { "timestamp", "session_id", "device_pair_id", "frame_number", "direction", "transaction_id", "function_code", "duration_ms", "is_error", "error_type", "status_code" },
            copy.ColumnNames);
        Assert.Equal(
            new object?[] { T, SessionId, PairId, 42L, "SERVER_TO_CLIENT", "17", (short)3, 12.5, true, "EXCEPTION", "MODBUS_EX_02" },
            copy.Rows.Single());
    }

    [Fact]
    public async Task WriteBatchAsync_SplitsRowsIntoCopiesOfAtMostFiveThousandWithinOneTransaction()
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var transactions = Enumerable.Range(1, 12_001).Select(i => Transaction(frameNumber: i)).ToArray();

        await sink.WriteBatchAsync(Batch(transactions: transactions), CancellationToken.None);

        var tx = Assert.Single(_writer.Transactions);
        Assert.True(tx.Committed);
        Assert.Equal(new[] { 5000, 5000, 2001 }, _writer.Copies.Select(c => c.Rows.Count));
        Assert.Equal(
            Enumerable.Range(1, 12_001).Select(i => (object?)(long)i),
            _writer.Copies.SelectMany(c => c.Rows).Select(row => row[3]));
    }

    [Fact]
    public async Task WriteBatchAsync_HonoursConfiguredBatchSize()
    {
        var sink = new TimescaleDbBatchSink(_writer, batchSize: 2);
        var transactions = Enumerable.Range(1, 5).Select(i => Transaction(frameNumber: i)).ToArray();

        await sink.WriteBatchAsync(Batch(transactions: transactions), CancellationToken.None);

        Assert.Equal(new[] { 2, 2, 1 }, _writer.Copies.Select(c => c.Rows.Count));
    }

    [Fact]
    public async Task WriteBatchAsync_WithEmptyBatch_DoesNotTouchTheDatabase()
    {
        var sink = new TimescaleDbBatchSink(_writer);

        await sink.WriteBatchAsync(Batch(), CancellationToken.None);

        Assert.Empty(_writer.Transactions);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Constructor_RejectsNonPositiveBatchSize(int batchSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TimescaleDbBatchSink(_writer, batchSize));
    }

    [Fact]
    public async Task WriteBatchAsync_CopiesDataPointIntoTagValuesWithDualTimestampsAndQualityFlags()
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var eventTime = new DateTime(2026, 10, 29, 1, 2, 2, 999, DateTimeKind.Utc);
        var dataPoint = new ExtractedDataPointRecord(
            PacketTimestamp: T,
            EventTimestamp: eventTime,
            SessionId: SessionId,
            TagId: TagA,
            FrameNumber: 7,
            Direction: TrafficDirection.ServerToClient,
            UnscaledNumericValue: 1234,
            ScaledNumericValue: 123.4,
            BooleanValue: null,
            RawHex: "04D2",
            QualityFlags: PointQualityFlags.Online | PointQualityFlags.CommLost,
            IsValueChange: true);

        await sink.WriteBatchAsync(Batch(dataPoints: [dataPoint]), CancellationToken.None);

        var copy = Assert.Single(_writer.Copies);
        Assert.Equal("tag_values", copy.TableName);
        Assert.Equal(
            new[] { "packet_timestamp", "event_timestamp", "session_id", "tag_id", "frame_number", "direction", "unscaled_numeric_value", "scaled_numeric_value", "boolean_value", "raw_hex", "quality_flags", "is_value_change" },
            copy.ColumnNames);
        Assert.Equal(
            new object?[] { T, eventTime, SessionId, TagA, 7L, "SERVER_TO_CLIENT", 1234.0, 123.4, null, "04D2", "ONLINE|COMM_LOST", true },
            copy.Rows.Single());
    }

    [Fact]
    public async Task WriteBatchAsync_WritesNullQualityFlagsWhenNoneAreSet()
    {
        var sink = new TimescaleDbBatchSink(_writer);

        await sink.WriteBatchAsync(Batch(dataPoints: [DataPoint(TagA, frameNumber: 1, booleanValue: true)]), CancellationToken.None);

        var row = Assert.Single(_writer.Copies).Row(0);
        Assert.Null(row["quality_flags"]);
        Assert.Null(row["event_timestamp"]);
        Assert.Equal(true, row["boolean_value"]);
    }

    [Fact]
    public async Task WriteBatchAsync_CopiesCommandEventIntoCapturedCommandEventsWithRawPdu()
    {
        var sink = new TimescaleDbBatchSink(_writer);
        byte[] pdu = [0xC1, 0x05, 0x0C, 0x01, 0x28, 0x01, 0x00, 0x02, 0x00];
        var command = new CapturedCommandEventRecord(
            Timestamp: T,
            SessionId: SessionId,
            DevicePairId: PairId,
            FrameNumber: 99,
            Direction: TrafficDirection.ClientToServer,
            Protocol: ProtocolType.Dnp3,
            FunctionCode: 5,
            CommandType: CommandType.Dnp3DirectOperate,
            TargetAddress: ProtocolAddress.Parse("G12V01:Idx2"),
            ControlAction: Dnp3ControlAction.PulseOn,
            CommandCount: 1,
            PulseOnMs: 1000,
            PulseOffMs: 0,
            UnscaledCommandValue: null,
            RawPduBytes: pdu);

        await sink.WriteBatchAsync(Batch(commandEvents: [command]), CancellationToken.None);

        var copy = Assert.Single(_writer.Copies);
        Assert.Equal("captured_command_events", copy.TableName);
        Assert.Equal(
            new[] { "timestamp", "session_id", "device_pair_id", "frame_number", "direction", "protocol", "function_code", "command_type", "target_address", "control_action", "command_count", "pulse_on_ms", "pulse_off_ms", "unscaled_command_value", "raw_pdu_bytes" },
            copy.ColumnNames);
        Assert.Equal(
            new object?[] { T, SessionId, PairId, 99L, "CLIENT_TO_SERVER", "DNP3", (short)5, "DNP3_DIRECT_OPERATE", "G12V01:Idx2", "PULSE_ON", (short)1, 1000L, 0L, null, pdu },
            copy.Rows.Single());
    }

    [Fact]
    public async Task WriteBatchAsync_CopiesUnmappedRegisterIntoModbusRawUnmapped()
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var unmapped = new ModbusUnmappedRecord(
            Timestamp: T,
            SessionId: SessionId,
            DevicePairId: PairId,
            FrameNumber: 12,
            Direction: TrafficDirection.ServerToClient,
            UnitId: 1,
            RegisterType: ModbusRegisterType.DiscreteInput,
            RegisterOffset: 10017,
            RawValueHex: "01");

        await sink.WriteBatchAsync(Batch(unmapped: [unmapped]), CancellationToken.None);

        var copy = Assert.Single(_writer.Copies);
        Assert.Equal("modbus_raw_unmapped", copy.TableName);
        Assert.Equal(
            new[] { "timestamp", "session_id", "device_pair_id", "frame_number", "direction", "unit_id", "register_type", "register_offset", "raw_value_hex" },
            copy.ColumnNames);
        Assert.Equal(
            new object?[] { T, SessionId, PairId, 12L, "SERVER_TO_CLIENT", (short)1, "DISCRETE_INPUT", 10017, "01" },
            copy.Rows.Single());
    }

    [Fact]
    public async Task WriteBatchAsync_WritesEveryNonEmptyHypertableInOneTransaction()
    {
        var sink = new TimescaleDbBatchSink(_writer);

        await sink.WriteBatchAsync(
            Batch(transactions: [Transaction()], dataPoints: [DataPoint(TagA, frameNumber: 1)]),
            CancellationToken.None);

        var tx = Assert.Single(_writer.Transactions);
        Assert.True(tx.Committed);
        Assert.Equal(new[] { "red_transactions", "tag_values" }, _writer.Copies.Select(c => c.TableName));
    }

    [Fact]
    public async Task WriteBatchAsync_NormalisesUnspecifiedTimestampsToUtc()
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var unspecified = DateTime.SpecifyKind(T, DateTimeKind.Unspecified);

        await sink.WriteBatchAsync(Batch(transactions: [Transaction() with { Timestamp = unspecified }]), CancellationToken.None);

        var timestamp = Assert.IsType<DateTime>(Assert.Single(_writer.Copies).Row(0)["timestamp"]);
        Assert.Equal(DateTimeKind.Utc, timestamp.Kind);
        Assert.Equal(T.Ticks, timestamp.Ticks);
    }

    private static ExtractedDataPointRecord DataPoint(
        Guid tagId,
        long frameNumber,
        double? unscaled = null,
        double? scaled = null,
        bool? booleanValue = null,
        string rawHex = "0000",
        Guid? sessionId = null) =>
        new(T.AddMilliseconds(frameNumber), null, sessionId ?? SessionId, tagId, frameNumber, TrafficDirection.ServerToClient,
            unscaled, scaled, booleanValue, rawHex, PointQualityFlags.None, IsValueChange: false);

    private static ProtocolTransactionRecord Transaction(long frameNumber = 1) =>
        new(T, SessionId, PairId, frameNumber, TrafficDirection.ClientToServer, "1", 3, null, false,
            TransactionErrorType.None, TransactionStatusCode.Success);

    private static ProtocolDecodeOutput Batch(
        IReadOnlyList<ProtocolTransactionRecord>? transactions = null,
        IReadOnlyList<ExtractedDataPointRecord>? dataPoints = null,
        IReadOnlyList<CapturedCommandEventRecord>? commandEvents = null,
        IReadOnlyList<ModbusUnmappedRecord>? unmapped = null) =>
        new(
            transactions ?? [],
            dataPoints ?? [],
            commandEvents ?? [],
            unmapped ?? []);
}
