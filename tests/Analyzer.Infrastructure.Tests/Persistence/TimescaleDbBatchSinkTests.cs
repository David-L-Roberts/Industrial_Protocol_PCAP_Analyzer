using System.Net;
using System.Text.Json;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;
using Analyzer.Infrastructure.Persistence;
using NpgsqlTypes;

namespace Analyzer.Infrastructure.Tests.Persistence;

public class TimescaleDbBatchSinkTests
{
    private static readonly Guid SessionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid PairId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly DateTime T = new(2026, 10, 29, 1, 2, 3, 456, DateTimeKind.Utc);
    private static readonly Guid TagA = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001");
    private static readonly Guid TagB = Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002");
    private static readonly TraceId SampleTraceId = TraceId.Parse("0123456789abcdef0123456789abcdef");
    private static readonly SpanId SampleSpanId = SpanId.Parse("0123456789abcdef");
    private static readonly SpanId SampleParentSpanId = SpanId.Parse("fedcba9876543210");

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
            StoreUnmappedRegisters: true,
            StoreTraceSpans: false,
            SboWindowMs: 7500);

        var pair = new DeviceEndpointPair(
            Id: PairId,
            SessionId: SessionId,
            Name: "RTAC_Relay",
            Protocol: ProtocolType.ModbusTcp,
            ClientIp: IPAddress.Parse("10.0.1.10"),
            ServerIp: IPAddress.Parse("10.0.1.20"),
            ClientProtocolAddressId: null,
            ServerProtocolAddressId: 1,
            ClientName: "SEL_RTAC",
            ServerName: "Feeder1_Relay");

        var tag = new TagDefinition(
            Id: TagA,
            DevicePairId: PairId,
            TagName: "Bus_Volts_A",
            ProtocolAddress: ProtocolAddress.Parse("HR:40001"),
            DataType: TagDataType.Float32,
            ScaleMultiplier: 0.1,
            ScaleOffset: 5.0,
            EngineeringUnits: "kV",
            Description: "Phase A Bus Voltage",
            Endianness: RegisterEndianness.Cdab);

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
        Assert.Equal(false, stmt["@store_trace_spans"]);
        Assert.Equal(7500, stmt["@sbo_window_ms"]);
        Assert.Equal("PROCESSING", stmt["@status"]);

        var copies = _writer.Copies.ToArray();
        Assert.Equal(2, copies.Length);

        var pairCopy = copies[0];
        Assert.Equal("device_pairs", pairCopy.TableName);
        Assert.Equal(
            new[] { "id", "session_id", "name", "protocol", "client_ip", "server_ip", "client_protocol_address_id", "server_protocol_address_id", "client_name", "server_name" },
            pairCopy.ColumnNames);
        Assert.Equal(
            new object?[] { PairId, SessionId, "RTAC_Relay", "ModbusTCP", IPAddress.Parse("10.0.1.10"), IPAddress.Parse("10.0.1.20"), null, 1, "SEL_RTAC", "Feeder1_Relay" },
            pairCopy.Rows.Single());

        var tagCopy = copies[1];
        Assert.Equal("tag_definitions", tagCopy.TableName);
        Assert.Equal(
            new[] { "id", "device_pair_id", "tag_name", "protocol_address", "data_type", "endianness", "scale_multiplier", "scale_offset", "engineering_units", "description", "initial_unscaled_numeric_value", "initial_scaled_numeric_value", "initial_boolean_value", "initial_raw_hex" },
            tagCopy.ColumnNames);
        Assert.Equal(
            new object?[] { TagA, PairId, "Bus_Volts_A", "HR:40001", "FLOAT32", "CDAB", 0.1, 5.0, "kV", "Phase A Bus Voltage", null, null, null, null },
            tagCopy.Rows.Single());
    }

    [Theory]
    [InlineData(TagDataType.Bool, RegisterEndianness.Abcd, "BOOL", "ABCD")]
    [InlineData(TagDataType.Int16, RegisterEndianness.Dcba, "INT16", "DCBA")]
    [InlineData(TagDataType.UInt16, RegisterEndianness.Badc, "UINT16", "BADC")]
    [InlineData(TagDataType.Int32, RegisterEndianness.Cdab, "INT32", "CDAB")]
    [InlineData(TagDataType.UInt32, RegisterEndianness.Abcd, "UINT32", "ABCD")]
    [InlineData(TagDataType.Int64, RegisterEndianness.Dcba, "INT64", "DCBA")]
    [InlineData(TagDataType.UInt64, RegisterEndianness.Badc, "UINT64", "BADC")]
    [InlineData(TagDataType.Float32, RegisterEndianness.Cdab, "FLOAT32", "CDAB")]
    [InlineData(TagDataType.Float64, RegisterEndianness.Abcd, "FLOAT64", "ABCD")]
    public async Task InitializeSessionAsync_SerializesAllTagDataTypesAndEndiannessValuesToWireFormat(
        TagDataType dataType,
        RegisterEndianness endianness,
        string expectedDataTypeWire,
        string expectedEndiannessWire)
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var session = new TestSession(SessionId, "Session", "capture.pcap", null);
        var tag = new TagDefinition(
            Id: TagA,
            DevicePairId: PairId,
            TagName: "Tag_1",
            ProtocolAddress: ProtocolAddress.Parse("HR:40001"),
            DataType: dataType,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null,
            Endianness: endianness);

        await sink.InitializeSessionAsync(session, [], [tag], CancellationToken.None);

        var tagCopy = Assert.Single(_writer.Copies);
        var row = tagCopy.Row(0);
        Assert.Equal(expectedDataTypeWire, row["data_type"]);
        Assert.Equal(expectedEndiannessWire, row["endianness"]);
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
            StatusCode: TransactionStatusCode.ModbusEx02,
            TraceId: SampleTraceId,
            SpanId: SampleSpanId);

        await sink.WriteBatchAsync(Batch(transactions: [transaction]), CancellationToken.None);

        var copy = Assert.Single(_writer.Copies);
        Assert.Equal("red_transactions", copy.TableName);
        Assert.Equal(
            new[] { "timestamp", "session_id", "device_pair_id", "frame_number", "direction", "transaction_id", "function_code", "duration_ms", "is_error", "error_type", "status_code", "trace_id", "span_id" },
            copy.ColumnNames);
        Assert.Equal(
            new object?[] { T, SessionId, PairId, 42L, "SERVER_TO_CLIENT", "17", (short)3, 12.5, true, "EXCEPTION", "MODBUS_EX_02", SampleTraceId.Value, SampleSpanId.Value },
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
            IsValueChange: true,
            TraceId: SampleTraceId,
            SpanId: SampleSpanId);

        await sink.WriteBatchAsync(Batch(dataPoints: [dataPoint]), CancellationToken.None);

        var copy = Assert.Single(_writer.Copies);
        Assert.Equal("tag_values", copy.TableName);
        Assert.Equal(
            new[] { "packet_timestamp", "event_timestamp", "session_id", "tag_id", "frame_number", "direction", "unscaled_numeric_value", "scaled_numeric_value", "boolean_value", "raw_hex", "quality_flags", "is_value_change", "trace_id", "span_id" },
            copy.ColumnNames);
        Assert.Equal(
            new object?[] { T, eventTime, SessionId, TagA, 7L, "SERVER_TO_CLIENT", 1234.0, 123.4, null, "04D2", "ONLINE|COMM_LOST", true, SampleTraceId.Value, SampleSpanId.Value },
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
        Assert.Null(row["trace_id"]);
        Assert.Null(row["span_id"]);
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
            RawPduBytes: pdu,
            TraceId: SampleTraceId,
            SpanId: SampleSpanId);

        await sink.WriteBatchAsync(Batch(commandEvents: [command]), CancellationToken.None);

        var copy = Assert.Single(_writer.Copies);
        Assert.Equal("captured_command_events", copy.TableName);
        Assert.Equal(
            new[] { "timestamp", "session_id", "device_pair_id", "frame_number", "direction", "protocol", "function_code", "command_type", "target_address", "control_action", "command_count", "pulse_on_ms", "pulse_off_ms", "unscaled_command_value", "raw_pdu_bytes", "trace_id", "span_id" },
            copy.ColumnNames);
        Assert.Equal(
            new object?[] { T, SessionId, PairId, 99L, "CLIENT_TO_SERVER", "DNP3", (short)5, "DNP3_DIRECT_OPERATE", "G12V01:Idx2", "PULSE_ON", (short)1, 1000L, 0L, null, pdu, SampleTraceId.Value, SampleSpanId.Value },
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

    [Fact]
    public async Task WriteBatchAsync_CopiesTraceSpanIntoTraceSpansWithExpectedColumnsTypesAndGrafanaLogsJsonb()
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var startUnspecified = DateTime.SpecifyKind(T, DateTimeKind.Unspecified);
        var endUtc = T.AddMilliseconds(42.5);

        var spanWithMetadata = new TraceSpanRecord(
            StartTimeUtc: startUnspecified,
            EndTimeUtc: endUtc,
            DurationMs: 42.5,
            SessionId: SessionId,
            DevicePairId: PairId,
            TraceId: SampleTraceId,
            SpanId: SampleSpanId,
            ParentSpanId: SampleParentSpanId,
            ServiceName: "Feeder1_Relay",
            OperationName: "Modbus FC03 ReadHoldingRegisters",
            SpanKind: SpanKind.Client,
            OriginKind: SpanOriginKind.RequestResponse,
            StatusCode: SpanStatusCode.Ok,
            StatusMessage: null,
            Protocol: ProtocolType.ModbusTcp,
            ClientEndpoint: "SEL_RTAC",
            ServerEndpoint: "Feeder1_Relay",
            Direction: TrafficDirection.ClientToServer,
            RequestFrameNumber: 10,
            ResponseFrameNumber: 11,
            TransactionId: "42",
            FunctionCode: 3,
            Attributes: new Dictionary<string, object?>
            {
                ["modbus.unit_id"] = 1,
                ["modbus.quantity"] = 2L,
                ["scale.ratio"] = 0.25,
                ["protocol.unpaired"] = false,
                ["protocol.name"] = ProtocolType.ModbusTcp,
                ["quality_none"] = PointQualityFlags.None,
                ["target"] = ProtocolAddress.Parse("HR:40001"),
                ["optional_null"] = null
            },
            Events:
            [
                new SpanEventRecord(
                    TimestampUtc: DateTime.SpecifyKind(endUtc, DateTimeKind.Unspecified),
                    Kind: SpanEventKind.TagValueChanged,
                    Name: "tag_value_changed",
                    Fields: new Dictionary<string, object?>
                    {
                        ["tag_name"] = "Breaker_52A",
                        ["scaled_value"] = false,
                        ["quality_flags"] = PointQualityFlags.Online,
                        ["reason"] = SpanOriginKind.Timeout,
                        ["event"] = "should_not_duplicate"
                    })
            ]);

        var emptyMetadataSpan = new TraceSpanRecord(
            StartTimeUtc: T,
            EndTimeUtc: T,
            DurationMs: 0.0,
            SessionId: SessionId,
            DevicePairId: PairId,
            TraceId: SampleTraceId,
            SpanId: SampleParentSpanId,
            ParentSpanId: null,
            ServiceName: "SEL_RTAC",
            OperationName: "DNP3 FC129 Response",
            SpanKind: SpanKind.Consumer,
            OriginKind: SpanOriginKind.OrphanResponse,
            StatusCode: SpanStatusCode.Unset,
            StatusMessage: "ORPHAN_RESPONSE",
            Protocol: ProtocolType.Dnp3,
            ClientEndpoint: "SEL_RTAC",
            ServerEndpoint: "Feeder1_Relay",
            Direction: TrafficDirection.ServerToClient,
            RequestFrameNumber: null,
            ResponseFrameNumber: 22,
            TransactionId: "7",
            FunctionCode: 0x81,
            Attributes: new Dictionary<string, object?>(),
            Events: []);

        await sink.WriteBatchAsync(Batch(traceSpans: [spanWithMetadata, emptyMetadataSpan]), CancellationToken.None);

        var tx = Assert.Single(_writer.Transactions);
        Assert.True(tx.Committed);

        var copy = Assert.Single(_writer.Copies);
        Assert.Equal("trace_spans", copy.TableName);
        Assert.Equal(
            [
                "start_time", "end_time", "duration_ms", "session_id", "device_pair_id",
                "trace_id", "span_id", "parent_span_id", "service_name", "operation_name",
                "span_kind", "origin_kind", "status_code", "status_message", "protocol",
                "client_endpoint", "server_endpoint", "direction", "request_frame_number",
                "response_frame_number", "transaction_id", "function_code", "attributes", "events"
            ],
            copy.ColumnNames);

        var typesByName = copy.Target.Columns.ToDictionary(c => c.Name, c => c.DbType);
        Assert.Equal(NpgsqlDbType.TimestampTz, typesByName["start_time"]);
        Assert.Equal(NpgsqlDbType.TimestampTz, typesByName["end_time"]);
        Assert.Equal(NpgsqlDbType.Double, typesByName["duration_ms"]);
        Assert.Equal(NpgsqlDbType.Uuid, typesByName["session_id"]);
        Assert.Equal(NpgsqlDbType.Uuid, typesByName["device_pair_id"]);
        Assert.Equal(NpgsqlDbType.Varchar, typesByName["trace_id"]);
        Assert.Equal(NpgsqlDbType.Varchar, typesByName["span_id"]);
        Assert.Equal(NpgsqlDbType.Varchar, typesByName["parent_span_id"]);
        Assert.Equal(NpgsqlDbType.Bigint, typesByName["request_frame_number"]);
        Assert.Equal(NpgsqlDbType.Bigint, typesByName["response_frame_number"]);
        Assert.Equal(NpgsqlDbType.Smallint, typesByName["function_code"]);
        Assert.Equal(NpgsqlDbType.Jsonb, typesByName["attributes"]);
        Assert.Equal(NpgsqlDbType.Jsonb, typesByName["events"]);

        var row0 = copy.Row(0);
        Assert.Equal(DateTimeKind.Utc, Assert.IsType<DateTime>(row0["start_time"]).Kind);
        Assert.Equal(DateTimeKind.Utc, Assert.IsType<DateTime>(row0["end_time"]).Kind);
        Assert.Equal(42.5, row0["duration_ms"]);
        Assert.Equal(SampleTraceId.Value, row0["trace_id"]);
        Assert.Equal(SampleSpanId.Value, row0["span_id"]);
        Assert.Equal(SampleParentSpanId.Value, row0["parent_span_id"]);
        Assert.Equal("Feeder1_Relay", row0["service_name"]);
        Assert.Equal("Modbus FC03 ReadHoldingRegisters", row0["operation_name"]);
        Assert.Equal("CLIENT", row0["span_kind"]);
        Assert.Equal("REQUEST_RESPONSE", row0["origin_kind"]);
        Assert.Equal("OK", row0["status_code"]);
        Assert.Null(row0["status_message"]);
        Assert.Equal("ModbusTCP", row0["protocol"]);
        Assert.Equal("SEL_RTAC", row0["client_endpoint"]);
        Assert.Equal("Feeder1_Relay", row0["server_endpoint"]);
        Assert.Equal("CLIENT_TO_SERVER", row0["direction"]);
        Assert.Equal(10L, row0["request_frame_number"]);
        Assert.Equal(11L, row0["response_frame_number"]);
        Assert.Equal("42", row0["transaction_id"]);
        Assert.Equal((short)3, row0["function_code"]);

        using var attrDoc = JsonDocument.Parse(Assert.IsType<string>(row0["attributes"]));
        Assert.Equal(1, attrDoc.RootElement.GetProperty("modbus.unit_id").GetInt32());
        Assert.Equal(2L, attrDoc.RootElement.GetProperty("modbus.quantity").GetInt64());
        Assert.Equal(0.25, attrDoc.RootElement.GetProperty("scale.ratio").GetDouble());
        Assert.False(attrDoc.RootElement.GetProperty("protocol.unpaired").GetBoolean());
        Assert.Equal("ModbusTCP", attrDoc.RootElement.GetProperty("protocol.name").GetString());
        Assert.Equal(JsonValueKind.Null, attrDoc.RootElement.GetProperty("quality_none").ValueKind);
        Assert.Equal("HR:40001", attrDoc.RootElement.GetProperty("target").GetString());
        Assert.Equal(JsonValueKind.Null, attrDoc.RootElement.GetProperty("optional_null").ValueKind);

        using var eventsDoc = JsonDocument.Parse(Assert.IsType<string>(row0["events"]));
        var eventElem = Assert.Single(eventsDoc.RootElement.EnumerateArray());
        double expectedEpochMs = (endUtc - DateTime.UnixEpoch).TotalMilliseconds;
        Assert.Equal(expectedEpochMs, eventElem.GetProperty("timestamp").GetDouble(), precision: 3);
        var fields = eventElem.GetProperty("fields").EnumerateArray().ToArray();
        Assert.Equal(5, fields.Length);
        Assert.Equal("event", fields[0].GetProperty("key").GetString());
        Assert.Equal("tag_value_changed", fields[0].GetProperty("value").GetString());
        Assert.Equal("tag_name", fields[1].GetProperty("key").GetString());
        Assert.Equal("Breaker_52A", fields[1].GetProperty("value").GetString());
        Assert.Equal("scaled_value", fields[2].GetProperty("key").GetString());
        Assert.False(fields[2].GetProperty("value").GetBoolean());
        Assert.Equal("quality_flags", fields[3].GetProperty("key").GetString());
        Assert.Equal("ONLINE", fields[3].GetProperty("value").GetString());
        Assert.Equal("reason", fields[4].GetProperty("key").GetString());
        Assert.Equal("TIMEOUT", fields[4].GetProperty("value").GetString());

        var row1 = copy.Row(1);
        Assert.Null(row1["parent_span_id"]);
        Assert.Null(row1["request_frame_number"]);
        Assert.Equal("ORPHAN_RESPONSE", row1["status_message"]);
        Assert.Equal("{}", row1["attributes"]);
        Assert.Equal("[]", row1["events"]);
    }

    [Theory]
    [InlineData(SpanKind.Client, "CLIENT")]
    [InlineData(SpanKind.Server, "SERVER")]
    [InlineData(SpanKind.Producer, "PRODUCER")]
    [InlineData(SpanKind.Consumer, "CONSUMER")]
    [InlineData(SpanKind.Internal, "INTERNAL")]
    public async Task WriteBatchAsync_SerializesAllSpanKindsToWireFormat(SpanKind kind, string expectedWire)
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var span = Span() with { SpanKind = kind };

        await sink.WriteBatchAsync(Batch(traceSpans: [span]), CancellationToken.None);

        Assert.Equal(expectedWire, Assert.Single(_writer.Copies).Row(0)["span_kind"]);
    }

    [Theory]
    [InlineData(SpanStatusCode.Unset, "UNSET")]
    [InlineData(SpanStatusCode.Ok, "OK")]
    [InlineData(SpanStatusCode.Error, "ERROR")]
    public async Task WriteBatchAsync_SerializesAllSpanStatusCodesToWireFormat(SpanStatusCode status, string expectedWire)
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var span = Span() with { StatusCode = status };

        await sink.WriteBatchAsync(Batch(traceSpans: [span]), CancellationToken.None);

        Assert.Equal(expectedWire, Assert.Single(_writer.Copies).Row(0)["status_code"]);
    }

    [Theory]
    [InlineData(SpanOriginKind.RequestResponse, "REQUEST_RESPONSE")]
    [InlineData(SpanOriginKind.Timeout, "TIMEOUT")]
    [InlineData(SpanOriginKind.TimeoutAtEof, "TIMEOUT_AT_EOF")]
    [InlineData(SpanOriginKind.Malformed, "MALFORMED")]
    [InlineData(SpanOriginKind.Unsolicited, "UNSOLICITED")]
    [InlineData(SpanOriginKind.DirectNoAck, "DIRECT_NO_ACK")]
    [InlineData(SpanOriginKind.Confirm, "CONFIRM")]
    [InlineData(SpanOriginKind.ConfirmTimeout, "CONFIRM_TIMEOUT")]
    [InlineData(SpanOriginKind.OrphanResponse, "ORPHAN_RESPONSE")]
    public async Task WriteBatchAsync_SerializesAllSpanOriginKindsToWireFormat(SpanOriginKind origin, string expectedWire)
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var span = Span() with { OriginKind = origin };

        await sink.WriteBatchAsync(Batch(traceSpans: [span]), CancellationToken.None);

        Assert.Equal(expectedWire, Assert.Single(_writer.Copies).Row(0)["origin_kind"]);
    }

    [Theory]
    [InlineData(SpanEventKind.RequestSent, "request_sent")]
    [InlineData(SpanEventKind.ResponseReceived, "response_received")]
    [InlineData(SpanEventKind.TimeoutExpired, "timeout_expired")]
    [InlineData(SpanEventKind.ProtocolException, "protocol_exception")]
    [InlineData(SpanEventKind.CommandIssued, "command_issued")]
    [InlineData(SpanEventKind.TagValueChanged, "tag_value_changed")]
    [InlineData(SpanEventKind.ConfirmSent, "confirm_sent")]
    [InlineData(SpanEventKind.ConfirmTimeoutExpired, "confirm_timeout_expired")]
    public async Task WriteBatchAsync_SerializesAllSpanEventKindsToWireFormat(SpanEventKind eventKind, string expectedWire)
    {
        var sink = new TimescaleDbBatchSink(_writer);
        var span = Span() with
        {
            Events = [new SpanEventRecord(T, eventKind, expectedWire, new Dictionary<string, object?>())]
        };

        await sink.WriteBatchAsync(Batch(traceSpans: [span]), CancellationToken.None);

        using var doc = JsonDocument.Parse(Assert.IsType<string>(Assert.Single(_writer.Copies).Row(0)["events"]));
        var fields = doc.RootElement[0].GetProperty("fields");
        Assert.Single(fields.EnumerateArray());
        Assert.Equal("event", fields[0].GetProperty("key").GetString());
        Assert.Equal(expectedWire, fields[0].GetProperty("value").GetString());
    }

    private static TraceSpanRecord Span() =>
        new(
            StartTimeUtc: T,
            EndTimeUtc: T.AddMilliseconds(10),
            DurationMs: 10.0,
            SessionId: SessionId,
            DevicePairId: PairId,
            TraceId: SampleTraceId,
            SpanId: SampleSpanId,
            ParentSpanId: null,
            ServiceName: "Feeder1_Relay",
            OperationName: "Modbus FC03 ReadHoldingRegisters",
            SpanKind: SpanKind.Client,
            OriginKind: SpanOriginKind.RequestResponse,
            StatusCode: SpanStatusCode.Ok,
            StatusMessage: null,
            Protocol: ProtocolType.ModbusTcp,
            ClientEndpoint: "SEL_RTAC",
            ServerEndpoint: "Feeder1_Relay",
            Direction: TrafficDirection.ClientToServer,
            RequestFrameNumber: 1,
            ResponseFrameNumber: 2,
            TransactionId: "1",
            FunctionCode: 3,
            Attributes: new Dictionary<string, object?>(),
            Events: []);

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
        IReadOnlyList<ModbusUnmappedRecord>? unmapped = null,
        IReadOnlyList<TraceSpanRecord>? traceSpans = null) =>
        new(
            transactions ?? [],
            dataPoints ?? [],
            commandEvents ?? [],
            unmapped ?? [],
            traceSpans ?? []);
}
