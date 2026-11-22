using System.Net;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Services;
using Analyzer.Decoders.Dnp3;
using Analyzer.Decoders.Dnp3.Handlers;
using Analyzer.Decoders.Dnp3.Registry;

namespace Analyzer.Decoders.Dnp3.Tests;

public class Dnp3TraceSpanTests
{
    private static readonly Guid SessionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid PairId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly IPAddress ClientIp = IPAddress.Parse("10.0.1.5");
    private static readonly IPAddress ServerIp = IPAddress.Parse("10.0.1.10");
    private static readonly DateTime BaseTime = new(2026, 11, 22, 8, 0, 0, DateTimeKind.Utc);

    private static DeviceEndpointPair CreateNamedPair(
        int? masterAddr = 1,
        int? outstationAddr = 100,
        string? clientName = "SCADA_Master",
        string? serverName = "Feeder1_RTU") =>
        new(
            Id: PairId,
            SessionId: SessionId,
            Name: "SCADA_to_Feeder1",
            Protocol: ProtocolType.Dnp3,
            ClientIp: ClientIp,
            ServerIp: ServerIp,
            ClientProtocolAddressId: masterAddr,
            ServerProtocolAddressId: outstationAddr,
            ClientName: clientName,
            ServerName: serverName);

    private static DissectedFrame CreateFrame(
        long frameNumber,
        DateTime timestampUtc,
        TrafficDirection direction,
        byte[] payload) =>
        new(
            FrameNumber: frameNumber,
            TimestampUtc: timestampUtc,
            SourceIp: direction == TrafficDirection.ClientToServer ? ClientIp : ServerIp,
            SourcePort: direction == TrafficDirection.ClientToServer ? 50100 : 20000,
            DestIp: direction == TrafficDirection.ClientToServer ? ServerIp : ClientIp,
            DestPort: direction == TrafficDirection.ClientToServer ? 20000 : 50100,
            ProtocolName: ProtocolType.Dnp3,
            RawApplicationPayload: payload);

    private static Dnp3HandlerRegistry CreateFullRegistry(TagResolutionEngine tagEngine) =>
        new(
        [
            new Group1BinaryInputStaticHandler(tagEngine),
            new Group2BinaryInputEventHandler(tagEngine),
            new Group10BinaryOutputStatusHandler(tagEngine),
            new Group12CrobControlHandler(tagEngine),
            new Group20RunningCounterHandler(tagEngine),
            new Group22CounterChangeEventHandler(tagEngine),
            new Group30AnalogInputStaticHandler(tagEngine),
            new Group32AnalogInputEventHandler(tagEngine)
        ]);

    [Fact]
    public void ProcessFrame_SolicitedReadAndResponse_ParsesAppControlFlagsAndEmitsCompleteTraceSpan()
    {
        var aiTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Feeder_MW",
            ProtocolAddress: ProtocolAddress.Parse("G30V02:Idx0"),
            DataType: TagDataType.Int16,
            ScaleMultiplier: 0.01,
            ScaleOffset: 0.0,
            EngineeringUnits: "MW",
            Description: null);

        var biTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Breaker_52A",
            ProtocolAddress: ProtocolAddress.Parse("G01V02:Idx0"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([aiTag, biTag]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        // Request: AppControl = 0xC5 (FIR=1, FIN=1, CON=0, UNS=0, SEQ=5), FC = 0x01 (Read), Class 0 (G60V1)
        byte[] reqPayload = Dnp3DecoderTests.BuildDnp3LinkFrame(
            destination: 100,
            source: 1,
            transportHeader: 0xC0,
            applicationFragment: [0xC5, 0x01, 0x3C, 0x01, 0x06]);

        var reqOut = decoder.ProcessFrame(
            CreateFrame(10, BaseTime, TrafficDirection.ClientToServer, reqPayload),
            pair,
            TrafficDirection.ClientToServer);

        Assert.Empty(reqOut.TraceSpans);

        // Response: AppControl = 0xE5 (FIR=1, FIN=1, CON=1, UNS=0, SEQ=5), FC = 0x81, IIN1=0x00, IIN2=0x00
        // Objects: G30V2 (idx 0 = 1234 -> 12.34 MW) + G1V2 (idx 0 = 0x81 -> true)
        DateTime respTime = BaseTime.AddMilliseconds(42.5);
        byte[] respPayload = Dnp3DecoderTests.BuildDnp3LinkFrame(
            destination: 1,
            source: 100,
            transportHeader: 0xC0,
            applicationFragment:
            [
                0xE5, 0x81, 0x00, 0x00,
                30, 2, 0x00, 0x00, 0x00, 0x01, 0xD2, 0x04,
                1, 2, 0x00, 0x00, 0x00, 0x81
            ]);

        var respOut = decoder.ProcessFrame(
            CreateFrame(11, respTime, TrafficDirection.ServerToClient, respPayload),
            pair,
            TrafficDirection.ServerToClient);

        var tx = Assert.Single(respOut.Transactions);
        var span = Assert.Single(respOut.TraceSpans);
        Assert.Equal(2, respOut.DataPoints.Count);

        Assert.NotNull(tx.TraceId);
        Assert.NotNull(tx.SpanId);
        Assert.Equal(tx.TraceId, span.TraceId);
        Assert.Equal(tx.SpanId, span.SpanId);
        Assert.All(respOut.DataPoints, dp =>
        {
            Assert.Equal(span.TraceId, dp.TraceId);
            Assert.Equal(span.SpanId, dp.SpanId);
        });

        Assert.Null(span.ParentSpanId);
        Assert.Equal(BaseTime, span.StartTimeUtc);
        Assert.Equal(respTime, span.EndTimeUtc);
        Assert.Equal(42.5, span.DurationMs, precision: 5);
        Assert.Equal(SessionId, span.SessionId);
        Assert.Equal(PairId, span.DevicePairId);
        Assert.Equal("Feeder1_RTU", span.ServiceName);
        Assert.Equal("SCADA_Master", span.ClientEndpoint);
        Assert.Equal("Feeder1_RTU", span.ServerEndpoint);
        Assert.Equal("DNP3 FC01 Read", span.OperationName);
        Assert.Equal(SpanKind.Client, span.SpanKind);
        Assert.Equal(SpanOriginKind.RequestResponse, span.OriginKind);
        Assert.Equal(SpanStatusCode.Ok, span.StatusCode);
        Assert.Null(span.StatusMessage);
        Assert.Equal(ProtocolType.Dnp3, span.Protocol);
        Assert.Equal(TrafficDirection.ClientToServer, span.Direction);
        Assert.Equal(10L, span.RequestFrameNumber);
        Assert.Equal(11L, span.ResponseFrameNumber);
        Assert.Equal("5", span.TransactionId);
        Assert.Equal((short)1, span.FunctionCode);

        Assert.Equal(ProtocolType.Dnp3, span.Attributes["protocol"]);
        Assert.Equal(SessionId, span.Attributes["session.id"]);
        Assert.Equal(PairId, span.Attributes["device_pair.id"]);
        Assert.Equal("SCADA_to_Feeder1", span.Attributes["device_pair.name"]);
        Assert.Equal("10.0.1.5", span.Attributes["net.client.ip"]);
        Assert.Equal(50100, span.Attributes["net.client.port"]);
        Assert.Equal("10.0.1.10", span.Attributes["net.server.ip"]);
        Assert.Equal(20000, span.Attributes["net.server.port"]);
        Assert.Equal(10L, span.Attributes["pcap.request_frame"]);
        Assert.Equal(11L, span.Attributes["pcap.response_frame"]);
        Assert.Equal(reqPayload.Length, span.Attributes["pcap.request_bytes"]);
        Assert.Equal(respPayload.Length, span.Attributes["pcap.response_bytes"]);
        Assert.Equal(1, span.Attributes["dnp3.src"]);
        Assert.Equal(100, span.Attributes["dnp3.dst"]);
        Assert.Equal(5, span.Attributes["dnp3.app_seq"]);
        Assert.Equal(true, span.Attributes["dnp3.fir"]);
        Assert.Equal(true, span.Attributes["dnp3.fin"]);
        Assert.Equal(true, span.Attributes["dnp3.con"]);
        Assert.Equal(false, span.Attributes["dnp3.uns"]);
        Assert.Equal(0, span.Attributes["dnp3.iin1"]);
        Assert.Equal(0, span.Attributes["dnp3.iin2"]);
        Assert.Equal("G30V02,G01V02", span.Attributes["dnp3.object_groups"]);
        Assert.Equal(2, span.Attributes["tags.matched_count"]);
        Assert.Equal(2, span.Attributes["tags.changed_count"]);
        Assert.False(span.Attributes.ContainsKey("tags.changes_truncated"));

        Assert.Equal(4, span.Events.Count);
        Assert.Equal(SpanEventKind.RequestSent, span.Events[0].Kind);
        Assert.Equal(BaseTime, span.Events[0].TimestampUtc);
        Assert.Equal(SpanEventKind.ResponseReceived, span.Events[1].Kind);
        Assert.Equal(respTime, span.Events[1].TimestampUtc);
        Assert.Equal(SpanEventKind.TagValueChanged, span.Events[2].Kind);
        Assert.Equal("Feeder_MW", span.Events[2].Fields["tag_name"]);
        Assert.Equal(12.34, (double)span.Events[2].Fields["scaled_value"]!, precision: 5);
        Assert.Equal(SpanEventKind.TagValueChanged, span.Events[3].Kind);
        Assert.Equal("Breaker_52A", span.Events[3].Fields["tag_name"]);
        Assert.Equal(true, span.Events[3].Fields["scaled_value"]);
    }

    [Theory]
    [InlineData(0x01, "DNP3 FC01 Read")]
    [InlineData(0x02, "DNP3 FC02 Write")]
    [InlineData(0x03, "DNP3 FC03 Select")]
    [InlineData(0x04, "DNP3 FC04 Operate")]
    [InlineData(0x05, "DNP3 FC05 DirectOperate")]
    [InlineData(0x0D, "DNP3 FC13 ColdRestart")]
    [InlineData(0x0E, "DNP3 FC14 WarmRestart")]
    [InlineData(0x14, "DNP3 FC20 EnableUnsolicited")]
    [InlineData(0x15, "DNP3 FC21 DisableUnsolicited")]
    [InlineData(0x17, "DNP3 FC23 DelayMeasure")]
    [InlineData(0x09, "DNP3 FC09 Unknown")]
    public void ProcessFrame_MatchedSolicitedResponse_PreservesInitiatingRequestOperationName(
        byte requestFc,
        string expectedOperationName)
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        // Use non-FIR/FIN appControl (0x2A -> CON=1, SEQ=10) to also test all bit positions
        byte[] reqPayload = Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0x2A, requestFc]);
        decoder.ProcessFrame(CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, reqPayload), pair, TrafficDirection.ClientToServer);

        // Response AC = 0xCA (FIR=1, FIN=1, CON=0, UNS=0, SEQ=10)
        byte[] respPayload = Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xCA, 0x81, 0x00, 0x00]);
        var respOut = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(12), TrafficDirection.ServerToClient, respPayload),
            pair,
            TrafficDirection.ServerToClient);

        var span = Assert.Single(respOut.TraceSpans);
        Assert.Equal(expectedOperationName, span.OperationName);
        Assert.Equal((short)requestFc, span.FunctionCode);
        Assert.Equal(SpanOriginKind.RequestResponse, span.OriginKind);
        Assert.Equal(SpanStatusCode.Ok, span.StatusCode);
        Assert.Equal(10, span.Attributes["dnp3.app_seq"]);
        Assert.Equal(true, span.Attributes["dnp3.fir"]);
        Assert.Equal(true, span.Attributes["dnp3.fin"]);
        Assert.Equal(false, span.Attributes["dnp3.con"]);
        Assert.Equal(false, span.Attributes["dnp3.uns"]);
    }

    [Theory]
    [InlineData(0x03, "DNP3 FC03 Select")]
    [InlineData(0x04, "DNP3 FC04 Operate")]
    [InlineData(0x05, "DNP3 FC05 DirectOperate")]
    public void ProcessFrame_SolicitedCrobControl_StampsRequestCommandAndDataPointAndCorrelatesWithResponse(
        byte controlFc,
        string expectedOperationName)
    {
        var crobTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Breaker_1_Cmd",
            ProtocolAddress: ProtocolAddress.Parse("G12V01:Idx1"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([crobTag]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        byte[] reqApp =
        [
            0xC4, controlFc,
            12, 1, 0x17, 0x01, 0x01,
            0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00
        ];

        var reqOut = decoder.ProcessFrame(
            CreateFrame(20, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, reqApp)),
            pair,
            TrafficDirection.ClientToServer);

        var cmd = Assert.Single(reqOut.CommandEvents);
        var dp = Assert.Single(reqOut.DataPoints);
        Assert.Empty(reqOut.TraceSpans);
        Assert.NotNull(cmd.TraceId);
        Assert.NotNull(cmd.SpanId);
        Assert.Equal(cmd.TraceId, dp.TraceId);
        Assert.Equal(cmd.SpanId, dp.SpanId);

        byte[] respApp =
        [
            0xC4, 0x81, 0x00, 0x00,
            12, 1, 0x17, 0x01, 0x01,
            0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00
        ];
        var respOut = decoder.ProcessFrame(
            CreateFrame(21, BaseTime.AddMilliseconds(25), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, respApp)),
            pair,
            TrafficDirection.ServerToClient);

        var tx = Assert.Single(respOut.Transactions);
        var span = Assert.Single(respOut.TraceSpans);

        Assert.Equal(cmd.TraceId, tx.TraceId);
        Assert.Equal(cmd.SpanId, tx.SpanId);
        Assert.Equal(cmd.TraceId, span.TraceId);
        Assert.Equal(cmd.SpanId, span.SpanId);
        Assert.Equal(expectedOperationName, span.OperationName);
        Assert.Equal(ProtocolAddress.Parse("G12V01:Idx1"), span.Attributes["dnp3.target_address"]);
        Assert.Equal("G12V01", span.Attributes["dnp3.object_groups"]);
        Assert.Equal(1, span.Attributes["tags.matched_count"]);
        Assert.Equal(1, span.Attributes["tags.changed_count"]);
        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.RequestSent);
        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.CommandIssued);
        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.TagValueChanged);
        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.ResponseReceived);
    }

    [Fact]
    public void FlushExpiredTimeouts_OnCrobAndReadRequests_EmitsTimeoutAndTimeoutAtEofSpansSharingPreAllocatedIds()
    {
        var crobTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Breaker_1_Cmd",
            ProtocolAddress: ProtocolAddress.Parse("G12V01:Idx1"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 1500);
        var tagEngine = new TagResolutionEngine([crobTag]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        // Request 1: CROB Select (SEQ=1) at T=0 -> expires mid-stream
        byte[] crobReq =
        [
            0xC1, 0x03,
            12, 1, 0x17, 0x01, 0x01,
            0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00
        ];
        var out1 = decoder.ProcessFrame(
            CreateFrame(30, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, crobReq)),
            pair,
            TrafficDirection.ClientToServer);
        var cmd1 = Assert.Single(out1.CommandEvents);
        var dp1 = Assert.Single(out1.DataPoints);

        // Request 2: Read Class 0/1 (SEQ=2) at T=+1000ms -> expires at EOF
        byte[] readReq = [0xC2, 0x01, 60, 2, 0x06];
        decoder.ProcessFrame(
            CreateFrame(31, BaseTime.AddMilliseconds(1000), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, readReq)),
            pair,
            TrafficDirection.ClientToServer);

        var midFlush = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(1600), isEndOfFile: false);
        var midTx = Assert.Single(midFlush.Transactions);
        var midSpan = Assert.Single(midFlush.TraceSpans);

        Assert.Equal(cmd1.TraceId, midTx.TraceId);
        Assert.Equal(cmd1.SpanId, midTx.SpanId);
        Assert.Equal(cmd1.TraceId, dp1.TraceId);
        Assert.Equal(cmd1.SpanId, dp1.SpanId);
        Assert.Equal(cmd1.TraceId, midSpan.TraceId);
        Assert.Equal(cmd1.SpanId, midSpan.SpanId);
        Assert.Equal("DNP3 FC03 Select", midSpan.OperationName);
        Assert.Equal(SpanOriginKind.Timeout, midSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Error, midSpan.StatusCode);
        Assert.Equal("TIMEOUT", midSpan.StatusMessage);
        Assert.Equal(1500.0, midSpan.DurationMs, precision: 5);
        Assert.Equal("G12V01", midSpan.Attributes["dnp3.object_groups"]);
        Assert.Equal(ProtocolAddress.Parse("G12V01:Idx1"), midSpan.Attributes["dnp3.target_address"]);
        Assert.Contains(midSpan.Events, e => e.Kind == SpanEventKind.CommandIssued);
        Assert.Contains(midSpan.Events, e => e.Kind == SpanEventKind.TagValueChanged);
        Assert.Contains(midSpan.Events, e => e.Kind == SpanEventKind.TimeoutExpired);

        var eofFlush = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(2000), isEndOfFile: true);
        var eofTx = Assert.Single(eofFlush.Transactions);
        var eofSpan = Assert.Single(eofFlush.TraceSpans);

        Assert.Equal(eofTx.TraceId, eofSpan.TraceId);
        Assert.Equal(eofTx.SpanId, eofSpan.SpanId);
        Assert.Equal("DNP3 FC01 Read", eofSpan.OperationName);
        Assert.Equal(SpanOriginKind.TimeoutAtEof, eofSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Error, eofSpan.StatusCode);
        Assert.Equal("TIMEOUT_AT_EOF", eofSpan.StatusMessage);
        Assert.Equal(1000.0, eofSpan.DurationMs, precision: 5);
        Assert.Equal("G60V02", eofSpan.Attributes["dnp3.object_groups"]);
        Assert.Contains(eofSpan.Events, e => e.Kind == SpanEventKind.TimeoutExpired);
    }

    [Theory]
    [InlineData(0x00, 0x01, TransactionStatusCode.Dnp3IinFuncNotSupported, "DNP3_IIN_FUNC_NOT_SUPPORTED")]
    [InlineData(0x00, 0x02, TransactionStatusCode.Dnp3IinObjectUnknown, "DNP3_IIN_OBJECT_UNKNOWN")]
    [InlineData(0x00, 0x04, TransactionStatusCode.Dnp3IinParamErr, "DNP3_IIN_PARAM_ERR")]
    [InlineData(0x00, 0x08, TransactionStatusCode.Dnp3IinEventBufferOverflow, "DNP3_IIN_EVENT_BUFFER_OVERFLOW")]
    [InlineData(0x00, 0x10, TransactionStatusCode.Dnp3IinAlreadyExecuting, "DNP3_IIN_ALREADY_EXECUTING")]
    [InlineData(0x00, 0x20, TransactionStatusCode.Dnp3IinConfigCorrupt, "DNP3_IIN_CONFIG_CORRUPT")]
    public void ProcessFrame_MatchedResponseWithIinError_PreservesOperationNameAndEmitsErrorSpanWithProtocolExceptionEvent(
        byte iin1,
        byte iin2,
        TransactionStatusCode expectedStatusCode,
        string expectedStatusMessage)
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        byte[] reqPayload = Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC6, 0x03, 12, 1, 0x06]);
        decoder.ProcessFrame(CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, reqPayload), pair, TrafficDirection.ClientToServer);

        DateTime respTime = BaseTime.AddMilliseconds(18.5);
        byte[] respPayload = Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xC6, 0x81, iin1, iin2]);
        var respOut = decoder.ProcessFrame(CreateFrame(2, respTime, TrafficDirection.ServerToClient, respPayload), pair, TrafficDirection.ServerToClient);

        var tx = Assert.Single(respOut.Transactions);
        var span = Assert.Single(respOut.TraceSpans);

        Assert.Equal(tx.TraceId, span.TraceId);
        Assert.Equal(tx.SpanId, span.SpanId);
        Assert.Equal("DNP3 FC03 Select", span.OperationName);
        Assert.Equal(SpanOriginKind.RequestResponse, span.OriginKind);
        Assert.Equal(SpanStatusCode.Error, span.StatusCode);
        Assert.Equal(expectedStatusMessage, span.StatusMessage);
        Assert.Equal((int)iin1, span.Attributes["dnp3.iin1"]);
        Assert.Equal((int)iin2, span.Attributes["dnp3.iin2"]);

        var exEvent = Assert.Single(span.Events, e => e.Kind == SpanEventKind.ProtocolException);
        Assert.Equal(respTime, exEvent.TimestampUtc);
        Assert.Equal(expectedStatusCode, exEvent.Fields["status_code"]);
        Assert.Equal((int)iin1, exEvent.Fields["iin1"]);
        Assert.Equal((int)iin2, exEvent.Fields["iin2"]);
    }

    [Fact]
    public void ProcessFrame_SolicitedResponseWithTwelveChangedTags_CapsTagValueChangedEventsAtTenAndSetsTruncatedFlag()
    {
        var tags = Enumerable.Range(0, 12)
            .Select(i => new TagDefinition(
                Id: Guid.NewGuid(),
                DevicePairId: PairId,
                TagName: $"Analog_{i:D2}",
                ProtocolAddress: ProtocolAddress.Parse($"G30V02:Idx{i}"),
                DataType: TagDataType.Int16,
                ScaleMultiplier: 1.0,
                ScaleOffset: 0.0,
                EngineeringUnits: null,
                Description: null))
            .ToArray();

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        // Poll 1: all 12 tags change (first observation)
        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC1, 0x01, 30, 2, 0x00, 0x00, 0x0B])),
            pair,
            TrafficDirection.ClientToServer);

        byte[] resp1App = new byte[4 + 5 + (12 * 3)];
        resp1App[0] = 0xC1;
        resp1App[1] = 0x81;
        resp1App[2] = 0x00;
        resp1App[3] = 0x00;
        resp1App[4] = 30;
        resp1App[5] = 2;
        resp1App[6] = 0x00;
        resp1App[7] = 0x00;
        resp1App[8] = 0x0B;
        for (int i = 0; i < 12; i++)
        {
            int offset = 9 + (i * 3);
            resp1App[offset] = 0x01; // Online
            resp1App[offset + 1] = (byte)(i + 1);
            resp1App[offset + 2] = 0x00;
        }

        var out1 = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(20), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, resp1App)),
            pair,
            TrafficDirection.ServerToClient);

        var span1 = Assert.Single(out1.TraceSpans);
        Assert.Equal(12, out1.DataPoints.Count);
        Assert.Equal(12, span1.Attributes["tags.matched_count"]);
        Assert.Equal(12, span1.Attributes["tags.changed_count"]);
        Assert.Equal(true, span1.Attributes["tags.changes_truncated"]);
        Assert.Equal(10, span1.Events.Count(e => e.Kind == SpanEventKind.TagValueChanged));
        Assert.Equal("Analog_00", span1.Events.First(e => e.Kind == SpanEventKind.TagValueChanged).Fields["tag_name"]);
        Assert.All(out1.DataPoints, dp =>
        {
            Assert.Equal(span1.TraceId, dp.TraceId);
            Assert.Equal(span1.SpanId, dp.SpanId);
        });

        // Poll 2: only 2 tags change out of 12 matched -> no truncation flag
        decoder.ProcessFrame(
            CreateFrame(3, BaseTime.AddMilliseconds(50), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC2, 0x01, 30, 2, 0x00, 0x00, 0x0B])),
            pair,
            TrafficDirection.ClientToServer);

        byte[] resp2App = (byte[])resp1App.Clone();
        resp2App[0] = 0xC2;
        resp2App[10] = 99;
        resp2App[13] = 100;

        var out2 = decoder.ProcessFrame(
            CreateFrame(4, BaseTime.AddMilliseconds(70), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, resp2App)),
            pair,
            TrafficDirection.ServerToClient);

        var span2 = Assert.Single(out2.TraceSpans);
        Assert.Equal(12, span2.Attributes["tags.matched_count"]);
        Assert.Equal(2, span2.Attributes["tags.changed_count"]);
        Assert.False(span2.Attributes.ContainsKey("tags.changes_truncated"));
        Assert.Equal(2, span2.Events.Count(e => e.Kind == SpanEventKind.TagValueChanged));
    }

    [Fact]
    public void ProcessFrame_MatchedResponseWithHandlerEmittingDataPointAndCommand_StampsBothWithoutChangingHandlerInterface()
    {
        var syntheticTagId = Guid.NewGuid();
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var customHandler = new ResponseEmittingStubHandler(group: 99, syntheticTagId);
        var registry = new Dnp3HandlerRegistry([customHandler]);
        var decoder = new Dnp3Decoder(redEngine, registry);

        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC3, 0x01])),
            pair,
            TrafficDirection.ClientToServer);

        var respOut = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(15), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xC3, 0x81, 0x00, 0x00, 99, 1, 0x06])),
            pair,
            TrafficDirection.ServerToClient);

        var span = Assert.Single(respOut.TraceSpans);
        var dp = Assert.Single(respOut.DataPoints);
        var cmd = Assert.Single(respOut.CommandEvents);

        Assert.Equal(span.TraceId, dp.TraceId);
        Assert.Equal(span.SpanId, dp.SpanId);
        Assert.Equal(span.TraceId, cmd.TraceId);
        Assert.Equal(span.SpanId, cmd.SpanId);
        Assert.Equal("G99V01", span.Attributes["dnp3.object_groups"]);
        Assert.Equal(ProtocolAddress.Parse("G99V01:Idx0"), span.Attributes["dnp3.target_address"]);
        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.CommandIssued);
    }

    [Theory]
    [InlineData(0x00, 0x00, SpanStatusCode.Ok, null, false)]
    [InlineData(0x00, 0x08, SpanStatusCode.Error, "DNP3_IIN_EVENT_BUFFER_OVERFLOW", true)]
    public void ProcessFrame_UnsolicitedResponseFc82_EmitsConsumerSpanAndStampsDataPointsWithoutTransaction(
        byte iin1,
        byte iin2,
        SpanStatusCode expectedStatus,
        string? expectedStatusMessage,
        bool expectExceptionEvent)
    {
        var eventTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Trip_Event_BI",
            ProtocolAddress: ProtocolAddress.Parse("G01V02:Idx4"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([eventTag]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        // AC = 0xF3 -> FIR=1, FIN=1, CON=1, UNS=1, SEQ=3
        byte[] appFragment =
        [
            0xF3, 0x82, iin1, iin2,
            2, 1, 0x17, 0x01, 0x04, 0x81
        ];
        byte[] payload = Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, appFragment);

        var output = decoder.ProcessFrame(
            CreateFrame(50, BaseTime, TrafficDirection.ServerToClient, payload),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Empty(output.Transactions);
        var dp = Assert.Single(output.DataPoints);
        var span = Assert.Single(output.TraceSpans);

        Assert.Null(span.ParentSpanId);
        Assert.Equal(dp.TraceId, span.TraceId);
        Assert.Equal(dp.SpanId, span.SpanId);
        Assert.Equal("SCADA_Master", span.ServiceName);
        Assert.Equal("DNP3 FC130 UnsolicitedResponse", span.OperationName);
        Assert.Equal(SpanKind.Consumer, span.SpanKind);
        Assert.Equal(SpanOriginKind.Unsolicited, span.OriginKind);
        Assert.Equal(expectedStatus, span.StatusCode);
        Assert.Equal(expectedStatusMessage, span.StatusMessage);
        Assert.Equal(TrafficDirection.ServerToClient, span.Direction);
        Assert.Equal(0.0, span.DurationMs);
        Assert.Equal(BaseTime, span.StartTimeUtc);
        Assert.Equal(BaseTime, span.EndTimeUtc);
        Assert.Null(span.RequestFrameNumber);
        Assert.Equal(50L, span.ResponseFrameNumber);
        Assert.Equal("3", span.TransactionId);
        Assert.Equal((short)0x82, span.FunctionCode);

        Assert.Equal(100, span.Attributes["dnp3.src"]);
        Assert.Equal(1, span.Attributes["dnp3.dst"]);
        Assert.Equal(3, span.Attributes["dnp3.app_seq"]);
        Assert.Equal(true, span.Attributes["dnp3.fir"]);
        Assert.Equal(true, span.Attributes["dnp3.fin"]);
        Assert.Equal(true, span.Attributes["dnp3.con"]);
        Assert.Equal(true, span.Attributes["dnp3.uns"]);
        Assert.Equal((int)iin1, span.Attributes["dnp3.iin1"]);
        Assert.Equal((int)iin2, span.Attributes["dnp3.iin2"]);
        Assert.Equal("G02V01", span.Attributes["dnp3.object_groups"]);
        Assert.Equal(1, span.Attributes["tags.matched_count"]);
        Assert.Equal(1, span.Attributes["tags.changed_count"]);
        Assert.False(span.Attributes.ContainsKey("protocol.unpaired"));

        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.ResponseReceived);
        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.TagValueChanged && (string)e.Fields["tag_name"]! == "Trip_Event_BI");
        Assert.Equal(expectExceptionEvent, span.Events.Any(e => e.Kind == SpanEventKind.ProtocolException));

        var eofFlush = decoder.FlushExpiredTimeouts(BaseTime.AddSeconds(30), isEndOfFile: true);
        Assert.Empty(eofFlush.Transactions);
        var confirmTimeout = Assert.Single(eofFlush.TraceSpans);
        Assert.Equal(SpanOriginKind.ConfirmTimeout, confirmTimeout.OriginKind);
        Assert.Equal(span.TraceId, confirmTimeout.TraceId);
        Assert.Equal(span.SpanId, confirmTimeout.ParentSpanId);
    }

    [Fact]
    public void ProcessFrame_DirectOperateNoAckFc06_EmitsProducerSpanStampsCommandAndPointAndRegistersNoTimeout()
    {
        var crobTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Breaker_Direct_NoAck",
            ProtocolAddress: ProtocolAddress.Parse("G12V01:Idx2"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 1000);
        var tagEngine = new TagResolutionEngine([crobTag]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        byte[] appFragment =
        [
            0xC7, 0x06,
            12, 1, 0x17, 0x01, 0x02,
            0x81, 0x01, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];
        byte[] payload = Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, appFragment);

        var output = decoder.ProcessFrame(
            CreateFrame(60, BaseTime, TrafficDirection.ClientToServer, payload),
            pair,
            TrafficDirection.ClientToServer);

        Assert.Empty(output.Transactions);
        var cmd = Assert.Single(output.CommandEvents);
        var dp = Assert.Single(output.DataPoints);
        var span = Assert.Single(output.TraceSpans);

        Assert.Null(span.ParentSpanId);
        Assert.Equal(cmd.TraceId, span.TraceId);
        Assert.Equal(cmd.SpanId, span.SpanId);
        Assert.Equal(dp.TraceId, span.TraceId);
        Assert.Equal(dp.SpanId, span.SpanId);
        Assert.Equal("Feeder1_RTU", span.ServiceName);
        Assert.Equal("DNP3 FC06 DirectOperateNoAck", span.OperationName);
        Assert.Equal(SpanKind.Producer, span.SpanKind);
        Assert.Equal(SpanOriginKind.DirectNoAck, span.OriginKind);
        Assert.Equal(SpanStatusCode.Ok, span.StatusCode);
        Assert.Null(span.StatusMessage);
        Assert.Equal(TrafficDirection.ClientToServer, span.Direction);
        Assert.Equal(0.0, span.DurationMs);
        Assert.Equal(60L, span.RequestFrameNumber);
        Assert.Null(span.ResponseFrameNumber);
        Assert.Equal("7", span.TransactionId);
        Assert.Equal((short)6, span.FunctionCode);
        Assert.Equal("G12V01", span.Attributes["dnp3.object_groups"]);
        Assert.Equal(ProtocolAddress.Parse("G12V01:Idx2"), span.Attributes["dnp3.target_address"]);
        Assert.Equal(1, span.Attributes["tags.matched_count"]);
        Assert.Equal(1, span.Attributes["tags.changed_count"]);

        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.RequestSent);
        var cmdEvent = Assert.Single(span.Events, e => e.Kind == SpanEventKind.CommandIssued);
        Assert.Equal(CommandType.Dnp3DirectOperate, cmdEvent.Fields["command_type"]);
        Assert.Equal(Dnp3ControlAction.Trip, cmdEvent.Fields["control_action"]);
        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.TagValueChanged);

        // Must NOT register pending timeout
        var eofFlush = decoder.FlushExpiredTimeouts(BaseTime.AddSeconds(10), isEndOfFile: true);
        Assert.Empty(eofFlush.Transactions);
        Assert.Empty(eofFlush.TraceSpans);
    }

    [Fact]
    public void ProcessFrame_DirectOperateNoAckWithoutObjects_StillEmitsDirectNoAckSpanWithCommandIssuedEvent()
    {
        var pair = CreateNamedPair();
        var decoder = new Dnp3Decoder(new VirtualClockRedEngine(1000), new Dnp3HandlerRegistry([]));

        byte[] payload = Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC1, 0x06]);
        var output = decoder.ProcessFrame(CreateFrame(61, BaseTime, TrafficDirection.ClientToServer, payload), pair, TrafficDirection.ClientToServer);

        Assert.Empty(output.Transactions);
        var span = Assert.Single(output.TraceSpans);
        Assert.Equal(SpanOriginKind.DirectNoAck, span.OriginKind);
        Assert.Equal("DNP3 FC06 DirectOperateNoAck", span.OperationName);
        var cmdEvent = Assert.Single(span.Events, e => e.Kind == SpanEventKind.CommandIssued);
        Assert.Equal(6, cmdEvent.Fields["function_code"]);
    }

    [Fact]
    public void ProcessFrame_UnpairedFc81Responses_EmitZeroDurationOrphanResponseSpansWithoutTransactions()
    {
        var biTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Orphan_Point",
            ProtocolAddress: ProtocolAddress.Parse("G01V02:Idx0"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([biTag]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        // 1. Orphan FC 0x81 without IIN error
        byte[] orphanOkPayload = Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xC2, 0x81, 0x00, 0x00, 1, 2, 0x00, 0x00, 0x00, 0x81]);
        var okOut = decoder.ProcessFrame(CreateFrame(70, BaseTime, TrafficDirection.ServerToClient, orphanOkPayload), pair, TrafficDirection.ServerToClient);

        Assert.Empty(okOut.Transactions);
        var dp = Assert.Single(okOut.DataPoints);
        var okSpan = Assert.Single(okOut.TraceSpans);
        Assert.Equal(dp.TraceId, okSpan.TraceId);
        Assert.Equal(dp.SpanId, okSpan.SpanId);
        Assert.Equal("SCADA_Master", okSpan.ServiceName);
        Assert.Equal("DNP3 FC129 Response", okSpan.OperationName);
        Assert.Equal(SpanKind.Consumer, okSpan.SpanKind);
        Assert.Equal(SpanOriginKind.OrphanResponse, okSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Unset, okSpan.StatusCode);
        Assert.Equal("ORPHAN_RESPONSE", okSpan.StatusMessage);
        Assert.Equal(0.0, okSpan.DurationMs);
        Assert.Null(okSpan.RequestFrameNumber);
        Assert.Equal(70L, okSpan.ResponseFrameNumber);
        Assert.Equal(true, okSpan.Attributes["protocol.unpaired"]);
        Assert.Contains(okSpan.Events, e => e.Kind == SpanEventKind.ResponseReceived);

        // 2. Orphan FC 0x81 with IIN error
        byte[] orphanErrPayload = Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xC3, 0x81, 0x00, 0x04]);
        var errOut = decoder.ProcessFrame(CreateFrame(71, BaseTime.AddMilliseconds(5), TrafficDirection.ServerToClient, orphanErrPayload), pair, TrafficDirection.ServerToClient);

        Assert.Empty(errOut.Transactions);
        var errSpan = Assert.Single(errOut.TraceSpans);
        Assert.Equal("SCADA_Master", errSpan.ServiceName);
        Assert.Equal("DNP3 FC129 Response", errSpan.OperationName);
        Assert.Equal(SpanOriginKind.OrphanResponse, errSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Error, errSpan.StatusCode);
        Assert.Equal("DNP3_IIN_PARAM_ERR", errSpan.StatusMessage);
        Assert.Equal(true, errSpan.Attributes["protocol.unpaired"]);
        Assert.Contains(errSpan.Events, e => e.Kind == SpanEventKind.ProtocolException);
    }

    [Theory]
    [InlineData(TrafficDirection.ClientToServer, new byte[] { 0x05, 0x64, 0x05, 0xC0, 0x01, 0x00 }, "Feeder1_RTU", SpanKind.Client, false)]
    [InlineData(TrafficDirection.ServerToClient, new byte[] { 0x05, 0x64, 0x08, 0x44, 0x01, 0x00, 0x64, 0x00, 0xAA, 0xBB, 0xC0, 0xC5, 0x81, 0xCC, 0xDD }, "SCADA_Master", SpanKind.Consumer, true)]
    public void ProcessFrame_MalformedDnp3Frames_EmitsZeroDurationMalformedSpanAndStampsTransaction(
        TrafficDirection direction,
        byte[] payload,
        string expectedServiceName,
        SpanKind expectedSpanKind,
        bool hasParsedAppHeader)
    {
        var pair = CreateNamedPair();
        var decoder = new Dnp3Decoder(new VirtualClockRedEngine(2000), new Dnp3HandlerRegistry([]));

        var output = decoder.ProcessFrame(CreateFrame(80, BaseTime, direction, payload), pair, direction);

        var tx = Assert.Single(output.Transactions);
        var span = Assert.Single(output.TraceSpans);

        Assert.NotNull(tx.TraceId);
        Assert.NotNull(tx.SpanId);
        Assert.Equal(tx.TraceId, span.TraceId);
        Assert.Equal(tx.SpanId, span.SpanId);
        Assert.Equal(expectedServiceName, span.ServiceName);
        Assert.Equal("DNP3 MalformedFrame", span.OperationName);
        Assert.Equal(expectedSpanKind, span.SpanKind);
        Assert.Equal(SpanOriginKind.Malformed, span.OriginKind);
        Assert.Equal(SpanStatusCode.Error, span.StatusCode);
        Assert.Equal("MALFORMED", span.StatusMessage);
        Assert.Equal(0.0, span.DurationMs);
        Assert.Equal(direction, span.Direction);
        Assert.Empty(span.Events);

        if (hasParsedAppHeader)
        {
            Assert.Equal(100, span.Attributes["dnp3.src"]);
            Assert.Equal(1, span.Attributes["dnp3.dst"]);
            Assert.Equal(5, span.Attributes["dnp3.app_seq"]);
        }
    }

    [Fact]
    public void ProcessFrame_AndFlushExpiredTimeouts_WhenStoreTraceSpansDisabled_EmitsZeroSpansAndNullIdsAcrossAllPaths()
    {
        var crobTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Breaker_OptOut",
            ProtocolAddress: ProtocolAddress.Parse("G12V01:Idx1"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var biTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "BI_OptOut",
            ProtocolAddress: ProtocolAddress.Parse("G01V02:Idx0"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 1000);
        var tagEngine = new TagResolutionEngine([crobTag, biTag]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine, storeTraceSpans: false);

        // 1. Solicited Read request + response
        var readReqOut = decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC1, 0x01, 60, 1, 0x06])),
            pair,
            TrafficDirection.ClientToServer);
        var readRespOut = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(15), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xC1, 0x81, 0x00, 0x00, 1, 2, 0x00, 0x00, 0x00, 0x81])),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Empty(readReqOut.TraceSpans);
        Assert.Empty(readRespOut.TraceSpans);
        var readTx = Assert.Single(readRespOut.Transactions);
        var readDp = Assert.Single(readRespOut.DataPoints);
        Assert.Null(readTx.TraceId);
        Assert.Null(readTx.SpanId);
        Assert.Null(readDp.TraceId);
        Assert.Null(readDp.SpanId);

        // 2. Solicited CROB request + IIN error response
        byte[] crobReq = [0xC2, 0x05, 12, 1, 0x17, 0x01, 0x01, 0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00];
        var crobReqOut = decoder.ProcessFrame(
            CreateFrame(3, BaseTime.AddMilliseconds(20), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, crobReq)),
            pair,
            TrafficDirection.ClientToServer);
        var crobCmd = Assert.Single(crobReqOut.CommandEvents);
        var crobDp = Assert.Single(crobReqOut.DataPoints);
        Assert.Empty(crobReqOut.TraceSpans);
        Assert.Null(crobCmd.TraceId);
        Assert.Null(crobCmd.SpanId);
        Assert.Null(crobDp.TraceId);
        Assert.Null(crobDp.SpanId);

        var crobRespOut = decoder.ProcessFrame(
            CreateFrame(4, BaseTime.AddMilliseconds(30), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xC2, 0x81, 0x00, 0x04])),
            pair,
            TrafficDirection.ServerToClient);
        Assert.Empty(crobRespOut.TraceSpans);
        var crobTx = Assert.Single(crobRespOut.Transactions);
        Assert.Null(crobTx.TraceId);
        Assert.Null(crobTx.SpanId);

        // 3. Unsolicited FC 0x82
        var unsOut = decoder.ProcessFrame(
            CreateFrame(5, BaseTime.AddMilliseconds(40), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xF3, 0x82, 0x00, 0x00, 2, 1, 0x17, 0x01, 0x00, 0x01])),
            pair,
            TrafficDirection.ServerToClient);
        Assert.Empty(unsOut.TraceSpans);
        Assert.Empty(unsOut.Transactions);
        var unsDp = Assert.Single(unsOut.DataPoints);
        Assert.Null(unsDp.TraceId);
        Assert.Null(unsDp.SpanId);

        // 4. Direct Operate No-Ack FC 0x06
        byte[] noAckReq = [0xC4, 0x06, 12, 1, 0x17, 0x01, 0x01, 0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00];
        var noAckOut = decoder.ProcessFrame(
            CreateFrame(6, BaseTime.AddMilliseconds(50), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, noAckReq)),
            pair,
            TrafficDirection.ClientToServer);
        Assert.Empty(noAckOut.TraceSpans);
        var noAckCmd = Assert.Single(noAckOut.CommandEvents);
        var noAckDp = Assert.Single(noAckOut.DataPoints);
        Assert.Null(noAckCmd.TraceId);
        Assert.Null(noAckCmd.SpanId);
        Assert.Null(noAckDp.TraceId);
        Assert.Null(noAckDp.SpanId);

        // 5. Orphan FC 0x81 + Malformed
        var orphanOut = decoder.ProcessFrame(
            CreateFrame(7, BaseTime.AddMilliseconds(60), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xC9, 0x81, 0x00, 0x00])),
            pair,
            TrafficDirection.ServerToClient);
        Assert.Empty(orphanOut.TraceSpans);
        Assert.Empty(orphanOut.Transactions);

        var malformedOut = decoder.ProcessFrame(
            CreateFrame(8, BaseTime.AddMilliseconds(70), TrafficDirection.ClientToServer, [0x05, 0x64, 0x03]),
            pair,
            TrafficDirection.ClientToServer);
        Assert.Empty(malformedOut.TraceSpans);
        var malformedTx = Assert.Single(malformedOut.Transactions);
        Assert.Null(malformedTx.TraceId);
        Assert.Null(malformedTx.SpanId);

        // 6. Timeout + TimeoutAtEof
        decoder.ProcessFrame(
            CreateFrame(9, BaseTime.AddMilliseconds(100), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC5, 0x01, 60, 1, 0x06])),
            pair,
            TrafficDirection.ClientToServer);
        var midFlush = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(1200), isEndOfFile: false);
        Assert.Empty(midFlush.TraceSpans);
        var midTx = Assert.Single(midFlush.Transactions);
        Assert.Null(midTx.TraceId);
        Assert.Null(midTx.SpanId);

        decoder.ProcessFrame(
            CreateFrame(10, BaseTime.AddMilliseconds(1300), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC6, 0x01, 60, 1, 0x06])),
            pair,
            TrafficDirection.ClientToServer);
        var eofFlush = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(1500), isEndOfFile: true);
        Assert.Empty(eofFlush.TraceSpans);
        var eofTx = Assert.Single(eofFlush.Transactions);
        Assert.Null(eofTx.TraceId);
        Assert.Null(eofTx.SpanId);
    }

    [Fact]
    public void ProcessFrame_DeterministicIdsAndAddressMismatchIsolation_AreConsistentAcrossReplays()
    {
        var unnamedPair = CreateNamedPair(clientName: null, serverName: null);
        byte[] reqPayload = Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC1, 0x01, 60, 1, 0x06]);
        byte[] wrongResp = Dnp3DecoderTests.BuildDnp3LinkFrame(1, 200, 0xC0, [0xC1, 0x81, 0x00, 0x00]);
        byte[] rightResp = Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xC1, 0x81, 0x00, 0x00]);

        TraceSpanRecord RunOnce()
        {
            var decoder = new Dnp3Decoder(new VirtualClockRedEngine(2000), new Dnp3HandlerRegistry([]));
            decoder.ProcessFrame(CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, reqPayload), unnamedPair, TrafficDirection.ClientToServer);

            var wrongOut = decoder.ProcessFrame(CreateFrame(2, BaseTime.AddMilliseconds(5), TrafficDirection.ServerToClient, wrongResp), unnamedPair, TrafficDirection.ServerToClient);
            Assert.Empty(wrongOut.Transactions);
            Assert.Empty(wrongOut.TraceSpans);

            var rightOut = decoder.ProcessFrame(CreateFrame(3, BaseTime.AddMilliseconds(15), TrafficDirection.ServerToClient, rightResp), unnamedPair, TrafficDirection.ServerToClient);
            return Assert.Single(rightOut.TraceSpans);
        }

        var firstSpan = RunOnce();
        var secondSpan = RunOnce();

        Assert.Equal(firstSpan.TraceId, secondSpan.TraceId);
        Assert.Equal(firstSpan.SpanId, secondSpan.SpanId);
        Assert.Equal("10.0.1.5:1", firstSpan.ClientEndpoint);
        Assert.Equal("10.0.1.10:100", firstSpan.ServerEndpoint);
        Assert.Equal("10.0.1.10:100", firstSpan.ServiceName);
    }

    private sealed class ResponseEmittingStubHandler(ushort group, Guid tagId) : IDnp3ObjectGroupHandler
    {
        public ushort Group { get; } = group;

        public void ExtractObjects(
            DissectedFrame frame,
            DeviceEndpointPair pair,
            TrafficDirection direction,
            ushort variation,
            ReadOnlySpan<byte> objectData,
            ICollection<ExtractedDataPointRecord> dataPointsOut,
            ICollection<CapturedCommandEventRecord> commandsOut)
        {
            if (direction != TrafficDirection.ServerToClient)
            {
                return;
            }

            dataPointsOut.Add(new ExtractedDataPointRecord(
                PacketTimestamp: frame.TimestampUtc,
                EventTimestamp: null,
                SessionId: pair.SessionId,
                TagId: tagId,
                FrameNumber: frame.FrameNumber,
                Direction: direction,
                UnscaledNumericValue: 42.0,
                ScaledNumericValue: 42.0,
                BooleanValue: null,
                RawHex: "2A00",
                QualityFlags: PointQualityFlags.Online,
                IsValueChange: true));

            commandsOut.Add(new CapturedCommandEventRecord(
                Timestamp: frame.TimestampUtc,
                SessionId: pair.SessionId,
                DevicePairId: pair.Id,
                FrameNumber: frame.FrameNumber,
                Direction: direction,
                Protocol: ProtocolType.Dnp3,
                FunctionCode: 0x81,
                CommandType: CommandType.Dnp3DirectOperate,
                TargetAddress: ProtocolAddress.Parse("G99V01:Idx0"),
                ControlAction: Dnp3ControlAction.PulseOn,
                CommandCount: 1,
                PulseOnMs: 100,
                PulseOffMs: 0,
                UnscaledCommandValue: 1.0,
                RawPduBytes: frame.RawApplicationPayload));
        }
    }
}
