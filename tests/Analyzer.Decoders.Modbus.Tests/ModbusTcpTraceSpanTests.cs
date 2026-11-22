using System.Net;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;
using Analyzer.Decoders.Modbus;

namespace Analyzer.Decoders.Modbus.Tests;

public class ModbusTcpTraceSpanTests
{
    private static readonly Guid SessionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid PairId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly IPAddress ClientIp = IPAddress.Parse("10.0.1.10");
    private static readonly IPAddress ServerIp = IPAddress.Parse("10.0.1.20");
    private static readonly DateTime BaseTime = new(2026, 11, 22, 8, 0, 0, DateTimeKind.Utc);

    private static DeviceEndpointPair CreateNamedPair(
        int? unitId = 1,
        string? clientName = "SEL_RTAC",
        string? serverName = "Feeder1_Relay") =>
        new(
            Id: PairId,
            SessionId: SessionId,
            Name: "RTAC_to_Relay",
            Protocol: ProtocolType.ModbusTcp,
            ClientIp: ClientIp,
            ServerIp: ServerIp,
            ClientProtocolAddressId: null,
            ServerProtocolAddressId: unitId,
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
            SourcePort: direction == TrafficDirection.ClientToServer ? 50123 : 502,
            DestIp: direction == TrafficDirection.ClientToServer ? ServerIp : ClientIp,
            DestPort: direction == TrafficDirection.ClientToServer ? 502 : 50123,
            ProtocolName: ProtocolType.ModbusTcp,
            RawApplicationPayload: payload);

    private static byte[] BuildMbap(ushort txId, byte unitId, ReadOnlySpan<byte> pdu)
    {
        byte[] frame = new byte[7 + pdu.Length];
        frame[0] = (byte)(txId >> 8);
        frame[1] = (byte)(txId & 0xFF);
        frame[2] = 0x00;
        frame[3] = 0x00;
        ushort mbapLen = (ushort)(1 + pdu.Length);
        frame[4] = (byte)(mbapLen >> 8);
        frame[5] = (byte)(mbapLen & 0xFF);
        frame[6] = unitId;
        pdu.CopyTo(frame.AsSpan(7));
        return frame;
    }

    [Theory]
    [InlineData(0x01, "COIL:00000", TagDataType.Bool, new byte[] { 0x01, 0x01 }, "Modbus FC01 ReadCoils", ModbusRegisterType.Coil)]
    [InlineData(0x02, "DI:10001", TagDataType.Bool, new byte[] { 0x01, 0x01 }, "Modbus FC02 ReadDiscreteInputs", ModbusRegisterType.DiscreteInput)]
    [InlineData(0x03, "HR:40001", TagDataType.UInt16, new byte[] { 0x02, 0x05, 0x64 }, "Modbus FC03 ReadHoldingRegisters", ModbusRegisterType.Holding)]
    [InlineData(0x04, "IR:30001", TagDataType.UInt16, new byte[] { 0x02, 0x01, 0x00 }, "Modbus FC04 ReadInputRegisters", ModbusRegisterType.Input)]
    public void ProcessFrame_MatchedReadExchange_EmitsSpanWithOperationAttributesEventsAndCorrelatedIds(
        byte fc,
        string address,
        TagDataType dataType,
        byte[] responseBodyAfterFc,
        string expectedOperation,
        ModbusRegisterType expectedRegisterType)
    {
        var tagId = Guid.NewGuid();
        var tag = new TagDefinition(
            Id: tagId,
            DevicePairId: PairId,
            TagName: "Test_Point",
            ProtocolAddress: ProtocolAddress.Parse(address),
            DataType: dataType,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([tag]);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine);

        byte[] reqPayload = BuildMbap(txId: 10, unitId: 1, [fc, 0x00, 0x00, 0x00, 0x01]);
        var reqOut = decoder.ProcessFrame(CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, reqPayload), pair, TrafficDirection.ClientToServer);
        Assert.Empty(reqOut.TraceSpans);

        byte[] respPdu = [fc, .. responseBodyAfterFc];
        byte[] respPayload = BuildMbap(txId: 10, unitId: 1, respPdu);
        DateTime respTime = BaseTime.AddMilliseconds(35.5);

        var respOut = decoder.ProcessFrame(CreateFrame(2, respTime, TrafficDirection.ServerToClient, respPayload), pair, TrafficDirection.ServerToClient);

        var tx = Assert.Single(respOut.Transactions);
        var dp = Assert.Single(respOut.DataPoints);
        var span = Assert.Single(respOut.TraceSpans);

        Assert.NotNull(tx.TraceId);
        Assert.NotNull(tx.SpanId);
        Assert.Equal(tx.TraceId, span.TraceId);
        Assert.Equal(tx.SpanId, span.SpanId);
        Assert.Equal(tx.TraceId, dp.TraceId);
        Assert.Equal(tx.SpanId, dp.SpanId);

        Assert.Null(span.ParentSpanId);
        Assert.Equal(BaseTime, span.StartTimeUtc);
        Assert.Equal(respTime, span.EndTimeUtc);
        Assert.Equal(35.5, span.DurationMs, precision: 5);
        Assert.Equal(SessionId, span.SessionId);
        Assert.Equal(PairId, span.DevicePairId);
        Assert.Equal("Feeder1_Relay", span.ServiceName);
        Assert.Equal("SEL_RTAC", span.ClientEndpoint);
        Assert.Equal("Feeder1_Relay", span.ServerEndpoint);
        Assert.Equal(expectedOperation, span.OperationName);
        Assert.Equal(SpanKind.Client, span.SpanKind);
        Assert.Equal(SpanOriginKind.RequestResponse, span.OriginKind);
        Assert.Equal(SpanStatusCode.Ok, span.StatusCode);
        Assert.Null(span.StatusMessage);
        Assert.Equal(ProtocolType.ModbusTcp, span.Protocol);
        Assert.Equal(TrafficDirection.ClientToServer, span.Direction);
        Assert.Equal(1L, span.RequestFrameNumber);
        Assert.Equal(2L, span.ResponseFrameNumber);
        Assert.Equal("10", span.TransactionId);
        Assert.Equal((short)fc, span.FunctionCode);

        Assert.Equal(ProtocolType.ModbusTcp, span.Attributes["protocol"]);
        Assert.Equal(SessionId, span.Attributes["session.id"]);
        Assert.Equal(PairId, span.Attributes["device_pair.id"]);
        Assert.Equal("RTAC_to_Relay", span.Attributes["device_pair.name"]);
        Assert.Equal("10.0.1.10", span.Attributes["net.client.ip"]);
        Assert.Equal(50123, span.Attributes["net.client.port"]);
        Assert.Equal("10.0.1.20", span.Attributes["net.server.ip"]);
        Assert.Equal(502, span.Attributes["net.server.port"]);
        Assert.Equal(1L, span.Attributes["pcap.request_frame"]);
        Assert.Equal(2L, span.Attributes["pcap.response_frame"]);
        Assert.Equal(reqPayload.Length, span.Attributes["pcap.request_bytes"]);
        Assert.Equal(respPayload.Length, span.Attributes["pcap.response_bytes"]);
        Assert.Equal(1, span.Attributes["modbus.unit_id"]);
        Assert.Equal(expectedRegisterType, span.Attributes["modbus.register_type"]);
        Assert.Equal(0, span.Attributes["modbus.start_address"]);
        Assert.Equal(1, span.Attributes["modbus.quantity"]);
        Assert.Equal(1, span.Attributes["tags.matched_count"]);
        Assert.Equal(1, span.Attributes["tags.changed_count"]);
        Assert.False(span.Attributes.ContainsKey("tags.changes_truncated"));

        Assert.Equal(3, span.Events.Count);
        Assert.Equal(SpanEventKind.RequestSent, span.Events[0].Kind);
        Assert.Equal(BaseTime, span.Events[0].TimestampUtc);
        Assert.Equal(SpanEventKind.ResponseReceived, span.Events[1].Kind);
        Assert.Equal(respTime, span.Events[1].TimestampUtc);
        Assert.Equal(SpanEventKind.TagValueChanged, span.Events[2].Kind);
        Assert.Equal("Test_Point", span.Events[2].Fields["tag_name"]);
    }

    [Theory]
    [InlineData(0x05, "COIL:00005", new byte[] { 0x05, 0x00, 0x05, 0xFF, 0x00 }, new byte[] { 0x05, 0x00, 0x05, 0xFF, 0x00 }, "Modbus FC05 WriteSingleCoil")]
    [InlineData(0x06, "HR:40006", new byte[] { 0x06, 0x00, 0x05, 0x04, 0xD2 }, new byte[] { 0x06, 0x00, 0x05, 0x04, 0xD2 }, "Modbus FC06 WriteSingleRegister")]
    [InlineData(0x0F, "COIL:00005", new byte[] { 0x0F, 0x00, 0x05, 0x00, 0x01, 0x01, 0x01 }, new byte[] { 0x0F, 0x00, 0x05, 0x00, 0x01 }, "Modbus FC15 WriteMultipleCoils")]
    [InlineData(0x10, "HR:40006", new byte[] { 0x10, 0x00, 0x05, 0x00, 0x01, 0x02, 0x04, 0xD2 }, new byte[] { 0x10, 0x00, 0x05, 0x00, 0x01 }, "Modbus FC16 WriteMultipleRegisters")]
    public void ProcessFrame_WriteRequestAndResponse_CorrelatesCommandEventRequestDataPointTransactionAndSpan(
        byte fc,
        string address,
        byte[] reqPdu,
        byte[] respPdu,
        string expectedOperation)
    {
        var tagId = Guid.NewGuid();
        var tag = new TagDefinition(
            Id: tagId,
            DevicePairId: PairId,
            TagName: "Write_Target",
            ProtocolAddress: ProtocolAddress.Parse(address),
            DataType: address.StartsWith("COIL", StringComparison.Ordinal) ? TagDataType.Bool : TagDataType.UInt16,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([tag]);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine);

        byte[] reqPayload = BuildMbap(txId: 77, unitId: 1, reqPdu);
        var reqOut = decoder.ProcessFrame(CreateFrame(10, BaseTime, TrafficDirection.ClientToServer, reqPayload), pair, TrafficDirection.ClientToServer);

        var cmd = Assert.Single(reqOut.CommandEvents);
        var reqDp = Assert.Single(reqOut.DataPoints);
        Assert.Empty(reqOut.TraceSpans);
        Assert.NotNull(cmd.TraceId);
        Assert.NotNull(cmd.SpanId);
        Assert.Equal(cmd.TraceId, reqDp.TraceId);
        Assert.Equal(cmd.SpanId, reqDp.SpanId);

        byte[] respPayload = BuildMbap(txId: 77, unitId: 1, respPdu);
        DateTime respTime = BaseTime.AddMilliseconds(22.0);
        var respOut = decoder.ProcessFrame(CreateFrame(11, respTime, TrafficDirection.ServerToClient, respPayload), pair, TrafficDirection.ServerToClient);

        var tx = Assert.Single(respOut.Transactions);
        var span = Assert.Single(respOut.TraceSpans);

        Assert.Equal(cmd.TraceId, tx.TraceId);
        Assert.Equal(cmd.SpanId, tx.SpanId);
        Assert.Equal(cmd.TraceId, span.TraceId);
        Assert.Equal(cmd.SpanId, span.SpanId);
        Assert.Equal(expectedOperation, span.OperationName);
        Assert.Equal(SpanOriginKind.RequestResponse, span.OriginKind);
        Assert.Equal(SpanStatusCode.Ok, span.StatusCode);
        Assert.Equal((short)fc, span.FunctionCode);
        Assert.Equal(1, span.Attributes["tags.matched_count"]);
        Assert.Equal(1, span.Attributes["tags.changed_count"]);

        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.RequestSent);
        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.CommandIssued);
        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.TagValueChanged);
        Assert.Contains(span.Events, e => e.Kind == SpanEventKind.ResponseReceived);
    }

    [Fact]
    public void ProcessFrame_ReadResponseWithTwelveChangedTags_CapsTagValueChangedEventsAtTenAndSetsTruncatedFlag()
    {
        var tags = Enumerable.Range(0, 12)
            .Select(i => new TagDefinition(
                Id: Guid.NewGuid(),
                DevicePairId: PairId,
                TagName: $"Reg_{i:D2}",
                ProtocolAddress: ProtocolAddress.Parse($"HR:{40001 + i}"),
                DataType: TagDataType.UInt16,
                ScaleMultiplier: 1.0,
                ScaleOffset: 0.0,
                EngineeringUnits: null,
                Description: null))
            .ToArray();

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine);

        // Poll 1: all 12 tags change (first appearance)
        byte[] req1 = BuildMbap(1, 1, [0x03, 0x00, 0x00, 0x00, 0x0C]);
        decoder.ProcessFrame(CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, req1), pair, TrafficDirection.ClientToServer);

        byte[] resp1Pdu = new byte[2 + 24];
        resp1Pdu[0] = 0x03;
        resp1Pdu[1] = 24;
        for (int i = 0; i < 12; i++)
        {
            resp1Pdu[2 + (i * 2) + 1] = (byte)(i + 1);
        }

        var out1 = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(15), TrafficDirection.ServerToClient, BuildMbap(1, 1, resp1Pdu)),
            pair,
            TrafficDirection.ServerToClient);

        var span1 = Assert.Single(out1.TraceSpans);
        Assert.Equal(12, span1.Attributes["tags.matched_count"]);
        Assert.Equal(12, span1.Attributes["tags.changed_count"]);
        Assert.Equal(true, span1.Attributes["tags.changes_truncated"]);
        Assert.Equal(10, span1.Events.Count(e => e.Kind == SpanEventKind.TagValueChanged));
        Assert.All(out1.DataPoints, dp =>
        {
            Assert.Equal(span1.TraceId, dp.TraceId);
            Assert.Equal(span1.SpanId, dp.SpanId);
        });

        // Poll 2: only 2 tags change out of 12 matched -> no truncation flag
        byte[] req2 = BuildMbap(2, 1, [0x03, 0x00, 0x00, 0x00, 0x0C]);
        decoder.ProcessFrame(CreateFrame(3, BaseTime.AddMilliseconds(50), TrafficDirection.ClientToServer, req2), pair, TrafficDirection.ClientToServer);

        byte[] resp2Pdu = (byte[])resp1Pdu.Clone();
        resp2Pdu[3] = 99;
        resp2Pdu[5] = 100;

        var out2 = decoder.ProcessFrame(
            CreateFrame(4, BaseTime.AddMilliseconds(65), TrafficDirection.ServerToClient, BuildMbap(2, 1, resp2Pdu)),
            pair,
            TrafficDirection.ServerToClient);

        var span2 = Assert.Single(out2.TraceSpans);
        Assert.Equal(12, span2.Attributes["tags.matched_count"]);
        Assert.Equal(2, span2.Attributes["tags.changed_count"]);
        Assert.False(span2.Attributes.ContainsKey("tags.changes_truncated"));
        Assert.Equal(2, span2.Events.Count(e => e.Kind == SpanEventKind.TagValueChanged));
    }

    [Fact]
    public void ProcessFrame_MatchedExceptionResponse_KeepsBaseOperationNameAndEmitsErrorSpanWithProtocolExceptionEvent()
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var decoder = new ModbusTcpDecoder(redEngine, new TagResolutionEngine([]));

        byte[] reqPayload = BuildMbap(txId: 21, unitId: 1, [0x03, 0x00, 0x00, 0x00, 0x02]);
        decoder.ProcessFrame(CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, reqPayload), pair, TrafficDirection.ClientToServer);

        byte[] exPayload = BuildMbap(txId: 21, unitId: 1, [0x83, 0x02]);
        var respTime = BaseTime.AddMilliseconds(18.0);
        var respOut = decoder.ProcessFrame(CreateFrame(2, respTime, TrafficDirection.ServerToClient, exPayload), pair, TrafficDirection.ServerToClient);

        var tx = Assert.Single(respOut.Transactions);
        var span = Assert.Single(respOut.TraceSpans);

        Assert.Equal(tx.TraceId, span.TraceId);
        Assert.Equal(tx.SpanId, span.SpanId);
        Assert.Equal("Modbus FC03 ReadHoldingRegisters", span.OperationName);
        Assert.Equal(SpanOriginKind.RequestResponse, span.OriginKind);
        Assert.Equal(SpanStatusCode.Error, span.StatusCode);
        Assert.Equal("MODBUS_EX_02", span.StatusMessage);
        Assert.Equal((short)3, span.FunctionCode);
        Assert.Equal(2, span.Attributes["modbus.exception_code"]);
        Assert.Equal(0, span.Attributes["tags.matched_count"]);
        Assert.Equal(0, span.Attributes["tags.changed_count"]);

        var exEvent = Assert.Single(span.Events, e => e.Kind == SpanEventKind.ProtocolException);
        Assert.Equal(respTime, exEvent.TimestampUtc);
        Assert.Equal(2, exEvent.Fields["exception_code"]);
        Assert.Equal(TransactionStatusCode.ModbusEx02, exEvent.Fields["status_code"]);
    }

    [Fact]
    public void FlushExpiredTimeouts_OnWriteRequests_EmitsTimeoutAndTimeoutAtEofSpansSharingPreAllocatedIds()
    {
        var coilTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Trip_Coil",
            ProtocolAddress: ProtocolAddress.Parse("COIL:00001"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var regTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Setpoint_Reg",
            ProtocolAddress: ProtocolAddress.Parse("HR:40001"),
            DataType: TagDataType.UInt16,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 1500);
        var tagEngine = new TagResolutionEngine([coilTag, regTag]);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine);

        byte[] write1Payload = BuildMbap(txId: 30, unitId: 1, [0x06, 0x00, 0x00, 0x01, 0xF4]);
        var out1 = decoder.ProcessFrame(CreateFrame(10, BaseTime, TrafficDirection.ClientToServer, write1Payload), pair, TrafficDirection.ClientToServer);
        var cmd1 = Assert.Single(out1.CommandEvents);
        var dp1 = Assert.Single(out1.DataPoints);

        byte[] write2Payload = BuildMbap(txId: 31, unitId: 1, [0x05, 0x00, 0x01, 0xFF, 0x00]);
        var out2 = decoder.ProcessFrame(CreateFrame(11, BaseTime.AddMilliseconds(1000), TrafficDirection.ClientToServer, write2Payload), pair, TrafficDirection.ClientToServer);
        var cmd2 = Assert.Single(out2.CommandEvents);
        var dp2 = Assert.Single(out2.DataPoints);

        var midFlush = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(1600), isEndOfFile: false);
        var midTx = Assert.Single(midFlush.Transactions);
        var midSpan = Assert.Single(midFlush.TraceSpans);

        Assert.Equal(cmd1.TraceId, midTx.TraceId);
        Assert.Equal(cmd1.SpanId, midTx.SpanId);
        Assert.Equal(cmd1.TraceId, dp1.TraceId);
        Assert.Equal(cmd1.SpanId, dp1.SpanId);
        Assert.Equal(cmd1.TraceId, midSpan.TraceId);
        Assert.Equal(cmd1.SpanId, midSpan.SpanId);
        Assert.Equal(SpanOriginKind.Timeout, midSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Error, midSpan.StatusCode);
        Assert.Equal("TIMEOUT", midSpan.StatusMessage);
        Assert.Equal(1500.0, midSpan.DurationMs, precision: 5);
        Assert.Contains(midSpan.Events, e => e.Kind == SpanEventKind.CommandIssued);
        Assert.Contains(midSpan.Events, e => e.Kind == SpanEventKind.TagValueChanged);
        Assert.Contains(midSpan.Events, e => e.Kind == SpanEventKind.TimeoutExpired);

        var eofFlush = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(2000), isEndOfFile: true);
        var eofTx = Assert.Single(eofFlush.Transactions);
        var eofSpan = Assert.Single(eofFlush.TraceSpans);

        Assert.Equal(cmd2.TraceId, eofTx.TraceId);
        Assert.Equal(cmd2.SpanId, eofTx.SpanId);
        Assert.Equal(cmd2.TraceId, dp2.TraceId);
        Assert.Equal(cmd2.SpanId, dp2.SpanId);
        Assert.Equal(cmd2.TraceId, eofSpan.TraceId);
        Assert.Equal(cmd2.SpanId, eofSpan.SpanId);
        Assert.Equal(SpanOriginKind.TimeoutAtEof, eofSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Error, eofSpan.StatusCode);
        Assert.Equal("TIMEOUT_AT_EOF", eofSpan.StatusMessage);
        Assert.Equal(1000.0, eofSpan.DurationMs, precision: 5);
        Assert.Contains(eofSpan.Events, e => e.Kind == SpanEventKind.TimeoutExpired);
    }

    [Fact]
    public void ProcessFrame_UnpairedServerResponses_EmitZeroDurationOrphanResponseSpansWithoutTransactions()
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var decoder = new ModbusTcpDecoder(redEngine, new TagResolutionEngine([]));

        byte[] orphanRead = BuildMbap(txId: 88, unitId: 1, [0x03, 0x02, 0x12, 0x34]);
        var readOut = decoder.ProcessFrame(CreateFrame(40, BaseTime, TrafficDirection.ServerToClient, orphanRead), pair, TrafficDirection.ServerToClient);

        Assert.Empty(readOut.Transactions);
        var orphanReadSpan = Assert.Single(readOut.TraceSpans);
        Assert.Equal("SEL_RTAC", orphanReadSpan.ServiceName);
        Assert.Equal("Modbus FC03 ReadHoldingRegisters", orphanReadSpan.OperationName);
        Assert.Equal(SpanKind.Consumer, orphanReadSpan.SpanKind);
        Assert.Equal(SpanOriginKind.OrphanResponse, orphanReadSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Unset, orphanReadSpan.StatusCode);
        Assert.Equal("ORPHAN_RESPONSE", orphanReadSpan.StatusMessage);
        Assert.Equal(0.0, orphanReadSpan.DurationMs);
        Assert.Null(orphanReadSpan.RequestFrameNumber);
        Assert.Equal(40L, orphanReadSpan.ResponseFrameNumber);
        Assert.Equal(true, orphanReadSpan.Attributes["protocol.unpaired"]);
        Assert.Single(orphanReadSpan.Events, e => e.Kind == SpanEventKind.ResponseReceived);

        byte[] orphanEx = BuildMbap(txId: 89, unitId: 1, [0x83, 0x02]);
        var exOut = decoder.ProcessFrame(CreateFrame(41, BaseTime.AddMilliseconds(5), TrafficDirection.ServerToClient, orphanEx), pair, TrafficDirection.ServerToClient);

        Assert.Empty(exOut.Transactions);
        var orphanExSpan = Assert.Single(exOut.TraceSpans);
        Assert.Equal("SEL_RTAC", orphanExSpan.ServiceName);
        Assert.Equal("Modbus FC03 ReadHoldingRegisters", orphanExSpan.OperationName);
        Assert.Equal(SpanOriginKind.OrphanResponse, orphanExSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Error, orphanExSpan.StatusCode);
        Assert.Equal("MODBUS_EX_02", orphanExSpan.StatusMessage);
        Assert.Equal(true, orphanExSpan.Attributes["protocol.unpaired"]);
        Assert.Equal(2, orphanExSpan.Attributes["modbus.exception_code"]);
        Assert.Contains(orphanExSpan.Events, e => e.Kind == SpanEventKind.ProtocolException);
    }

    [Theory]
    [InlineData(TrafficDirection.ClientToServer, new byte[] { 0x00, 0x05, 0x00, 0x00, 0x00 }, "Feeder1_Relay", SpanKind.Client)]
    [InlineData(TrafficDirection.ServerToClient, new byte[] { 0x00, 0x0A, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x04, 0x12, 0x34 }, "SEL_RTAC", SpanKind.Consumer)]
    public void ProcessFrame_MalformedMbapOrPdu_EmitsZeroDurationMalformedSpanAndCorrelatesTransaction(
        TrafficDirection direction,
        byte[] payload,
        string expectedServiceName,
        SpanKind expectedSpanKind)
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var decoder = new ModbusTcpDecoder(redEngine, new TagResolutionEngine([]));

        var output = decoder.ProcessFrame(CreateFrame(50, BaseTime, direction, payload), pair, direction);

        var tx = Assert.Single(output.Transactions);
        var span = Assert.Single(output.TraceSpans);

        Assert.NotNull(tx.TraceId);
        Assert.NotNull(tx.SpanId);
        Assert.Equal(tx.TraceId, span.TraceId);
        Assert.Equal(tx.SpanId, span.SpanId);
        Assert.Equal(expectedServiceName, span.ServiceName);
        Assert.Equal("Modbus MalformedFrame", span.OperationName);
        Assert.Equal(expectedSpanKind, span.SpanKind);
        Assert.Equal(SpanOriginKind.Malformed, span.OriginKind);
        Assert.Equal(SpanStatusCode.Error, span.StatusCode);
        Assert.Equal("MALFORMED", span.StatusMessage);
        Assert.Equal(0.0, span.DurationMs);
        Assert.Equal(direction, span.Direction);
    }

    [Fact]
    public void ProcessFrame_AndFlushExpiredTimeouts_WhenStoreTraceSpansDisabled_EmitsZeroSpansAndNullIdsAcrossAllPaths()
    {
        var tag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "OptOut_Tag",
            ProtocolAddress: ProtocolAddress.Parse("HR:40001"),
            DataType: TagDataType.UInt16,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 1000);
        var tagEngine = new TagResolutionEngine([tag]);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine, storeUnmappedRegisters: false, storeTraceSpans: false);

        // 1. Read request + response
        var readReqOut = decoder.ProcessFrame(CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, BuildMbap(1, 1, [0x03, 0x00, 0x00, 0x00, 0x01])), pair, TrafficDirection.ClientToServer);
        var readRespOut = decoder.ProcessFrame(CreateFrame(2, BaseTime.AddMilliseconds(10), TrafficDirection.ServerToClient, BuildMbap(1, 1, [0x03, 0x02, 0x00, 0x64])), pair, TrafficDirection.ServerToClient);

        Assert.Empty(readReqOut.TraceSpans);
        Assert.Empty(readRespOut.TraceSpans);
        var readTx = Assert.Single(readRespOut.Transactions);
        var readDp = Assert.Single(readRespOut.DataPoints);
        Assert.Null(readTx.TraceId);
        Assert.Null(readTx.SpanId);
        Assert.Null(readDp.TraceId);
        Assert.Null(readDp.SpanId);

        // 2. Write request + exception response
        var writeReqOut = decoder.ProcessFrame(CreateFrame(3, BaseTime.AddMilliseconds(20), TrafficDirection.ClientToServer, BuildMbap(2, 1, [0x06, 0x00, 0x00, 0x00, 0x7B])), pair, TrafficDirection.ClientToServer);
        var writeCmd = Assert.Single(writeReqOut.CommandEvents);
        var writeDp = Assert.Single(writeReqOut.DataPoints);
        Assert.Empty(writeReqOut.TraceSpans);
        Assert.Null(writeCmd.TraceId);
        Assert.Null(writeCmd.SpanId);
        Assert.Null(writeDp.TraceId);
        Assert.Null(writeDp.SpanId);

        var writeExOut = decoder.ProcessFrame(CreateFrame(4, BaseTime.AddMilliseconds(30), TrafficDirection.ServerToClient, BuildMbap(2, 1, [0x86, 0x02])), pair, TrafficDirection.ServerToClient);
        Assert.Empty(writeExOut.TraceSpans);
        var exTx = Assert.Single(writeExOut.Transactions);
        Assert.Null(exTx.TraceId);
        Assert.Null(exTx.SpanId);

        // 3. Orphan response + Malformed frame
        var orphanOut = decoder.ProcessFrame(CreateFrame(5, BaseTime.AddMilliseconds(40), TrafficDirection.ServerToClient, BuildMbap(99, 1, [0x03, 0x02, 0x00, 0x01])), pair, TrafficDirection.ServerToClient);
        Assert.Empty(orphanOut.Transactions);
        Assert.Empty(orphanOut.TraceSpans);

        var malformedOut = decoder.ProcessFrame(CreateFrame(6, BaseTime.AddMilliseconds(50), TrafficDirection.ClientToServer, [0x00, 0x01, 0x00]), pair, TrafficDirection.ClientToServer);
        Assert.Empty(malformedOut.TraceSpans);
        var malformedTx = Assert.Single(malformedOut.Transactions);
        Assert.Null(malformedTx.TraceId);
        Assert.Null(malformedTx.SpanId);

        // 4. Timeout + TimeoutAtEof
        decoder.ProcessFrame(CreateFrame(7, BaseTime.AddMilliseconds(100), TrafficDirection.ClientToServer, BuildMbap(3, 1, [0x03, 0x00, 0x00, 0x00, 0x01])), pair, TrafficDirection.ClientToServer);
        var midFlush = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(1200), isEndOfFile: false);
        Assert.Empty(midFlush.TraceSpans);
        var midTx = Assert.Single(midFlush.Transactions);
        Assert.Null(midTx.TraceId);
        Assert.Null(midTx.SpanId);

        decoder.ProcessFrame(CreateFrame(8, BaseTime.AddMilliseconds(1300), TrafficDirection.ClientToServer, BuildMbap(4, 1, [0x03, 0x00, 0x00, 0x00, 0x01])), pair, TrafficDirection.ClientToServer);
        var eofFlush = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(1500), isEndOfFile: true);
        Assert.Empty(eofFlush.TraceSpans);
        var eofTx = Assert.Single(eofFlush.Transactions);
        Assert.Null(eofTx.TraceId);
        Assert.Null(eofTx.SpanId);
    }
}
