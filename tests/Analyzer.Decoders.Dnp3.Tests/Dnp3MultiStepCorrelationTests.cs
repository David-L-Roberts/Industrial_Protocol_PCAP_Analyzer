using System.Net;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;
using Analyzer.Decoders.Dnp3;
using Analyzer.Decoders.Dnp3.Handlers;
using Analyzer.Decoders.Dnp3.Registry;

namespace Analyzer.Decoders.Dnp3.Tests;

public class Dnp3MultiStepCorrelationTests
{
    private static readonly Guid SessionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid PairId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid SecondPairId = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly IPAddress ClientIp = IPAddress.Parse("10.0.1.5");
    private static readonly IPAddress ServerIp = IPAddress.Parse("10.0.1.10");
    private static readonly DateTime BaseTime = new(2026, 11, 22, 12, 0, 0, DateTimeKind.Utc);

    private static DeviceEndpointPair CreateNamedPair(
        Guid? pairId = null,
        int? masterAddr = 1,
        int? outstationAddr = 100) =>
        new(
            Id: pairId ?? PairId,
            SessionId: SessionId,
            Name: "SCADA_to_Feeder1",
            Protocol: ProtocolType.Dnp3,
            ClientIp: ClientIp,
            ServerIp: ServerIp,
            ClientProtocolAddressId: masterAddr,
            ServerProtocolAddressId: outstationAddr,
            ClientName: "SCADA_Master",
            ServerName: "Feeder1_RTU");

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

    private static byte[] BuildCrobFragment(byte appControl, byte functionCode, byte index = 1) =>
        [
            appControl,
            functionCode,
            12, 1, 0x17, 0x01, index,
            0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00
        ];

    private static byte[] BuildCrobResponseFragment(byte appControl, byte iin1 = 0x00, byte iin2 = 0x00, byte index = 1) =>
        [
            appControl,
            0x81,
            iin1,
            iin2,
            12, 1, 0x17, 0x01, index,
            0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00
        ];

    [Fact]
    public void ProcessFrame_SboSelectFollowedByOperateWithinRefreshedWindow_LinksOperateAsChildOfSelectAndStampsAllOutputs()
    {
        var crobTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Breaker_52A_Cmd",
            ProtocolAddress: ProtocolAddress.Parse("G12V01:Idx1"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([crobTag]);
        var decoder = new Dnp3Decoder(
            redEngine,
            CreateFullRegistry(tagEngine),
            tagEngine,
            storeTraceSpans: true,
            sboWindowMs: 5000);

        // 1. Select (FC 0x03, SEQ=1) at T=0
        var selReqOut = decoder.ProcessFrame(
            CreateFrame(10, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC1, 0x03, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var selCmd = Assert.Single(selReqOut.CommandEvents);
        var selDp = Assert.Single(selReqOut.DataPoints);

        // 2. Select Response (FC 0x81, SEQ=1, CON=0) at T=+1000ms -> refreshes SBO AnchorUtc to T=+1000ms
        var selRespTime = BaseTime.AddMilliseconds(1000);
        var selRespOut = decoder.ProcessFrame(
            CreateFrame(11, selRespTime, TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC1, index: 1))),
            pair,
            TrafficDirection.ServerToClient);
        var selSpan = Assert.Single(selRespOut.TraceSpans);
        Assert.Null(selSpan.ParentSpanId);
        Assert.Equal(selCmd.TraceId, selSpan.TraceId);
        Assert.Equal(selCmd.SpanId, selSpan.SpanId);
        Assert.False(selSpan.Attributes.ContainsKey("dnp3.sbo_linked"));

        // 3. Operate (FC 0x04, SEQ=2) at T=+5500ms:
        //    5500ms after Select request (> 5000ms), but 4500ms after refreshed Select response (<= 5000ms)!
        var opReqTime = BaseTime.AddMilliseconds(5500);
        var opReqOut = decoder.ProcessFrame(
            CreateFrame(12, opReqTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC2, 0x04, index: 1))),
            pair,
            TrafficDirection.ClientToServer);

        var opCmd = Assert.Single(opReqOut.CommandEvents);
        var opDp = Assert.Single(opReqOut.DataPoints);
        Assert.Equal(selSpan.TraceId, opCmd.TraceId);
        Assert.Equal(selSpan.TraceId, opDp.TraceId);
        Assert.NotEqual(selSpan.SpanId, opCmd.SpanId);
        Assert.Equal(opCmd.SpanId, opDp.SpanId);
        Assert.Equal(
            DeterministicTraceIdGenerator.CreateSpanId(SessionId, PairId, 12, SpanCorrelationRole.SboOperate),
            opCmd.SpanId);

        // 4. Operate Response (FC 0x81, SEQ=2, CON=0) at T=+5540ms
        var opRespTime = BaseTime.AddMilliseconds(5540);
        var opRespOut = decoder.ProcessFrame(
            CreateFrame(13, opRespTime, TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC2, index: 1))),
            pair,
            TrafficDirection.ServerToClient);

        var opTx = Assert.Single(opRespOut.Transactions);
        var opSpan = Assert.Single(opRespOut.TraceSpans);
        Assert.Equal(selSpan.TraceId, opTx.TraceId);
        Assert.Equal(opCmd.SpanId, opTx.SpanId);
        Assert.Equal(selSpan.TraceId, opSpan.TraceId);
        Assert.Equal(opCmd.SpanId, opSpan.SpanId);
        Assert.Equal(selSpan.SpanId, opSpan.ParentSpanId);
        Assert.Equal("DNP3 FC04 Operate", opSpan.OperationName);
        Assert.Equal(true, opSpan.Attributes["dnp3.sbo_linked"]);
        Assert.Equal(selDp.SpanId, selSpan.SpanId);

        // 5. A second Operate targeting the same point after SBO entry was consumed must NOT re-link
        decoder.ProcessFrame(
            CreateFrame(14, BaseTime.AddMilliseconds(5600), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC3, 0x04, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var secondOpOut = decoder.ProcessFrame(
            CreateFrame(15, BaseTime.AddMilliseconds(5620), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC3, index: 1))),
            pair,
            TrafficDirection.ServerToClient);

        var secondOpSpan = Assert.Single(secondOpOut.TraceSpans);
        Assert.Null(secondOpSpan.ParentSpanId);
        Assert.NotEqual(selSpan.TraceId, secondOpSpan.TraceId);
        Assert.Equal(false, secondOpSpan.Attributes["dnp3.sbo_linked"]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProcessFrame_SboOperatePastSboWindow_StartsIndependentRootTraceWithSboLinkedFalse(bool invokeFlushBeforeOperate)
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new Dnp3Decoder(
            redEngine,
            CreateFullRegistry(tagEngine),
            tagEngine,
            storeTraceSpans: true,
            sboWindowMs: 5000);

        // Select + response at T=0 and T=+50ms
        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC1, 0x03, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var selRespOut = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(50), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC1, index: 1))),
            pair,
            TrafficDirection.ServerToClient);
        var selSpan = Assert.Single(selRespOut.TraceSpans);

        if (invokeFlushBeforeOperate)
        {
            decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(5051), isEndOfFile: false);
        }

        // Operate arrives at T=+5051ms (5001ms after AnchorUtc=50ms > 5000ms)
        var opReqTime = BaseTime.AddMilliseconds(5051);
        var opReqOut = decoder.ProcessFrame(
            CreateFrame(3, opReqTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC2, 0x04, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var opCmd = Assert.Single(opReqOut.CommandEvents);
        Assert.NotEqual(selSpan.TraceId, opCmd.TraceId);

        var opRespOut = decoder.ProcessFrame(
            CreateFrame(4, opReqTime.AddMilliseconds(10), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC2, index: 1))),
            pair,
            TrafficDirection.ServerToClient);

        var opSpan = Assert.Single(opRespOut.TraceSpans);
        Assert.Null(opSpan.ParentSpanId);
        Assert.NotEqual(selSpan.TraceId, opSpan.TraceId);
        Assert.Equal(false, opSpan.Attributes["dnp3.sbo_linked"]);
    }

    [Fact]
    public void ProcessFrame_SboMismatchedTargetAddressOrDevicePair_IsolatesEntriesAndPreservesOriginalSelect()
    {
        var pair1 = CreateNamedPair(PairId);
        var pair2 = CreateNamedPair(SecondPairId);
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new Dnp3Decoder(
            redEngine,
            CreateFullRegistry(tagEngine),
            tagEngine,
            storeTraceSpans: true,
            sboWindowMs: 10000);

        // Select on pair1 targeting G12V01:Idx1
        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC1, 0x03, index: 1))),
            pair1,
            TrafficDirection.ClientToServer);
        var selSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(10), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC1, index: 1))),
            pair1,
            TrafficDirection.ServerToClient).TraceSpans);

        // Operate on pair1 targeting DIFFERENT index G12V01:Idx2 -> unlinked
        decoder.ProcessFrame(
            CreateFrame(3, BaseTime.AddMilliseconds(20), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC2, 0x04, index: 2))),
            pair1,
            TrafficDirection.ClientToServer);
        var wrongTargetSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(4, BaseTime.AddMilliseconds(30), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC2, index: 2))),
            pair1,
            TrafficDirection.ServerToClient).TraceSpans);

        Assert.Null(wrongTargetSpan.ParentSpanId);
        Assert.NotEqual(selSpan.TraceId, wrongTargetSpan.TraceId);
        Assert.Equal(false, wrongTargetSpan.Attributes["dnp3.sbo_linked"]);

        // Operate on pair2 targeting G12V01:Idx1 -> unlinked (device_pair_id isolation)
        decoder.ProcessFrame(
            CreateFrame(5, BaseTime.AddMilliseconds(40), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC1, 0x04, index: 1))),
            pair2,
            TrafficDirection.ClientToServer);
        var wrongPairSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(6, BaseTime.AddMilliseconds(50), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC1, index: 1))),
            pair2,
            TrafficDirection.ServerToClient).TraceSpans);

        Assert.Null(wrongPairSpan.ParentSpanId);
        Assert.NotEqual(selSpan.TraceId, wrongPairSpan.TraceId);
        Assert.Equal(false, wrongPairSpan.Attributes["dnp3.sbo_linked"]);

        // Original pair1 G12V01:Idx1 Operate -> still links cleanly!
        decoder.ProcessFrame(
            CreateFrame(7, BaseTime.AddMilliseconds(60), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC3, 0x04, index: 1))),
            pair1,
            TrafficDirection.ClientToServer);
        var validOpSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(8, BaseTime.AddMilliseconds(70), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC3, index: 1))),
            pair1,
            TrafficDirection.ServerToClient).TraceSpans);

        Assert.Equal(selSpan.TraceId, validOpSpan.TraceId);
        Assert.Equal(selSpan.SpanId, validOpSpan.ParentSpanId);
        Assert.Equal(true, validOpSpan.Attributes["dnp3.sbo_linked"]);
    }

    [Fact]
    public void ProcessFrame_SelectFailedWithIinError_ClearsSboEntrySoOperateStartsIndependentRootTrace()
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new Dnp3Decoder(
            redEngine,
            CreateFullRegistry(tagEngine),
            tagEngine,
            storeTraceSpans: true,
            sboWindowMs: 10000);

        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC1, 0x03, index: 1))),
            pair,
            TrafficDirection.ClientToServer);

        var failedSelSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(20), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC1, iin1: 0x00, iin2: 0x04, index: 1))),
            pair,
            TrafficDirection.ServerToClient).TraceSpans);
        Assert.Equal(SpanStatusCode.Error, failedSelSpan.StatusCode);

        // Operate arrives quickly after failed Select -> must NOT link
        decoder.ProcessFrame(
            CreateFrame(3, BaseTime.AddMilliseconds(40), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC2, 0x04, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var opSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(4, BaseTime.AddMilliseconds(50), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC2, index: 1))),
            pair,
            TrafficDirection.ServerToClient).TraceSpans);

        Assert.Null(opSpan.ParentSpanId);
        Assert.NotEqual(failedSelSpan.TraceId, opSpan.TraceId);
        Assert.Equal(false, opSpan.Attributes["dnp3.sbo_linked"]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProcessFrame_TimedOutSelect_ClearsSboEntryEvenWhenSharedRedEngineDrainedFirst(bool drainRedEngineDirectlyBeforeDnp3Flush)
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 1000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new Dnp3Decoder(
            redEngine,
            CreateFullRegistry(tagEngine),
            tagEngine,
            storeTraceSpans: true,
            sboWindowMs: 10000);

        // Select at T=0 (never receives response -> times out after 1000ms, while sboWindowMs is 10000ms)
        var selOut = decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC1, 0x03, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var selCmd = Assert.Single(selOut.CommandEvents);

        var laterTime = BaseTime.AddMilliseconds(1500);
        if (drainRedEngineDirectlyBeforeDnp3Flush)
        {
            var drained = redEngine.FlushExpiredTimeouts(laterTime, isEndOfFile: false);
            Assert.Single(drained.Transactions);
        }

        decoder.FlushExpiredTimeouts(laterTime, isEndOfFile: false);

        // Operate arrives at T=+1600ms (still < sboWindowMs=10000ms, but Select timed out at > 1000ms)
        decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(1600), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC2, 0x04, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var opSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(3, BaseTime.AddMilliseconds(1620), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xC2, index: 1))),
            pair,
            TrafficDirection.ServerToClient).TraceSpans);

        Assert.Null(opSpan.ParentSpanId);
        Assert.NotEqual(selCmd.TraceId, opSpan.TraceId);
        Assert.Equal(false, opSpan.Attributes["dnp3.sbo_linked"]);
    }

    [Fact]
    public void ProcessFrame_SolicitedAndOrphanResponseWithCon1_AttachConfirmChildSpanWithoutTransaction()
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        // 1. Solicited Read (SEQ=4) + Response (AC=0xE4: FIR=1, FIN=1, CON=1, UNS=0, SEQ=4)
        decoder.ProcessFrame(
            CreateFrame(10, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC4, 0x01, 60, 1, 0x06])),
            pair,
            TrafficDirection.ClientToServer);

        var respTime = BaseTime.AddMilliseconds(30);
        var respOut = decoder.ProcessFrame(
            CreateFrame(11, respTime, TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xE4, 0x81, 0x00, 0x00])),
            pair,
            TrafficDirection.ServerToClient);
        var respSpan = Assert.Single(respOut.TraceSpans);

        // Master Application Confirm (FC 0x00, AC=0xC4: SEQ=4, UNS=0) at T=+45.5ms
        var confirmTime = BaseTime.AddMilliseconds(45.5);
        var confirmOut = decoder.ProcessFrame(
            CreateFrame(12, confirmTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC4, 0x00])),
            pair,
            TrafficDirection.ClientToServer);

        Assert.Empty(confirmOut.Transactions);
        var confirmSpan = Assert.Single(confirmOut.TraceSpans);
        Assert.Equal(respSpan.TraceId, confirmSpan.TraceId);
        Assert.Equal(respSpan.SpanId, confirmSpan.ParentSpanId);
        Assert.Equal(
            DeterministicTraceIdGenerator.CreateSpanId(SessionId, PairId, 12, SpanCorrelationRole.Confirm),
            confirmSpan.SpanId);
        Assert.Equal("Feeder1_RTU", confirmSpan.ServiceName);
        Assert.Equal("DNP3 FC00 Confirm", confirmSpan.OperationName);
        Assert.Equal(SpanKind.Client, confirmSpan.SpanKind);
        Assert.Equal(SpanOriginKind.Confirm, confirmSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Ok, confirmSpan.StatusCode);
        Assert.Null(confirmSpan.StatusMessage);
        Assert.Equal(respTime, confirmSpan.StartTimeUtc);
        Assert.Equal(confirmTime, confirmSpan.EndTimeUtc);
        Assert.Equal(15.5, confirmSpan.DurationMs, precision: 5);
        Assert.Equal(12L, confirmSpan.RequestFrameNumber);
        Assert.Equal(11L, confirmSpan.ResponseFrameNumber);
        Assert.Equal((short)0, confirmSpan.FunctionCode);
        Assert.Equal("4", confirmSpan.TransactionId);
        var confirmEvent = Assert.Single(confirmSpan.Events, e => e.Kind == SpanEventKind.ConfirmSent);
        Assert.Equal(11L, confirmEvent.Fields["confirmed_frame"]);

        // 2. Orphan FC 0x81 (AC=0xE7: CON=1, SEQ=7) + Master FC 0x00 Confirm (SEQ=7)
        var orphanTime = BaseTime.AddMilliseconds(100);
        var orphanOut = decoder.ProcessFrame(
            CreateFrame(20, orphanTime, TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xE7, 0x81, 0x00, 0x00])),
            pair,
            TrafficDirection.ServerToClient);
        var orphanSpan = Assert.Single(orphanOut.TraceSpans);
        Assert.Equal(SpanOriginKind.OrphanResponse, orphanSpan.OriginKind);

        var orphanConfirmOut = decoder.ProcessFrame(
            CreateFrame(21, orphanTime.AddMilliseconds(8), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC7, 0x00])),
            pair,
            TrafficDirection.ClientToServer);
        Assert.Empty(orphanConfirmOut.Transactions);
        var orphanConfirmSpan = Assert.Single(orphanConfirmOut.TraceSpans);
        Assert.Equal(orphanSpan.TraceId, orphanConfirmSpan.TraceId);
        Assert.Equal(orphanSpan.SpanId, orphanConfirmSpan.ParentSpanId);
        Assert.Equal(8.0, orphanConfirmSpan.DurationMs, precision: 5);

        var eofFlush = decoder.FlushExpiredTimeouts(BaseTime.AddSeconds(5), isEndOfFile: true);
        Assert.Empty(eofFlush.Transactions);
        Assert.Empty(eofFlush.TraceSpans);
    }

    [Fact]
    public void ProcessFrame_UnsolicitedResponseWithCon1_MatchesUnsAndFallbackAndDisambiguatesConcurrentSolicited()
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new Dnp3Decoder(redEngine, CreateFullRegistry(tagEngine), tagEngine);

        // Concurrent Solicited (SEQ=3, UNS=0) and Unsolicited (SEQ=3, UNS=1) with CON=1
        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC3, 0x01, 60, 1, 0x06])),
            pair,
            TrafficDirection.ClientToServer);
        var solRespSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(10), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xE3, 0x81, 0x00, 0x00])),
            pair,
            TrafficDirection.ServerToClient).TraceSpans);

        var unsRespSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(3, BaseTime.AddMilliseconds(20), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xF3, 0x82, 0x00, 0x00])),
            pair,
            TrafficDirection.ServerToClient).TraceSpans);

        // Master Confirm with UNS=1 (AC=0xD3) matches Unsolicited (frame 3)
        var unsConfirmSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(4, BaseTime.AddMilliseconds(32), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xD3, 0x00])),
            pair,
            TrafficDirection.ClientToServer).TraceSpans);
        Assert.Equal(unsRespSpan.TraceId, unsConfirmSpan.TraceId);
        Assert.Equal(unsRespSpan.SpanId, unsConfirmSpan.ParentSpanId);
        Assert.Equal(12.0, unsConfirmSpan.DurationMs, precision: 5);

        // Master Confirm with UNS=0 (AC=0xC3) matches Solicited (frame 2)
        var solConfirmSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(5, BaseTime.AddMilliseconds(40), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC3, 0x00])),
            pair,
            TrafficDirection.ClientToServer).TraceSpans);
        Assert.Equal(solRespSpan.TraceId, solConfirmSpan.TraceId);
        Assert.Equal(solRespSpan.SpanId, solConfirmSpan.ParentSpanId);
        Assert.Equal(30.0, solConfirmSpan.DurationMs, precision: 5);

        // Fallback: Unsolicited FC 0x82 (SEQ=5, CON=1, UNS=1) confirmed by FC 0x00 with UNS=0 (AC=0xC5)
        var unsFallbackSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(6, BaseTime.AddMilliseconds(60), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xF5, 0x82, 0x00, 0x00])),
            pair,
            TrafficDirection.ServerToClient).TraceSpans);
        var fallbackConfirmSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(7, BaseTime.AddMilliseconds(75), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC5, 0x00])),
            pair,
            TrafficDirection.ClientToServer).TraceSpans);
        Assert.Equal(unsFallbackSpan.TraceId, fallbackConfirmSpan.TraceId);
        Assert.Equal(unsFallbackSpan.SpanId, fallbackConfirmSpan.ParentSpanId);
        Assert.Equal(15.0, fallbackConfirmSpan.DurationMs, precision: 5);
    }

    [Fact]
    public void ProcessFrame_FullSboWithCon1ConfirmSequence_ProducesFourSpanHierarchyInSingleTrace()
    {
        var crobTag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: PairId,
            TagName: "Feeder_Breaker_52",
            ProtocolAddress: ProtocolAddress.Parse("G12V01:Idx1"),
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([crobTag]);
        var decoder = new Dnp3Decoder(
            redEngine,
            CreateFullRegistry(tagEngine),
            tagEngine,
            storeTraceSpans: true,
            sboWindowMs: 10000);

        // 1. Select (FC 0x03, SEQ=1) -> Select Response (FC 0x81, CON=1, SEQ=1)
        decoder.ProcessFrame(
            CreateFrame(100, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC1, 0x03, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var selectSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(101, BaseTime.AddMilliseconds(15), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xE1, index: 1))),
            pair,
            TrafficDirection.ServerToClient).TraceSpans);

        // 2. Confirm for Select Response (FC 0x00, SEQ=1)
        var selectConfirmSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(102, BaseTime.AddMilliseconds(22), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC1, 0x00])),
            pair,
            TrafficDirection.ClientToServer).TraceSpans);

        // 3. Operate (FC 0x04, SEQ=2) -> Operate Response (FC 0x81, CON=1, SEQ=2)
        decoder.ProcessFrame(
            CreateFrame(103, BaseTime.AddMilliseconds(50), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC2, 0x04, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var operateSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(104, BaseTime.AddMilliseconds(70), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xE2, index: 1))),
            pair,
            TrafficDirection.ServerToClient).TraceSpans);

        // 4. Confirm for Operate Response (FC 0x00, SEQ=2)
        var operateConfirmSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(105, BaseTime.AddMilliseconds(80), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC2, 0x00])),
            pair,
            TrafficDirection.ClientToServer).TraceSpans);

        // All 4 spans share the exact same TraceId and form the expected tree
        Assert.Null(selectSpan.ParentSpanId);
        Assert.Equal("DNP3 FC03 Select", selectSpan.OperationName);

        Assert.Equal(selectSpan.TraceId, selectConfirmSpan.TraceId);
        Assert.Equal(selectSpan.SpanId, selectConfirmSpan.ParentSpanId);
        Assert.Equal("DNP3 FC00 Confirm", selectConfirmSpan.OperationName);

        Assert.Equal(selectSpan.TraceId, operateSpan.TraceId);
        Assert.Equal(selectSpan.SpanId, operateSpan.ParentSpanId);
        Assert.Equal("DNP3 FC04 Operate", operateSpan.OperationName);
        Assert.Equal(true, operateSpan.Attributes["dnp3.sbo_linked"]);

        Assert.Equal(selectSpan.TraceId, operateConfirmSpan.TraceId);
        Assert.Equal(operateSpan.SpanId, operateConfirmSpan.ParentSpanId);
        Assert.Equal("DNP3 FC00 Confirm", operateConfirmSpan.OperationName);

        var eofFlush = decoder.FlushExpiredTimeouts(BaseTime.AddSeconds(10), isEndOfFile: true);
        Assert.Empty(eofFlush.Transactions);
        Assert.Empty(eofFlush.TraceSpans);
    }

    [Fact]
    public void ProcessFrame_UnmatchedConfirmFc00_EmitsZeroDurationUnpairedSpanWithoutTransaction()
    {
        var pair = CreateNamedPair();
        var decoder = new Dnp3Decoder(new VirtualClockRedEngine(2000), new Dnp3HandlerRegistry([]));

        var output = decoder.ProcessFrame(
            CreateFrame(90, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC9, 0x00])),
            pair,
            TrafficDirection.ClientToServer);

        Assert.Empty(output.Transactions);
        var span = Assert.Single(output.TraceSpans);
        Assert.Null(span.ParentSpanId);
        Assert.Equal("Feeder1_RTU", span.ServiceName);
        Assert.Equal("DNP3 FC00 Confirm", span.OperationName);
        Assert.Equal(SpanKind.Client, span.SpanKind);
        Assert.Equal(SpanOriginKind.Confirm, span.OriginKind);
        Assert.Equal(SpanStatusCode.Unset, span.StatusCode);
        Assert.Null(span.StatusMessage);
        Assert.Equal(0.0, span.DurationMs);
        Assert.Equal(90L, span.RequestFrameNumber);
        Assert.Null(span.ResponseFrameNumber);
        Assert.Equal(true, span.Attributes["protocol.unpaired"]);
        Assert.Single(span.Events, e => e.Kind == SpanEventKind.ConfirmSent);
    }

    [Fact]
    public void FlushExpiredTimeouts_UnconfirmedSolicitedAndUnsolicitedCon1_EmitsMidStreamAndEofConfirmTimeoutChildSpansWithoutTransactions()
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 1500);
        var decoder = new Dnp3Decoder(redEngine, new Dnp3HandlerRegistry([]));

        // 1. Solicited response (CON=1, SEQ=1) at T=0 -> expires mid-stream (> 1500ms)
        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC1, 0x01, 60, 1, 0x06])),
            pair,
            TrafficDirection.ClientToServer);
        var solRespTime = BaseTime.AddMilliseconds(20);
        var solSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(2, solRespTime, TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xE1, 0x81, 0x00, 0x00])),
            pair,
            TrafficDirection.ServerToClient).TraceSpans);

        // 2. Unsolicited response (CON=1, SEQ=2) at T=+1000ms -> remains unconfirmed at EOF (+2000ms)
        var unsRespTime = BaseTime.AddMilliseconds(1000);
        var unsSpan = Assert.Single(decoder.ProcessFrame(
            CreateFrame(3, unsRespTime, TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xF2, 0x82, 0x00, 0x00])),
            pair,
            TrafficDirection.ServerToClient).TraceSpans);

        // Mid-stream sweep at T=+1600ms -> solSpan expired (1580ms > 1500ms); unsSpan (600ms <= 1500ms) still pending
        var midFlush = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(1600), isEndOfFile: false);
        Assert.Empty(midFlush.Transactions);
        var midTimeout = Assert.Single(midFlush.TraceSpans);
        Assert.Equal(solSpan.TraceId, midTimeout.TraceId);
        Assert.Equal(solSpan.SpanId, midTimeout.ParentSpanId);
        Assert.Equal(
            DeterministicTraceIdGenerator.CreateSpanId(SessionId, PairId, 2, SpanCorrelationRole.ConfirmTimeout),
            midTimeout.SpanId);
        Assert.Equal("DNP3 FC00 Confirm", midTimeout.OperationName);
        Assert.Equal("Feeder1_RTU", midTimeout.ServiceName);
        Assert.Equal(SpanKind.Client, midTimeout.SpanKind);
        Assert.Equal(SpanOriginKind.ConfirmTimeout, midTimeout.OriginKind);
        Assert.Equal(SpanStatusCode.Error, midTimeout.StatusCode);
        Assert.Equal("CONFIRM_TIMEOUT", midTimeout.StatusMessage);
        Assert.Equal(solRespTime, midTimeout.StartTimeUtc);
        Assert.Equal(solRespTime.AddMilliseconds(1500), midTimeout.EndTimeUtc);
        Assert.Equal(1500.0, midTimeout.DurationMs, precision: 5);
        Assert.Null(midTimeout.RequestFrameNumber);
        Assert.Equal(2L, midTimeout.ResponseFrameNumber);
        Assert.Equal(1, midTimeout.Attributes["dnp3.src"]);
        Assert.Equal(100, midTimeout.Attributes["dnp3.dst"]);
        Assert.Equal(1, midTimeout.Attributes["dnp3.app_seq"]);
        Assert.Equal(false, midTimeout.Attributes["dnp3.uns"]);
        Assert.Equal(2L, midTimeout.Attributes["pcap.response_frame"]);
        Assert.Single(midTimeout.Events, e => e.Kind == SpanEventKind.ConfirmTimeoutExpired);

        // EOF sweep at T=+2000ms -> unsSpan expires with CONFIRM_TIMEOUT_AT_EOF (elapsed = 1000ms)
        var eofFlush = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(2000), isEndOfFile: true);
        Assert.Empty(eofFlush.Transactions);
        var eofTimeout = Assert.Single(eofFlush.TraceSpans);
        Assert.Equal(unsSpan.TraceId, eofTimeout.TraceId);
        Assert.Equal(unsSpan.SpanId, eofTimeout.ParentSpanId);
        Assert.Equal(
            DeterministicTraceIdGenerator.CreateSpanId(SessionId, PairId, 3, SpanCorrelationRole.ConfirmTimeout),
            eofTimeout.SpanId);
        Assert.Equal(SpanOriginKind.ConfirmTimeout, eofTimeout.OriginKind);
        Assert.Equal(SpanStatusCode.Error, eofTimeout.StatusCode);
        Assert.Equal("CONFIRM_TIMEOUT_AT_EOF", eofTimeout.StatusMessage);
        Assert.Equal(unsRespTime, eofTimeout.StartTimeUtc);
        Assert.Equal(BaseTime.AddMilliseconds(2000), eofTimeout.EndTimeUtc);
        Assert.Equal(1000.0, eofTimeout.DurationMs, precision: 5);
        Assert.Equal(3L, eofTimeout.ResponseFrameNumber);
        Assert.Equal(1, eofTimeout.Attributes["dnp3.src"]);
        Assert.Equal(100, eofTimeout.Attributes["dnp3.dst"]);
        Assert.Equal(2, eofTimeout.Attributes["dnp3.app_seq"]);
        Assert.Equal(true, eofTimeout.Attributes["dnp3.uns"]);
        Assert.Equal(3L, eofTimeout.Attributes["pcap.response_frame"]);
        Assert.Single(eofTimeout.Events, e => e.Kind == SpanEventKind.ConfirmTimeoutExpired);
    }

    [Fact]
    public void ProcessFrame_WhenStoreTraceSpansDisabled_SboAndConfirmTrackersRemainInactiveAndEmitZeroSpans()
    {
        var pair = CreateNamedPair();
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 1000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new Dnp3Decoder(
            redEngine,
            CreateFullRegistry(tagEngine),
            tagEngine,
            storeTraceSpans: false,
            sboWindowMs: 10000);

        // Select + Response(CON=1) + Confirm
        var selReq = decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC1, 0x03, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var selResp = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(10), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xE1, index: 1))),
            pair,
            TrafficDirection.ServerToClient);
        var selConfirm = decoder.ProcessFrame(
            CreateFrame(3, BaseTime.AddMilliseconds(15), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC1, 0x00])),
            pair,
            TrafficDirection.ClientToServer);

        // Operate + Response(CON=1) (left unconfirmed)
        var opReq = decoder.ProcessFrame(
            CreateFrame(4, BaseTime.AddMilliseconds(20), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, BuildCrobFragment(0xC2, 0x04, index: 1))),
            pair,
            TrafficDirection.ClientToServer);
        var opResp = decoder.ProcessFrame(
            CreateFrame(5, BaseTime.AddMilliseconds(30), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, BuildCrobResponseFragment(0xE2, index: 1))),
            pair,
            TrafficDirection.ServerToClient);

        // Unsolicited(CON=1) (left unconfirmed) + Orphan Confirm
        var unsResp = decoder.ProcessFrame(
            CreateFrame(6, BaseTime.AddMilliseconds(40), TrafficDirection.ServerToClient, Dnp3DecoderTests.BuildDnp3LinkFrame(1, 100, 0xC0, [0xF5, 0x82, 0x00, 0x00])),
            pair,
            TrafficDirection.ServerToClient);
        var orphanConfirm = decoder.ProcessFrame(
            CreateFrame(7, BaseTime.AddMilliseconds(45), TrafficDirection.ClientToServer, Dnp3DecoderTests.BuildDnp3LinkFrame(100, 1, 0xC0, [0xC9, 0x00])),
            pair,
            TrafficDirection.ClientToServer);

        var eofFlush = decoder.FlushExpiredTimeouts(BaseTime.AddSeconds(5), isEndOfFile: true);

        Assert.Empty(selReq.TraceSpans);
        Assert.Empty(selResp.TraceSpans);
        Assert.Empty(selConfirm.TraceSpans);
        Assert.Empty(selConfirm.Transactions);
        Assert.Empty(opReq.TraceSpans);
        Assert.Empty(opResp.TraceSpans);
        Assert.Empty(unsResp.TraceSpans);
        Assert.Empty(orphanConfirm.TraceSpans);
        Assert.Empty(orphanConfirm.Transactions);
        Assert.Empty(eofFlush.TraceSpans);
        Assert.Empty(eofFlush.Transactions);

        Assert.All(selReq.CommandEvents, c => { Assert.Null(c.TraceId); Assert.Null(c.SpanId); });
        Assert.All(opReq.CommandEvents, c => { Assert.Null(c.TraceId); Assert.Null(c.SpanId); });
        Assert.All(selResp.Transactions, t => { Assert.Null(t.TraceId); Assert.Null(t.SpanId); });
        Assert.All(opResp.Transactions, t => { Assert.Null(t.TraceId); Assert.Null(t.SpanId); });
    }
}
