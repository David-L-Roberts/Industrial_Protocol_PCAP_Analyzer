using System.Buffers.Binary;
using System.Net;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;
using Analyzer.Decoders.Dnp3;
using Analyzer.Decoders.Dnp3.Handlers;
using Analyzer.Decoders.Dnp3.Registry;

namespace Analyzer.Decoders.Dnp3.Tests;

public class Dnp3DecoderTests
{
    private static readonly Guid SessionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid PairId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly IPAddress ClientIp = IPAddress.Parse("10.0.1.5");
    private static readonly IPAddress ServerIp = IPAddress.Parse("10.0.1.10");
    private static readonly DateTime BaseTime = new(2026, 10, 29, 12, 0, 0, DateTimeKind.Utc);

    private static DeviceEndpointPair CreatePair(int? masterAddr = 1, int? outstationAddr = 100) =>
        new(
            Id: PairId,
            SessionId: SessionId,
            Name: "SCADA_to_RTAC",
            Protocol: ProtocolType.Dnp3,
            ClientIp: ClientIp,
            ServerIp: ServerIp,
            ClientProtocolAddressId: masterAddr,
            ServerProtocolAddressId: outstationAddr);

    private static DissectedFrame CreateFrame(
        long frameNumber,
        DateTime timestampUtc,
        TrafficDirection direction,
        byte[] payload) =>
        new(
            FrameNumber: frameNumber,
            TimestampUtc: timestampUtc,
            SourceIp: direction == TrafficDirection.ClientToServer ? ClientIp : ServerIp,
            SourcePort: direction == TrafficDirection.ClientToServer ? 50000 : 20000,
            DestIp: direction == TrafficDirection.ClientToServer ? ServerIp : ClientIp,
            DestPort: direction == TrafficDirection.ClientToServer ? 20000 : 50000,
            ProtocolName: ProtocolType.Dnp3,
            RawApplicationPayload: payload);

    /// <summary>
    /// Builds a valid DNP3 Data Link frame with 10-byte link header (including 2-byte CRC)
    /// and 16-byte user data blocks (each followed by a 2-byte CRC).
    /// </summary>
    internal static byte[] BuildDnp3LinkFrame(
        ushort destination,
        ushort source,
        byte transportHeader,
        ReadOnlySpan<byte> applicationFragment,
        byte linkControl = 0xC4)
    {
        int userDataLen = 1 + applicationFragment.Length;
        byte linkLen = (byte)(5 + userDataLen);

        byte[] userBytes = new byte[userDataLen];
        userBytes[0] = transportHeader;
        applicationFragment.CopyTo(userBytes.AsSpan(1));

        int numBlocks = (userDataLen + 15) / 16;
        int totalLen = 10 + userDataLen + (numBlocks * 2);
        byte[] frame = new byte[totalLen];

        frame[0] = 0x05;
        frame[1] = 0x64;
        frame[2] = linkLen;
        frame[3] = linkControl;
        BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(4, 2), destination);
        BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(6, 2), source);
        // Header CRC placeholder (bytes 8..9)
        frame[8] = 0xAA;
        frame[9] = 0xBB;

        int srcOffset = 0;
        int dstOffset = 10;
        while (srcOffset < userDataLen)
        {
            int chunkLen = Math.Min(16, userDataLen - srcOffset);
            userBytes.AsSpan(srcOffset, chunkLen).CopyTo(frame.AsSpan(dstOffset, chunkLen));
            dstOffset += chunkLen;
            // Block CRC placeholder
            frame[dstOffset++] = 0xCC;
            frame[dstOffset++] = 0xDD;
            srcOffset += chunkLen;
        }

        return frame;
    }

    [Theory]
    // 1. Shorter than 10-byte Data Link header
    [InlineData(new byte[] { 0x05, 0x64, 0x05, 0xC0, 0x01, 0x00 }, TrafficDirection.ClientToServer)]
    // 2. Wrong start bytes (not 0x0564)
    [InlineData(new byte[] { 0x05, 0x65, 0x08, 0xC4, 0x64, 0x00, 0x01, 0x00, 0xAA, 0xBB, 0xC0, 0xC1, 0x01, 0xCC, 0xDD }, TrafficDirection.ClientToServer)]
    // 3. Link length < 5 (invalid DNP3 link length)
    [InlineData(new byte[] { 0x05, 0x64, 0x04, 0xC4, 0x64, 0x00, 0x01, 0x00, 0xAA, 0xBB }, TrafficDirection.ClientToServer)]
    // 4. Declared link length (8 -> 3 user bytes + 2 CRC bytes = 15 total bytes) exceeds actual buffer length
    [InlineData(new byte[] { 0x05, 0x64, 0x08, 0xC4, 0x64, 0x00, 0x01, 0x00, 0xAA, 0xBB, 0xC0, 0xC1 }, TrafficDirection.ClientToServer)]
    // 5. Response frame missing 2-byte IIN (only 2 application bytes AC + FC instead of 4 bytes AC + FC + IIN1 + IIN2)
    [InlineData(new byte[] { 0x05, 0x64, 0x08, 0x44, 0x01, 0x00, 0x64, 0x00, 0xAA, 0xBB, 0xC0, 0xC1, 0x81, 0xCC, 0xDD }, TrafficDirection.ServerToClient)]
    public void ProcessFrame_MalformedDataLinkOrApplicationHeader_EmitsMalformedTransactionRecord(
        byte[] malformedPayload,
        TrafficDirection direction)
    {
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var registry = new Dnp3HandlerRegistry([]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair();
        var frame = CreateFrame(frameNumber: 99, timestampUtc: BaseTime, direction: direction, payload: malformedPayload);

        var output = decoder.ProcessFrame(frame, pair, direction);

        var tx = Assert.Single(output.Transactions);
        Assert.Equal(BaseTime, tx.Timestamp);
        Assert.Equal(SessionId, tx.SessionId);
        Assert.Equal(PairId, tx.DevicePairId);
        Assert.Equal(99, tx.FrameNumber);
        Assert.Equal(direction, tx.Direction);
        Assert.Null(tx.DurationMs);
        Assert.True(tx.IsError);
        Assert.Equal(TransactionErrorType.Malformed, tx.ErrorType);
        Assert.Equal(TransactionStatusCode.Malformed, tx.StatusCode);
        Assert.Empty(output.DataPoints);
        Assert.Empty(output.CommandEvents);
        Assert.Empty(output.UnmappedRegisters);
    }

    [Fact]
    public void ProcessFrame_RequestAndResponseCorrelationByAppSequenceAndAddressVerification_CalculatesVirtualClockDuration()
    {
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var registry = new Dnp3HandlerRegistry([]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair(masterAddr: 1, outstationAddr: 100);

        // Request: Master (1) -> Outstation (100), Transport = 0xC0 (FIN=1, FIR=1), AppControl = 0xC5 (FIR=1, FIN=1, SEQ=5), FC = 0x01 (Read)
        byte[] reqPayload = BuildDnp3LinkFrame(
            destination: 100,
            source: 1,
            transportHeader: 0xC0,
            applicationFragment: [0xC5, 0x01, 0x3C, 0x01, 0x06]); // Read Class 0 (G60V1, Qualifier 0x06 no range)

        var reqOutput = decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, reqPayload),
            pair,
            TrafficDirection.ClientToServer);

        Assert.Empty(reqOutput.Transactions);

        // Frame from wrong Outstation address (Outstation 200 instead of 100) with same SEQ=5 -> ignored by address verification
        byte[] wrongAddrResp = BuildDnp3LinkFrame(
            destination: 1,
            source: 200,
            transportHeader: 0xC0,
            applicationFragment: [0xC5, 0x81, 0x00, 0x00]);

        var wrongAddrOutput = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(15), TrafficDirection.ServerToClient, wrongAddrResp),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Empty(wrongAddrOutput.Transactions);

        // Matching Response: Outstation (100) -> Master (1) at T + 42.5ms, AppControl = 0xC5 (SEQ=5), FC = 0x81 (Response), IIN = 0x0000
        byte[] respPayload = BuildDnp3LinkFrame(
            destination: 1,
            source: 100,
            transportHeader: 0xC0,
            applicationFragment: [0xC5, 0x81, 0x00, 0x00]);

        var respOutput = decoder.ProcessFrame(
            CreateFrame(3, BaseTime.AddMilliseconds(42.5), TrafficDirection.ServerToClient, respPayload),
            pair,
            TrafficDirection.ServerToClient);

        var tx = Assert.Single(respOutput.Transactions);
        Assert.Equal(BaseTime.AddMilliseconds(42.5), tx.Timestamp);
        Assert.Equal(SessionId, tx.SessionId);
        Assert.Equal(PairId, tx.DevicePairId);
        Assert.Equal(3, tx.FrameNumber);
        Assert.Equal(TrafficDirection.ServerToClient, tx.Direction);
        Assert.Equal("5", tx.TransactionId);
        Assert.Equal(0x81, tx.FunctionCode);
        Assert.Equal(42.5, tx.DurationMs!.Value, precision: 5);
        Assert.False(tx.IsError);
        Assert.Equal(TransactionErrorType.None, tx.ErrorType);
        Assert.Equal(TransactionStatusCode.Success, tx.StatusCode);
    }

    [Theory]
    [InlineData(0x00, 0x01, TransactionStatusCode.Dnp3IinFuncNotSupported)]
    [InlineData(0x00, 0x02, TransactionStatusCode.Dnp3IinObjectUnknown)]
    [InlineData(0x00, 0x04, TransactionStatusCode.Dnp3IinParamErr)]
    [InlineData(0x00, 0x08, TransactionStatusCode.Dnp3IinEventBufferOverflow)]
    [InlineData(0x00, 0x10, TransactionStatusCode.Dnp3IinAlreadyExecuting)]
    [InlineData(0x00, 0x20, TransactionStatusCode.Dnp3IinConfigCorrupt)]
    public void ProcessFrame_ResponseWithIinErrorBits_EmitsExceptionTransactionRecord(
        byte iin1,
        byte iin2,
        TransactionStatusCode expectedStatus)
    {
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var registry = new Dnp3HandlerRegistry([]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair(masterAddr: 1, outstationAddr: 100);

        byte[] reqPayload = BuildDnp3LinkFrame(
            destination: 100,
            source: 1,
            transportHeader: 0xC0,
            applicationFragment: [0xC9, 0x01, 0x1E, 0x02, 0x06]); // SEQ = 9, FC = 1 (Read)

        decoder.ProcessFrame(
            CreateFrame(10, BaseTime, TrafficDirection.ClientToServer, reqPayload),
            pair,
            TrafficDirection.ClientToServer);

        byte[] respPayload = BuildDnp3LinkFrame(
            destination: 1,
            source: 100,
            transportHeader: 0xC0,
            applicationFragment: [0xC9, 0x81, iin1, iin2]); // SEQ = 9, FC = 0x81 (Response)

        var output = decoder.ProcessFrame(
            CreateFrame(11, BaseTime.AddMilliseconds(18.75), TrafficDirection.ServerToClient, respPayload),
            pair,
            TrafficDirection.ServerToClient);

        var tx = Assert.Single(output.Transactions);
        Assert.Equal("9", tx.TransactionId);
        Assert.Equal(0x81, tx.FunctionCode);
        Assert.Equal(18.75, tx.DurationMs!.Value, precision: 5);
        Assert.True(tx.IsError);
        Assert.Equal(TransactionErrorType.Exception, tx.ErrorType);
        Assert.Equal(expectedStatus, tx.StatusCode);
    }

    [Fact]
    public void ProcessFrame_MultiBlockDataLinkPayload_StripsIntermediateBlockCrcsAndDispatchesMultipleObjectHeaders()
    {
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var recordingHandler1 = new RecordingObjectGroupHandler(1);
        var recordingHandler30 = new RecordingObjectGroupHandler(30);
        var registry = new Dnp3HandlerRegistry([recordingHandler1, recordingHandler30]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair(masterAddr: 1, outstationAddr: 100);

        // Request SEQ = 2
        byte[] reqPayload = BuildDnp3LinkFrame(100, 1, 0xC0, [0xC2, 0x01, 0x3C, 0x01, 0x06]);
        decoder.ProcessFrame(CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, reqPayload), pair, TrafficDirection.ClientToServer);

        // Response SEQ = 2 with two objects exceeding 16 bytes so it spans 2 Data Link user-data blocks:
        // App header (4 bytes): C2 81 00 00
        // Object 1: Group 30, Var 1, Qualifier 0x00 (8-bit start/stop), Start=0, Stop=2 (3 items * 5 bytes = 15 bytes) -> 3 + 2 + 15 = 20 bytes
        // Object 2: Group 1, Var 2, Qualifier 0x00 (8-bit start/stop), Start=4, Stop=5 (2 items * 1 byte = 2 bytes) -> 3 + 2 + 2 = 7 bytes
        // Total Application Fragment = 4 + 20 + 7 = 31 bytes (+ 1 transport byte = 32 user bytes across two 16-byte CRC blocks!)
        byte[] appFragment =
        [
            0xC2, 0x81, 0x00, 0x00,
            // Object 1: G30V1, Qualifier 0x00, Start=0, Stop=2, 15 bytes of payload
            30, 1, 0x00, 0x00, 0x02,
            0x01, 0x10, 0x00, 0x00, 0x00,
            0x01, 0x20, 0x00, 0x00, 0x00,
            0x01, 0x30, 0x00, 0x00, 0x00,
            // Object 2: G1V2, Qualifier 0x00, Start=4, Stop=5, 2 bytes of payload
            1, 2, 0x00, 0x04, 0x05,
            0x81, 0x01
        ];

        byte[] respPayload = BuildDnp3LinkFrame(1, 100, 0xC0, appFragment);
        var output = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(25), TrafficDirection.ServerToClient, respPayload),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Single(output.Transactions);
        var g30Call = Assert.Single(recordingHandler30.Invocations);
        Assert.Equal((ushort)1, g30Call.Variation);
        // ObjectData passed to handler starts at Qualifier (0x00, 0x00, 0x02, plus 15 item bytes = 18 bytes)
        Assert.Equal(18, g30Call.ObjectData.Length);
        Assert.Equal(0x00, g30Call.ObjectData[0]);
        Assert.Equal(0x00, g30Call.ObjectData[1]);
        Assert.Equal(0x02, g30Call.ObjectData[2]);

        var g1Call = Assert.Single(recordingHandler1.Invocations);
        Assert.Equal((ushort)2, g1Call.Variation);
        // ObjectData passed to handler starts at Qualifier (0x00, 0x04, 0x05, 0x81, 0x01 = 5 bytes)
        Assert.Equal(new byte[] { 0x00, 0x04, 0x05, 0x81, 0x01 }, g1Call.ObjectData);
    }

    [Fact]
    public void ProcessFrame_Group1Var1PackedAndVar2FlagsAndGroup10Var1PackedAndVar2Flags_DecodesBinaryValuesAndQualityFlags()
    {
        var g1v1Idx4Id = Guid.Parse("30000000-0000-0000-0000-000000000001");
        var g1v1Idx6Id = Guid.Parse("30000000-0000-0000-0000-000000000002");
        var g1v2Idx4Id = Guid.Parse("30000000-0000-0000-0000-000000000003");
        var g1v2Idx5Id = Guid.Parse("30000000-0000-0000-0000-000000000004");
        var g10v1Idx2Id = Guid.Parse("30000000-0000-0000-0000-000000000005");
        var g10v2Idx7Id = Guid.Parse("30000000-0000-0000-0000-000000000006");

        var tags = new[]
        {
            new TagDefinition(g1v1Idx4Id, PairId, "BI_Packed_4", ProtocolAddress.Parse("G01V01:Idx4"), TagDataType.Bool, 1.0, 0.0, null, null),
            new TagDefinition(g1v1Idx6Id, PairId, "BI_Packed_6", ProtocolAddress.Parse("G01V01:Idx6"), TagDataType.Bool, 1.0, 0.0, null, null),
            new TagDefinition(g1v2Idx4Id, PairId, "Relay_Trip_State", ProtocolAddress.Parse("G01V02:Idx4"), TagDataType.Bool, 1.0, 0.0, null, null),
            new TagDefinition(g1v2Idx5Id, PairId, "Breaker_Aux_52b", ProtocolAddress.Parse("G01V02:Idx5"), TagDataType.Bool, 1.0, 0.0, null, null),
            new TagDefinition(g10v1Idx2Id, PairId, "BO_Packed_2", ProtocolAddress.Parse("G10V01:Idx2"), TagDataType.Bool, 1.0, 0.0, null, null),
            new TagDefinition(g10v2Idx7Id, PairId, "BO_Status_7", ProtocolAddress.Parse("G10V02:Idx7"), TagDataType.Bool, 1.0, 0.0, null, null)
        };

        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var registry = new Dnp3HandlerRegistry(
        [
            new Group1BinaryInputStaticHandler(tagEngine),
            new Group10BinaryOutputStatusHandler(tagEngine)
        ]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair(masterAddr: 1, outstationAddr: 100);

        // Request SEQ = 3
        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, BuildDnp3LinkFrame(100, 1, 0xC0, [0xC3, 0x01, 0x3C, 0x01, 0x06])),
            pair,
            TrafficDirection.ClientToServer);

        // Response SEQ = 3 containing:
        // 1. Group 1 Var 1 (packed binary): Qualifier 0x00 (8-bit start/stop), Start = 4, Stop = 6 (3 points: Idx 4, 5, 6)
        //    Packed byte = 0b1111_1001 (0xF9):
        //      bit 0 (Idx 4) = 1 (true)
        //      bit 1 (Idx 5, unmapped) = 0 (false)
        //      bit 2 (Idx 6) = 0 (false)
        //      bits 3..7 = 1 (padding beyond Stop=6, must be ignored)
        // 2. Group 1 Var 2 (binary with flags): Qualifier 0x00 (8-bit start/stop), Start = 4, Stop = 5 (2 points: Idx 4, 5)
        //    Idx 4 byte = 0x83 (STATE = 1 [0x80], RESTART [0x02], ONLINE [0x01])
        //    Idx 5 byte = 0x34 (STATE = 0, CHATTER_FILTER [0x20], LOCAL_FORCED [0x10], COMM_LOST [0x04])
        // 3. Group 10 Var 1 (packed binary output): Qualifier 0x01 (16-bit start/stop), Start = 1 (0x01,0x00), Stop = 2 (0x02,0x00)
        //    Packed byte = 0b0000_0010 (0x02):
        //      bit 0 (Idx 1, unmapped) = 0
        //      bit 1 (Idx 2) = 1 (true)
        // 4. Group 10 Var 2 (binary output status with flags): Qualifier 0x17 (1-byte index prefix, 8-bit count), Count = 1
        //    Prefix Index = 7, Flags = 0x89 (STATE = 1 [0x80], REMOTE_FORCED [0x08], ONLINE [0x01])
        byte[] appFragment =
        [
            0xC3, 0x81, 0x00, 0x00,
            // G1V1:
            1, 1, 0x00, 0x04, 0x06, 0xF9,
            // G1V2:
            1, 2, 0x00, 0x04, 0x05, 0x83, 0x34,
            // G10V1:
            10, 1, 0x01, 0x01, 0x00, 0x02, 0x00, 0x02,
            // G10V2:
            10, 2, 0x17, 0x01, 0x07, 0x89
        ];

        var respOutput = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(30), TrafficDirection.ServerToClient, BuildDnp3LinkFrame(1, 100, 0xC0, appFragment)),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Single(respOutput.Transactions);
        Assert.Equal(6, respOutput.DataPoints.Count);

        // 1. G01V01:Idx4 -> true, Online, "01"
        var dp0 = respOutput.DataPoints[0];
        Assert.Equal(g1v1Idx4Id, dp0.TagId);
        Assert.True(dp0.BooleanValue);
        Assert.Null(dp0.UnscaledNumericValue);
        Assert.Equal("01", dp0.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp0.QualityFlags);

        // 2. G01V01:Idx6 -> false, Online, "00"
        var dp1 = respOutput.DataPoints[1];
        Assert.Equal(g1v1Idx6Id, dp1.TagId);
        Assert.False(dp1.BooleanValue);
        Assert.Equal("00", dp1.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp1.QualityFlags);

        // 3. G01V02:Idx4 -> true, Online | Restart, "83"
        var dp2 = respOutput.DataPoints[2];
        Assert.Equal(g1v2Idx4Id, dp2.TagId);
        Assert.True(dp2.BooleanValue);
        Assert.Equal("83", dp2.RawHex);
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.Restart, dp2.QualityFlags);

        // 4. G01V02:Idx5 -> false, CommLost | LocalForced | ChatterFilter, "34"
        var dp3 = respOutput.DataPoints[3];
        Assert.Equal(g1v2Idx5Id, dp3.TagId);
        Assert.False(dp3.BooleanValue);
        Assert.Equal("34", dp3.RawHex);
        Assert.Equal(PointQualityFlags.CommLost | PointQualityFlags.LocalForced | PointQualityFlags.ChatterFilter, dp3.QualityFlags);

        // 5. G10V01:Idx2 -> true, Online, "01"
        var dp4 = respOutput.DataPoints[4];
        Assert.Equal(g10v1Idx2Id, dp4.TagId);
        Assert.True(dp4.BooleanValue);
        Assert.Equal("01", dp4.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp4.QualityFlags);

        // 6. G10V02:Idx7 -> true, Online | RemoteForced, "89"
        var dp5 = respOutput.DataPoints[5];
        Assert.Equal(g10v2Idx7Id, dp5.TagId);
        Assert.True(dp5.BooleanValue);
        Assert.Equal("89", dp5.RawHex);
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.RemoteForced, dp5.QualityFlags);
    }

    [Fact]
    public void ProcessFrame_Group20RunningCountersVar1Var2Var5Var6_Decodes32And16BitCountersAndQualityFlags()
    {
        var g20v1Idx0Id = Guid.Parse("40000000-0000-0000-0000-000000000001");
        var g20v2Idx1Id = Guid.Parse("40000000-0000-0000-0000-000000000002");
        var g20v5Idx2Id = Guid.Parse("40000000-0000-0000-0000-000000000003");
        var g20v6Idx3Id = Guid.Parse("40000000-0000-0000-0000-000000000004");

        var tags = new[]
        {
            new TagDefinition(g20v1Idx0Id, PairId, "Pulse_Cnt_32_Flag", ProtocolAddress.Parse("G20V01:Idx0"), TagDataType.Int32, 0.1, 0.0, "kWh", null),
            new TagDefinition(g20v2Idx1Id, PairId, "Pulse_Cnt_16_Flag", ProtocolAddress.Parse("G20V02:Idx1"), TagDataType.UInt16, 1.0, 5.0, "Counts", null),
            new TagDefinition(g20v5Idx2Id, PairId, "Pulse_Cnt_32_NoFlag", ProtocolAddress.Parse("G20V05:Idx2"), TagDataType.Int32, 0.01, 0.0, "MWh", null),
            new TagDefinition(g20v6Idx3Id, PairId, "Pulse_Cnt_16_NoFlag", ProtocolAddress.Parse("G20V06:Idx3"), TagDataType.UInt16, 2.0, 0.0, "Counts", null)
        };

        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var registry = new Dnp3HandlerRegistry([new Group20RunningCounterHandler(tagEngine)]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair(masterAddr: 1, outstationAddr: 100);

        // Request SEQ = 4
        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, BuildDnp3LinkFrame(100, 1, 0xC0, [0xC4, 0x01, 0x14, 0x00, 0x06])),
            pair,
            TrafficDirection.ClientToServer);

        // Response SEQ = 4 containing:
        // 1. G20V1 (32-bit running counter with flags, 5 bytes): Qualifier 0x00, Start=0, Stop=0
        //    Flags = 0x01 (Online), Value = 123456 (0x0001E240 -> LE: 40 E2 01 00) -> Scaled = 12345.6
        // 2. G20V2 (16-bit running counter with flags, 3 bytes): Qualifier 0x00, Start=1, Stop=1
        //    Flags = 0x23 (Online | Restart | Rollover/ChatterFilter), Value = 50000 (0xC350 -> LE: 50 C3) -> Scaled = 50005.0
        // 3. G20V5 (32-bit running counter without flags, 4 bytes): Qualifier 0x00, Start=2, Stop=2
        //    Value = 500000 (0x0007A120 -> LE: 20 A1 07 00) -> Scaled = 5000.0, Quality = Online
        // 4. G20V6 (16-bit running counter without flags, 2 bytes): Qualifier 0x28 (2-byte index prefix, 16-bit count = 1), Index = 3 (0x03, 0x00)
        //    Value = 1200 (0x04B0 -> LE: B0 04) -> Scaled = 2400.0, Quality = Online
        byte[] appFragment =
        [
            0xC4, 0x81, 0x00, 0x00,
            // G20V1:
            20, 1, 0x00, 0x00, 0x00, 0x01, 0x40, 0xE2, 0x01, 0x00,
            // G20V2:
            20, 2, 0x00, 0x01, 0x01, 0x23, 0x50, 0xC3,
            // G20V5:
            20, 5, 0x00, 0x02, 0x02, 0x20, 0xA1, 0x07, 0x00,
            // G20V6:
            20, 6, 0x28, 0x01, 0x00, 0x03, 0x00, 0xB0, 0x04
        ];

        var respOutput = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(40), TrafficDirection.ServerToClient, BuildDnp3LinkFrame(1, 100, 0xC0, appFragment)),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Single(respOutput.Transactions);
        Assert.Equal(4, respOutput.DataPoints.Count);

        // 1. G20V01:Idx0
        var dp0 = respOutput.DataPoints[0];
        Assert.Equal(g20v1Idx0Id, dp0.TagId);
        Assert.Equal(123456.0, dp0.UnscaledNumericValue);
        Assert.Equal(12345.6, dp0.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("0140E20100", dp0.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp0.QualityFlags);

        // 2. G20V02:Idx1
        var dp1 = respOutput.DataPoints[1];
        Assert.Equal(g20v2Idx1Id, dp1.TagId);
        Assert.Equal(50000.0, dp1.UnscaledNumericValue);
        Assert.Equal(50005.0, dp1.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("2350C3", dp1.RawHex);
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.Restart | PointQualityFlags.ChatterFilter, dp1.QualityFlags);

        // 3. G20V05:Idx2
        var dp2 = respOutput.DataPoints[2];
        Assert.Equal(g20v5Idx2Id, dp2.TagId);
        Assert.Equal(500000.0, dp2.UnscaledNumericValue);
        Assert.Equal(5000.0, dp2.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("20A10700", dp2.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp2.QualityFlags);

        // 4. G20V06:Idx3
        var dp3 = respOutput.DataPoints[3];
        Assert.Equal(g20v6Idx3Id, dp3.TagId);
        Assert.Equal(1200.0, dp3.UnscaledNumericValue);
        Assert.Equal(2400.0, dp3.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("B004", dp3.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp3.QualityFlags);
    }

    [Fact]
    public void ProcessFrame_Group30AnalogInputStaticVar1ThroughVar5_Decodes16And32BitSignedIntegersFloat32AndQualityFlags()
    {
        var g30v1Idx0Id = Guid.Parse("50000000-0000-0000-0000-000000000001");
        var g30v2Idx0Id = Guid.Parse("50000000-0000-0000-0000-000000000002");
        var g30v3Idx1Id = Guid.Parse("50000000-0000-0000-0000-000000000003");
        var g30v4Idx2Id = Guid.Parse("50000000-0000-0000-0000-000000000004");
        var g30v5Idx3Id = Guid.Parse("50000000-0000-0000-0000-000000000005");

        var tags = new[]
        {
            new TagDefinition(g30v1Idx0Id, PairId, "Feeder_kW_32Flag", ProtocolAddress.Parse("G30V01:Idx0"), TagDataType.Int32, 0.1, 0.0, "kW", null),
            new TagDefinition(g30v2Idx0Id, PairId, "Feeder_MW_16Flag", ProtocolAddress.Parse("G30V02:Idx0"), TagDataType.Int16, 0.01, 0.0, "MW", null),
            new TagDefinition(g30v3Idx1Id, PairId, "Feeder_Var_32NoFlag", ProtocolAddress.Parse("G30V03:Idx1"), TagDataType.Int32, 1.0, 10.0, "kVAR", null),
            new TagDefinition(g30v4Idx2Id, PairId, "Temp_C_16NoFlag", ProtocolAddress.Parse("G30V04:Idx2"), TagDataType.Int16, 0.5, 0.0, "C", null),
            new TagDefinition(g30v5Idx3Id, PairId, "Bus_Freq_Float32Flag", ProtocolAddress.Parse("G30V05:Idx3"), TagDataType.Float32Be, 1.0, 0.0, "Hz", null)
        };

        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var registry = new Dnp3HandlerRegistry([new Group30AnalogInputStaticHandler(tagEngine)]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair(masterAddr: 1, outstationAddr: 100);

        // Request SEQ = 7
        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer, BuildDnp3LinkFrame(100, 1, 0xC0, [0xC7, 0x01, 0x1E, 0x00, 0x06])),
            pair,
            TrafficDirection.ClientToServer);

        // Response SEQ = 7 containing:
        // 1. G30V1 (32-bit signed int with flags, 5 bytes): Qualifier 0x00, Start=0, Stop=0
        //    Flags = 0x41 (Online [0x01] | OverRange [0x40]), Value = -100000 (0xFFFE7960 -> LE: 60 79 FE FF) -> Scaled = -10000.0
        // 2. G30V2 (16-bit signed int with flags, 3 bytes): Qualifier 0x00, Start=0, Stop=0
        //    Flags = 0x81 (Online [0x01] | ReferenceErr [0x80]), Value = -2500 (0xF63C -> LE: 3C F6) -> Scaled = -25.0
        // 3. G30V3 (32-bit signed int without flags, 4 bytes): Qualifier 0x00, Start=1, Stop=1
        //    Value = 75000 (0x000124F8 -> LE: F8 24 01 00) -> Scaled = 75010.0, Quality = Online
        // 4. G30V4 (16-bit signed int without flags, 2 bytes): Qualifier 0x00, Start=2, Stop=2
        //    Value = -40 (0xFFD8 -> LE: D8 FF) -> Scaled = -20.0, Quality = Online
        // 5. G30V5 (32-bit float with flags, 5 bytes): Qualifier 0x00, Start=3, Stop=3
        //    Flags = 0x01 (Online), Value = 50.25f (IEEE 754: 0x42490000 -> LE: 00 00 49 42) -> Scaled = 50.25
        byte[] appFragment =
        [
            0xC7, 0x81, 0x00, 0x00,
            // G30V1:
            30, 1, 0x00, 0x00, 0x00, 0x41, 0x60, 0x79, 0xFE, 0xFF,
            // G30V2:
            30, 2, 0x00, 0x00, 0x00, 0x81, 0x3C, 0xF6,
            // G30V3:
            30, 3, 0x00, 0x01, 0x01, 0xF8, 0x24, 0x01, 0x00,
            // G30V4:
            30, 4, 0x00, 0x02, 0x02, 0xD8, 0xFF,
            // G30V5:
            30, 5, 0x00, 0x03, 0x03, 0x01, 0x00, 0x00, 0x49, 0x42
        ];

        var respOutput = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(50), TrafficDirection.ServerToClient, BuildDnp3LinkFrame(1, 100, 0xC0, appFragment)),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Single(respOutput.Transactions);
        Assert.Equal(5, respOutput.DataPoints.Count);

        // 1. G30V01:Idx0
        var dp0 = respOutput.DataPoints[0];
        Assert.Equal(g30v1Idx0Id, dp0.TagId);
        Assert.Equal(-100000.0, dp0.UnscaledNumericValue);
        Assert.Equal(-10000.0, dp0.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("416079FEFF", dp0.RawHex);
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.OverRange, dp0.QualityFlags);

        // 2. G30V02:Idx0
        var dp1 = respOutput.DataPoints[1];
        Assert.Equal(g30v2Idx0Id, dp1.TagId);
        Assert.Equal(-2500.0, dp1.UnscaledNumericValue);
        Assert.Equal(-25.0, dp1.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("813CF6", dp1.RawHex);
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.ReferenceErr, dp1.QualityFlags);

        // 3. G30V03:Idx1
        var dp2 = respOutput.DataPoints[2];
        Assert.Equal(g30v3Idx1Id, dp2.TagId);
        Assert.Equal(75000.0, dp2.UnscaledNumericValue);
        Assert.Equal(75010.0, dp2.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("F8240100", dp2.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp2.QualityFlags);

        // 4. G30V04:Idx2
        var dp3 = respOutput.DataPoints[3];
        Assert.Equal(g30v4Idx2Id, dp3.TagId);
        Assert.Equal(-40.0, dp3.UnscaledNumericValue);
        Assert.Equal(-20.0, dp3.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("D8FF", dp3.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp3.QualityFlags);

        // 5. G30V05:Idx3
        var dp4 = respOutput.DataPoints[4];
        Assert.Equal(g30v5Idx3Id, dp4.TagId);
        Assert.Equal(50.25, dp4.UnscaledNumericValue!.Value, precision: 5);
        Assert.Equal(50.25, dp4.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("0100004942", dp4.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp4.QualityFlags);
    }

    [Fact]
    public void Dnp3HandlerRegistryAndDirectExtractObjects_Supports16BitRangeAndUnknownGroupsOrVariationsAndTimeoutFlushing()
    {
        var tagId = Guid.Parse("60000000-0000-0000-0000-000000000001");
        var tag = new TagDefinition(tagId, PairId, "AI_High_Idx", ProtocolAddress.Parse("G30V2:Idx300"), TagDataType.Int16, 1.0, 0.0, null, null);
        var tagEngine = new TagResolutionEngine([tag]);
        var g30Handler = new Group30AnalogInputStaticHandler(tagEngine);
        var registry = new Dnp3HandlerRegistry([g30Handler]);

        Assert.True(registry.TryGetHandler(30, out var resolvedHandler));
        Assert.Same(g30Handler, resolvedHandler);
        Assert.False(registry.TryGetHandler(99, out _));

        var pair = CreatePair(1, 100);
        var frame = CreateFrame(50, BaseTime, TrafficDirection.ServerToClient, []);
        var dataPoints = new List<ExtractedDataPointRecord>();
        var commands = new List<CapturedCommandEventRecord>();

        // 1. Direct ExtractObjects with Qualifier 0x01 (16-bit start/stop), Start = 300 (0x012C -> 2C 01), Stop = 300 (2C 01)
        //    G30V2 item: Flags = 0x01 (Online), Value = 1234 (0x04D2 -> D2 04)
        byte[] g30v2Data = [0x01, 0x2C, 0x01, 0x2C, 0x01, 0x01, 0xD2, 0x04];
        g30Handler.ExtractObjects(frame, pair, TrafficDirection.ServerToClient, variation: 2, g30v2Data, dataPoints, commands);

        var dp = Assert.Single(dataPoints);
        Assert.Equal(tagId, dp.TagId);
        Assert.Equal(1234.0, dp.UnscaledNumericValue);
        Assert.Equal("01D204", dp.RawHex);

        // 2. Unsupported variation (Var 99) is ignored safely
        dataPoints.Clear();
        g30Handler.ExtractObjects(frame, pair, TrafficDirection.ServerToClient, variation: 99, g30v2Data, dataPoints, commands);
        Assert.Empty(dataPoints);

        // 3. FlushExpiredTimeouts on Dnp3Decoder delegates to VirtualClockRedEngine
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 1000);
        var decoder = new Dnp3Decoder(redEngine, registry);
        byte[] reqPayload = BuildDnp3LinkFrame(100, 1, 0xC0, [0xC1, 0x01, 0x3C, 0x01, 0x06]);
        decoder.ProcessFrame(CreateFrame(60, BaseTime, TrafficDirection.ClientToServer, reqPayload), pair, TrafficDirection.ClientToServer);

        var timeouts = decoder.FlushExpiredTimeouts(BaseTime.AddMilliseconds(1500), isEndOfFile: false);
        var timeoutTx = Assert.Single(timeouts);
        Assert.Equal("1", timeoutTx.TransactionId);
        Assert.True(timeoutTx.IsError);
        Assert.Equal(TransactionErrorType.Timeout, timeoutTx.ErrorType);
        Assert.Equal(TransactionStatusCode.Timeout, timeoutTx.StatusCode);
    }

    /// <summary>
    /// Writes a 48-bit unsigned integer (milliseconds since Unix Epoch) in Little-Endian order into a 6-byte array.
    /// </summary>
    private static byte[] EncodeDnp3Timestamp48(DateTime utcTimestamp)
    {
        ulong epochMs = (ulong)new DateTimeOffset(utcTimestamp).ToUnixTimeMilliseconds();
        byte[] bytes = new byte[6];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0, 4), (uint)(epochMs & 0xFFFF_FFFFUL));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(4, 2), (ushort)((epochMs >> 32) & 0xFFFFUL));
        return bytes;
    }

    [Fact]
    public void ProcessFrame_Group2BinaryInputEventVar1Var2Var3_DecodesDualTimestampsQualityFlagsAndStaticFallbackTags()
    {
        var g2v1Idx1Id = Guid.Parse("70000000-0000-0000-0000-000000000001");
        var g2v2Idx4Id = Guid.Parse("70000000-0000-0000-0000-000000000002");
        var g2v3Idx7Id = Guid.Parse("70000000-0000-0000-0000-000000000003");

        var tags = new[]
        {
            // Mapped explicitly to G02V01:Idx1
            new TagDefinition(g2v1Idx1Id, PairId, "Event_NoTime_1", ProtocolAddress.Parse("G02V01:Idx1"), TagDataType.Bool, 1.0, 0.0, null, null),
            // Mapped via static Group 1 fallback G01V02:Idx4 (as in SPECIFICATION.md CSV example)
            new TagDefinition(g2v2Idx4Id, PairId, "Relay_Trip_State", ProtocolAddress.Parse("G01V02:Idx4"), TagDataType.Bool, 1.0, 0.0, null, null),
            // Mapped to G02V03:Idx7
            new TagDefinition(g2v3Idx7Id, PairId, "Event_RelTime_7", ProtocolAddress.Parse("G02V03:Idx7"), TagDataType.Bool, 1.0, 0.0, null, null)
        };

        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var registry = new Dnp3HandlerRegistry([new Group2BinaryInputEventHandler(tagEngine)]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair(masterAddr: 1, outstationAddr: 100);

        DateTime packetArrivalUtc = BaseTime.AddSeconds(10);
        DateTime rtuEventUtc = BaseTime.AddSeconds(9).AddMilliseconds(876); // 124 ms before packet arrival
        byte[] rtuTimeBytes = EncodeDnp3Timestamp48(rtuEventUtc);

        // Unsolicited Response (FC = 0x82) or Solicited Response (FC = 0x81) containing:
        // 1. G2V1 (without time, 1 byte): Qualifier 0x17 (1-byte index prefix, 8-bit count = 1), Index = 1, Flags = 0x81 (STATE=1, ONLINE)
        // 2. G2V2 (with 48-bit absolute time, 7 bytes): Qualifier 0x17 (1-byte index prefix, 8-bit count = 1), Index = 4, Flags = 0x83 (STATE=1, ONLINE | RESTART), 6-byte timestamp
        // 3. G2V3 (with 16-bit relative time, 3 bytes): Qualifier 0x28 (2-byte index prefix, 16-bit count = 1), Index = 7 (0x07, 0x00), Flags = 0x05 (STATE=0, ONLINE | COMM_LOST), RelTime = 250 ms (0xFA, 0x00)
        byte[] appFragment =
        [
            0xD1, 0x82, 0x00, 0x00, // Unsolicited response FC = 0x82
            // G2V1:
            2, 1, 0x17, 0x01, 0x01, 0x81,
            // G2V2:
            2, 2, 0x17, 0x01, 0x04, 0x83,
            rtuTimeBytes[0], rtuTimeBytes[1], rtuTimeBytes[2], rtuTimeBytes[3], rtuTimeBytes[4], rtuTimeBytes[5],
            // G2V3:
            2, 3, 0x28, 0x01, 0x00, 0x07, 0x00, 0x05, 0xFA, 0x00
        ];

        var output = decoder.ProcessFrame(
            CreateFrame(10, packetArrivalUtc, TrafficDirection.ServerToClient, BuildDnp3LinkFrame(1, 100, 0xC0, appFragment)),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Equal(3, output.DataPoints.Count);

        // 1. G2V1: EventTimestamp is null, PacketTimestamp is packetArrivalUtc
        var dp0 = output.DataPoints[0];
        Assert.Equal(g2v1Idx1Id, dp0.TagId);
        Assert.Equal(packetArrivalUtc, dp0.PacketTimestamp);
        Assert.Null(dp0.EventTimestamp);
        Assert.True(dp0.BooleanValue);
        Assert.Equal("81", dp0.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp0.QualityFlags);

        // 2. G2V2: EventTimestamp is rtuEventUtc (48-bit DNP3 time), PacketTimestamp is packetArrivalUtc
        var dp1 = output.DataPoints[1];
        Assert.Equal(g2v2Idx4Id, dp1.TagId);
        Assert.Equal(packetArrivalUtc, dp1.PacketTimestamp);
        Assert.Equal(rtuEventUtc, dp1.EventTimestamp);
        Assert.True(dp1.BooleanValue);
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.Restart, dp1.QualityFlags);
        Assert.Equal(14, dp1.RawHex.Length); // 7 bytes = 14 hex chars

        // 3. G2V3: EventTimestamp is packetArrivalUtc + 250ms (relative time without preceding CTO), PacketTimestamp is packetArrivalUtc
        var dp2 = output.DataPoints[2];
        Assert.Equal(g2v3Idx7Id, dp2.TagId);
        Assert.Equal(packetArrivalUtc, dp2.PacketTimestamp);
        Assert.Equal(packetArrivalUtc.AddMilliseconds(250), dp2.EventTimestamp);
        Assert.False(dp2.BooleanValue);
        Assert.Equal("05FA00", dp2.RawHex);
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.CommLost, dp2.QualityFlags);
    }

    [Fact]
    public void ProcessFrame_Group22CounterChangeEventVar1Var2Var5Var6_DecodesCounterEventsWithAndWithoutTimestamps()
    {
        var g22v1Idx0Id = Guid.Parse("71000000-0000-0000-0000-000000000001");
        var g22v2Idx1Id = Guid.Parse("71000000-0000-0000-0000-000000000002");
        var g22v5Idx2Id = Guid.Parse("71000000-0000-0000-0000-000000000003");
        var g22v6Idx3Id = Guid.Parse("71000000-0000-0000-0000-000000000004");

        var tags = new[]
        {
            new TagDefinition(g22v1Idx0Id, PairId, "CntEvt_32_NoTime", ProtocolAddress.Parse("G22V01:Idx0"), TagDataType.Int32, 0.1, 0.0, "kWh", null),
            new TagDefinition(g22v2Idx1Id, PairId, "CntEvt_16_NoTime", ProtocolAddress.Parse("G22V02:Idx1"), TagDataType.UInt16, 1.0, 0.0, "Counts", null),
            // Mapped via static Group 20 fallback G20V01:Idx2
            new TagDefinition(g22v5Idx2Id, PairId, "CntEvt_32_WithTime", ProtocolAddress.Parse("G20V01:Idx2"), TagDataType.Int32, 0.01, 0.0, "MWh", null),
            new TagDefinition(g22v6Idx3Id, PairId, "CntEvt_16_WithTime", ProtocolAddress.Parse("G22V06:Idx3"), TagDataType.UInt16, 2.0, 10.0, "Counts", null)
        };

        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var registry = new Dnp3HandlerRegistry([new Group22CounterChangeEventHandler(tagEngine)]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair(masterAddr: 1, outstationAddr: 100);

        DateTime packetArrivalUtc = BaseTime.AddSeconds(20);
        DateTime eventTime5 = BaseTime.AddSeconds(19).AddMilliseconds(500);
        DateTime eventTime6 = BaseTime.AddSeconds(19).AddMilliseconds(750);
        byte[] t5Bytes = EncodeDnp3Timestamp48(eventTime5);
        byte[] t6Bytes = EncodeDnp3Timestamp48(eventTime6);

        // 1. G22V1 (32-bit counter event without time, 5 bytes): Qualifier 0x17, Count = 1, Index = 0, Flags = 0x01 (Online), Value = 200000 (0x00030D40 -> 40 0D 03 00) -> Scaled = 20000.0
        // 2. G22V2 (16-bit counter event without time, 3 bytes): Qualifier 0x17, Count = 1, Index = 1, Flags = 0x21 (Online | ChatterFilter/Rollover), Value = 40000 (0x9C40 -> 40 9C) -> Scaled = 40000.0
        // 3. G22V5 (32-bit counter event with 48-bit time, 11 bytes): Qualifier 0x17, Count = 1, Index = 2, Flags = 0x01 (Online), Value = 900000 (0x000DBBA0 -> A0 BB 0D 00), Time = eventTime5 -> Scaled = 9000.0
        // 4. G22V6 (16-bit counter event with 48-bit time, 9 bytes): Qualifier 0x17, Count = 1, Index = 3, Flags = 0x03 (Online | Restart), Value = 1500 (0x05DC -> DC 05), Time = eventTime6 -> Scaled = 3010.0
        byte[] appFragment =
        [
            0xD2, 0x82, 0x00, 0x00,
            // G22V1:
            22, 1, 0x17, 0x01, 0x00, 0x01, 0x40, 0x0D, 0x03, 0x00,
            // G22V2:
            22, 2, 0x17, 0x01, 0x01, 0x21, 0x40, 0x9C,
            // G22V5:
            22, 5, 0x17, 0x01, 0x02, 0x01, 0xA0, 0xBB, 0x0D, 0x00,
            t5Bytes[0], t5Bytes[1], t5Bytes[2], t5Bytes[3], t5Bytes[4], t5Bytes[5],
            // G22V6:
            22, 6, 0x17, 0x01, 0x03, 0x03, 0xDC, 0x05,
            t6Bytes[0], t6Bytes[1], t6Bytes[2], t6Bytes[3], t6Bytes[4], t6Bytes[5]
        ];

        var output = decoder.ProcessFrame(
            CreateFrame(20, packetArrivalUtc, TrafficDirection.ServerToClient, BuildDnp3LinkFrame(1, 100, 0xC0, appFragment)),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Equal(4, output.DataPoints.Count);

        // 1. G22V1
        var dp0 = output.DataPoints[0];
        Assert.Equal(g22v1Idx0Id, dp0.TagId);
        Assert.Equal(packetArrivalUtc, dp0.PacketTimestamp);
        Assert.Null(dp0.EventTimestamp);
        Assert.Equal(200000.0, dp0.UnscaledNumericValue);
        Assert.Equal(20000.0, dp0.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("01400D0300", dp0.RawHex);
        Assert.Equal(PointQualityFlags.Online, dp0.QualityFlags);

        // 2. G22V2
        var dp1 = output.DataPoints[1];
        Assert.Equal(g22v2Idx1Id, dp1.TagId);
        Assert.Equal(packetArrivalUtc, dp1.PacketTimestamp);
        Assert.Null(dp1.EventTimestamp);
        Assert.Equal(40000.0, dp1.UnscaledNumericValue);
        Assert.Equal(40000.0, dp1.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("21409C", dp1.RawHex);
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.ChatterFilter, dp1.QualityFlags);

        // 3. G22V5
        var dp2 = output.DataPoints[2];
        Assert.Equal(g22v5Idx2Id, dp2.TagId);
        Assert.Equal(packetArrivalUtc, dp2.PacketTimestamp);
        Assert.Equal(eventTime5, dp2.EventTimestamp);
        Assert.Equal(900000.0, dp2.UnscaledNumericValue);
        Assert.Equal(9000.0, dp2.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal(22, dp2.RawHex.Length); // 11 bytes = 22 hex chars
        Assert.Equal(PointQualityFlags.Online, dp2.QualityFlags);

        // 4. G22V6
        var dp3 = output.DataPoints[3];
        Assert.Equal(g22v6Idx3Id, dp3.TagId);
        Assert.Equal(packetArrivalUtc, dp3.PacketTimestamp);
        Assert.Equal(eventTime6, dp3.EventTimestamp);
        Assert.Equal(1500.0, dp3.UnscaledNumericValue);
        Assert.Equal(3010.0, dp3.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal(18, dp3.RawHex.Length); // 9 bytes = 18 hex chars
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.Restart, dp3.QualityFlags);
    }

    [Fact]
    public void ProcessFrame_Group32AnalogInputEventVar1Var2Var3Var4Var5Var7_DecodesInt16Int32Float32EventsWithAndWithoutTimestamps()
    {
        var g32v1Idx0Id = Guid.Parse("72000000-0000-0000-0000-000000000001");
        var g32v2Idx0Id = Guid.Parse("72000000-0000-0000-0000-000000000002");
        var g32v3Idx1Id = Guid.Parse("72000000-0000-0000-0000-000000000003");
        var g32v4Idx2Id = Guid.Parse("72000000-0000-0000-0000-000000000004");
        var g32v5Idx3Id = Guid.Parse("72000000-0000-0000-0000-000000000005");
        var g32v7Idx4Id = Guid.Parse("72000000-0000-0000-0000-000000000006");

        var tags = new[]
        {
            new TagDefinition(g32v1Idx0Id, PairId, "AiEvt_32_NoTime", ProtocolAddress.Parse("G32V01:Idx0"), TagDataType.Int32, 0.1, 0.0, "kW", null),
            // Mapped via static Group 30 fallback G30V02:Idx0 (as in SPECIFICATION.md CSV example)
            new TagDefinition(g32v2Idx0Id, PairId, "Feeder_MW", ProtocolAddress.Parse("G30V02:Idx0"), TagDataType.Int16, 0.01, 0.0, "MW", null),
            new TagDefinition(g32v3Idx1Id, PairId, "AiEvt_32_WithTime", ProtocolAddress.Parse("G32V03:Idx1"), TagDataType.Int32, 0.5, 0.0, "kW", null),
            new TagDefinition(g32v4Idx2Id, PairId, "AiEvt_16_WithTime", ProtocolAddress.Parse("G32V04:Idx2"), TagDataType.Int16, 0.1, 5.0, "C", null),
            new TagDefinition(g32v5Idx3Id, PairId, "AiEvt_Float_NoTime", ProtocolAddress.Parse("G32V05:Idx3"), TagDataType.Float32Be, 2.0, 0.0, "A", null),
            new TagDefinition(g32v7Idx4Id, PairId, "AiEvt_Float_WithTime", ProtocolAddress.Parse("G32V07:Idx4"), TagDataType.Float32Be, 1.0, 0.0, "Hz", null)
        };

        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var registry = new Dnp3HandlerRegistry([new Group32AnalogInputEventHandler(tagEngine)]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair(masterAddr: 1, outstationAddr: 100);

        DateTime packetArrivalUtc = BaseTime.AddSeconds(30);
        DateTime eventTime3 = BaseTime.AddSeconds(29).AddMilliseconds(100);
        DateTime eventTime4 = BaseTime.AddSeconds(29).AddMilliseconds(200);
        DateTime eventTime7 = BaseTime.AddSeconds(29).AddMilliseconds(300);
        byte[] t3Bytes = EncodeDnp3Timestamp48(eventTime3);
        byte[] t4Bytes = EncodeDnp3Timestamp48(eventTime4);
        byte[] t7Bytes = EncodeDnp3Timestamp48(eventTime7);

        // 1. G32V1 (32-bit signed int without time, 5 bytes): Qualifier 0x17, Count=1, Index=0, Flags=0x01 (Online), Value=-50000 (0xFFFF3CB0 -> B0 3C FF FF) -> Scaled = -5000.0
        // 2. G32V2 (16-bit signed int without time, 3 bytes): Qualifier 0x17, Count=1, Index=0, Flags=0x41 (Online | OverRange), Value=1250 (0x04E2 -> E2 04) -> Scaled = 12.5
        // 3. G32V3 (32-bit signed int with 48-bit time, 11 bytes): Qualifier 0x17, Count=1, Index=1, Flags=0x01 (Online), Value=40000 (0x00009C40 -> 40 9C 00 00), Time=eventTime3 -> Scaled = 20000.0
        // 4. G32V4 (16-bit signed int with 48-bit time, 9 bytes): Qualifier 0x17, Count=1, Index=2, Flags=0x81 (Online | ReferenceErr), Value=-150 (0xFF6A -> 6A FF), Time=eventTime4 -> Scaled = -10.0
        // 5. G32V5 (32-bit float without time, 5 bytes): Qualifier 0x17, Count=1, Index=3, Flags=0x01 (Online), Value=12.5f (0x41480000 -> LE: 00 00 48 41) -> Scaled = 25.0
        // 6. G32V7 (32-bit float with 48-bit time, 11 bytes): Qualifier 0x17, Count=1, Index=4, Flags=0x01 (Online), Value=60.5f (0x42720000 -> LE: 00 00 72 42), Time=eventTime7 -> Scaled = 60.5
        byte[] appFragment =
        [
            0xD3, 0x82, 0x00, 0x00,
            // G32V1:
            32, 1, 0x17, 0x01, 0x00, 0x01, 0xB0, 0x3C, 0xFF, 0xFF,
            // G32V2:
            32, 2, 0x17, 0x01, 0x00, 0x41, 0xE2, 0x04,
            // G32V3:
            32, 3, 0x17, 0x01, 0x01, 0x01, 0x40, 0x9C, 0x00, 0x00,
            t3Bytes[0], t3Bytes[1], t3Bytes[2], t3Bytes[3], t3Bytes[4], t3Bytes[5],
            // G32V4:
            32, 4, 0x17, 0x01, 0x02, 0x81, 0x6A, 0xFF,
            t4Bytes[0], t4Bytes[1], t4Bytes[2], t4Bytes[3], t4Bytes[4], t4Bytes[5],
            // G32V5:
            32, 5, 0x17, 0x01, 0x03, 0x01, 0x00, 0x00, 0x48, 0x41,
            // G32V7:
            32, 7, 0x17, 0x01, 0x04, 0x01, 0x00, 0x00, 0x72, 0x42,
            t7Bytes[0], t7Bytes[1], t7Bytes[2], t7Bytes[3], t7Bytes[4], t7Bytes[5]
        ];

        var output = decoder.ProcessFrame(
            CreateFrame(30, packetArrivalUtc, TrafficDirection.ServerToClient, BuildDnp3LinkFrame(1, 100, 0xC0, appFragment)),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Equal(6, output.DataPoints.Count);

        // 1. G32V1
        Assert.Equal(g32v1Idx0Id, output.DataPoints[0].TagId);
        Assert.Equal(packetArrivalUtc, output.DataPoints[0].PacketTimestamp);
        Assert.Null(output.DataPoints[0].EventTimestamp);
        Assert.Equal(-50000.0, output.DataPoints[0].UnscaledNumericValue);
        Assert.Equal(-5000.0, output.DataPoints[0].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("01B03CFFFF", output.DataPoints[0].RawHex);

        // 2. G32V2 (resolved via G30V02:Idx0 fallback)
        Assert.Equal(g32v2Idx0Id, output.DataPoints[1].TagId);
        Assert.Null(output.DataPoints[1].EventTimestamp);
        Assert.Equal(1250.0, output.DataPoints[1].UnscaledNumericValue);
        Assert.Equal(12.5, output.DataPoints[1].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.OverRange, output.DataPoints[1].QualityFlags);

        // 3. G32V3
        Assert.Equal(g32v3Idx1Id, output.DataPoints[2].TagId);
        Assert.Equal(eventTime3, output.DataPoints[2].EventTimestamp);
        Assert.Equal(40000.0, output.DataPoints[2].UnscaledNumericValue);
        Assert.Equal(20000.0, output.DataPoints[2].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal(22, output.DataPoints[2].RawHex.Length);

        // 4. G32V4
        Assert.Equal(g32v4Idx2Id, output.DataPoints[3].TagId);
        Assert.Equal(eventTime4, output.DataPoints[3].EventTimestamp);
        Assert.Equal(-150.0, output.DataPoints[3].UnscaledNumericValue);
        Assert.Equal(-10.0, output.DataPoints[3].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal(PointQualityFlags.Online | PointQualityFlags.ReferenceErr, output.DataPoints[3].QualityFlags);
        Assert.Equal(18, output.DataPoints[3].RawHex.Length);

        // 5. G32V5
        Assert.Equal(g32v5Idx3Id, output.DataPoints[4].TagId);
        Assert.Null(output.DataPoints[4].EventTimestamp);
        Assert.Equal(12.5, output.DataPoints[4].UnscaledNumericValue!.Value, precision: 5);
        Assert.Equal(25.0, output.DataPoints[4].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("0100004841", output.DataPoints[4].RawHex);

        // 6. G32V7
        Assert.Equal(g32v7Idx4Id, output.DataPoints[5].TagId);
        Assert.Equal(eventTime7, output.DataPoints[5].EventTimestamp);
        Assert.Equal(60.5, output.DataPoints[5].UnscaledNumericValue!.Value, precision: 5);
        Assert.Equal(60.5, output.DataPoints[5].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal(22, output.DataPoints[5].RawHex.Length);
    }

    [Theory]
    [InlineData(0x03, CommandType.Dnp3CrobSelect, 0x01, Dnp3ControlAction.PulseOn, true)]
    [InlineData(0x04, CommandType.Dnp3CrobOperate, 0x02, Dnp3ControlAction.PulseOff, false)]
    [InlineData(0x05, CommandType.Dnp3DirectOperate, 0x03, Dnp3ControlAction.LatchOn, true)]
    [InlineData(0x05, CommandType.Dnp3DirectOperate, 0x04, Dnp3ControlAction.LatchOff, false)]
    [InlineData(0x03, CommandType.Dnp3CrobSelect, 0x81, Dnp3ControlAction.Trip, false)]
    [InlineData(0x04, CommandType.Dnp3CrobOperate, 0x41, Dnp3ControlAction.Close, true)]
    public void ProcessFrame_Group12Var1CrobControlCommands_EmitsCapturedCommandEventProjectsMappedTagAndCorrelatesResponse(
        byte functionCode,
        CommandType expectedCommandType,
        byte controlCodeByte,
        Dnp3ControlAction expectedControlAction,
        bool expectedBooleanState)
    {
        var crobTagId = Guid.Parse("73000000-0000-0000-0000-000000000001");
        var tags = new[]
        {
            new TagDefinition(crobTagId, PairId, "Breaker_Trip_Cmd", ProtocolAddress.Parse("G12V01:Idx2"), TagDataType.Bool, 1.0, 0.0, null, "CROB Control Point")
        };

        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var registry = new Dnp3HandlerRegistry([new Group12CrobControlHandler(tagEngine)]);
        var decoder = new Dnp3Decoder(redEngine, registry);
        var pair = CreatePair(masterAddr: 1, outstationAddr: 100);

        // Build 11-byte CROB (Group 12 Var 1):
        // Qualifier = 0x17 (1-byte index prefix, 8-bit count = 1), Index = 2
        // ControlCode = controlCodeByte
        // Count = 3
        // OnTime = 500 ms (0x000001F4 -> F4 01 00 00)
        // OffTime = 1000 ms (0x000003E8 -> E8 03 00 00)
        // Status = 0x00
        byte[] appRequest =
        [
            0xC8, functionCode, // AppControl SEQ=8, FC = Select(3) / Operate(4) / DirectOperate(5)
            12, 1, 0x17, 0x01, 0x02,
            controlCodeByte,
            0x03,
            0xF4, 0x01, 0x00, 0x00,
            0xE8, 0x03, 0x00, 0x00,
            0x00
        ];

        byte[] reqFrameBytes = BuildDnp3LinkFrame(100, 1, 0xC0, appRequest);
        var reqOutput = decoder.ProcessFrame(
            CreateFrame(40, BaseTime, TrafficDirection.ClientToServer, reqFrameBytes),
            pair,
            TrafficDirection.ClientToServer);

        Assert.Empty(reqOutput.Transactions);
        var cmd = Assert.Single(reqOutput.CommandEvents);
        Assert.Equal(BaseTime, cmd.Timestamp);
        Assert.Equal(SessionId, cmd.SessionId);
        Assert.Equal(PairId, cmd.DevicePairId);
        Assert.Equal(40, cmd.FrameNumber);
        Assert.Equal(TrafficDirection.ClientToServer, cmd.Direction);
        Assert.Equal(ProtocolType.Dnp3, cmd.Protocol);
        Assert.Equal(functionCode, cmd.FunctionCode);
        Assert.Equal(expectedCommandType, cmd.CommandType);
        Assert.Equal(ProtocolAddress.Parse("G12V01:Idx2"), cmd.TargetAddress);
        Assert.Equal(expectedControlAction, cmd.ControlAction);
        Assert.Equal((short)3, cmd.CommandCount);
        Assert.Equal(500L, cmd.PulseOnMs);
        Assert.Equal(1000L, cmd.PulseOffMs);
        Assert.Equal(expectedBooleanState ? 1.0 : 0.0, cmd.UnscaledCommandValue);
        Assert.Equal(reqFrameBytes, cmd.RawPduBytes);

        // Verify mapped G12V01:Idx2 tag point is projected
        var dp = Assert.Single(reqOutput.DataPoints);
        Assert.Equal(crobTagId, dp.TagId);
        Assert.Equal(TrafficDirection.ClientToServer, dp.Direction);
        Assert.Equal(expectedBooleanState, dp.BooleanValue);

        // Outstation echoes CROB in Response (ServerToClient, FC = 0x81, SEQ = 8) at T + 16ms:
        // Must correlate RED transaction and NOT emit duplicate command event on ServerToClient response!
        byte[] appResponse =
        [
            0xC8, 0x81, 0x00, 0x00,
            12, 1, 0x17, 0x01, 0x02,
            controlCodeByte,
            0x03,
            0xF4, 0x01, 0x00, 0x00,
            0xE8, 0x03, 0x00, 0x00,
            0x00
        ];

        var respOutput = decoder.ProcessFrame(
            CreateFrame(41, BaseTime.AddMilliseconds(16), TrafficDirection.ServerToClient, BuildDnp3LinkFrame(1, 100, 0xC0, appResponse)),
            pair,
            TrafficDirection.ServerToClient);

        var tx = Assert.Single(respOutput.Transactions);
        Assert.Equal("8", tx.TransactionId);
        Assert.Equal(16.0, tx.DurationMs!.Value, precision: 5);
        Assert.False(tx.IsError);
        Assert.Empty(respOutput.CommandEvents);
    }

    private sealed class RecordingObjectGroupHandler(ushort group) : Analyzer.Core.Interfaces.IDnp3ObjectGroupHandler
    {
        public ushort Group { get; } = group;
        public List<(ushort Variation, byte[] ObjectData)> Invocations { get; } = [];

        public void ExtractObjects(
            DissectedFrame frame,
            DeviceEndpointPair pair,
            TrafficDirection direction,
            ushort variation,
            ReadOnlySpan<byte> objectData,
            ICollection<ExtractedDataPointRecord> dataPointsOut,
            ICollection<CapturedCommandEventRecord> commandsOut)
        {
            Invocations.Add((variation, objectData.ToArray()));
        }
    }
}

