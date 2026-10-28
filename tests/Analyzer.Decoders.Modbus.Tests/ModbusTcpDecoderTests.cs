using System.Net;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;
using Analyzer.Decoders.Modbus;

namespace Analyzer.Decoders.Modbus.Tests;

public class ModbusTcpDecoderTests
{
    private static readonly Guid SessionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid PairId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly IPAddress ClientIp = IPAddress.Parse("10.0.1.10");
    private static readonly IPAddress ServerIp = IPAddress.Parse("10.0.1.20");
    private static readonly DateTime BaseTime = new(2026, 10, 28, 12, 0, 0, DateTimeKind.Utc);

    private static DeviceEndpointPair CreatePair(int? unitId = 1) =>
        new(
            Id: PairId,
            SessionId: SessionId,
            Name: "RTAC_to_Relay",
            Protocol: ProtocolType.ModbusTcp,
            ClientIp: ClientIp,
            ServerIp: ServerIp,
            ClientProtocolAddressId: null,
            ServerProtocolAddressId: unitId);

    private static DissectedFrame CreateFrame(
        long frameNumber,
        DateTime timestampUtc,
        TrafficDirection direction,
        byte[] payload) =>
        new(
            FrameNumber: frameNumber,
            TimestampUtc: timestampUtc,
            SourceIp: direction == TrafficDirection.ClientToServer ? ClientIp : ServerIp,
            SourcePort: direction == TrafficDirection.ClientToServer ? 50100 : 502,
            DestIp: direction == TrafficDirection.ClientToServer ? ServerIp : ClientIp,
            DestPort: direction == TrafficDirection.ClientToServer ? 502 : 50100,
            ProtocolName: ProtocolType.ModbusTcp,
            RawApplicationPayload: payload);

    [Theory]
    // 1. Shorter than 8 bytes (7-byte MBAP + 1-byte FC)
    [InlineData(new byte[] { 0x00, 0x05, 0x00, 0x00, 0x00 }, TrafficDirection.ClientToServer, "5", 0)]
    // 2. Non-zero MBAP Protocol ID (0x0001 instead of 0x0000)
    [InlineData(new byte[] { 0x00, 0x07, 0x00, 0x01, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 }, TrafficDirection.ClientToServer, "7", 3)]
    // 3. MBAP Length (6) exceeds actual remaining bytes (only 4 bytes after length field)
    [InlineData(new byte[] { 0x00, 0x08, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00 }, TrafficDirection.ClientToServer, "8", 3)]
    // 4. Truncated Read Request PDU (FC 03 requires 5-byte PDU, only 3 bytes provided with MBAP length 4)
    [InlineData(new byte[] { 0x00, 0x09, 0x00, 0x00, 0x00, 0x04, 0x01, 0x03, 0x00, 0x00 }, TrafficDirection.ClientToServer, "9", 3)]
    // 5. Truncated Read Response PDU (FC 03 declares ByteCount = 4, but only 2 data bytes present)
    [InlineData(new byte[] { 0x00, 0x0A, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x04, 0x12, 0x34 }, TrafficDirection.ServerToClient, "10", 3)]
    // 6. Odd ByteCount in 16-bit Register Read Response (FC 03 with ByteCount = 3)
    [InlineData(new byte[] { 0x00, 0x0B, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x03, 0x12, 0x34, 0x56 }, TrafficDirection.ServerToClient, "11", 3)]
    // 7. Truncated Write Multiple Registers Request PDU (FC 16 with Quantity = 2, ByteCount = 4, but only 2 data bytes present)
    [InlineData(new byte[] { 0x00, 0x0C, 0x00, 0x00, 0x00, 0x09, 0x01, 0x10, 0x00, 0x00, 0x00, 0x02, 0x04, 0x12, 0x34 }, TrafficDirection.ClientToServer, "12", 16)]
    public void ProcessFrame_TruncatedOrInvalidMbapOrPduFraming_EmitsMalformedTransactionRecord(
        byte[] malformedPayload,
        TrafficDirection direction,
        string expectedTxId,
        short expectedFc)
    {
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine);
        var pair = CreatePair();
        var frame = CreateFrame(frameNumber: 42, timestampUtc: BaseTime, direction: direction, payload: malformedPayload);

        var output = decoder.ProcessFrame(frame, pair, direction);

        var tx = Assert.Single(output.Transactions);
        Assert.Equal(BaseTime, tx.Timestamp);
        Assert.Equal(SessionId, tx.SessionId);
        Assert.Equal(PairId, tx.DevicePairId);
        Assert.Equal(42, tx.FrameNumber);
        Assert.Equal(direction, tx.Direction);
        Assert.Equal(expectedTxId, tx.TransactionId);
        Assert.Equal(expectedFc, tx.FunctionCode);
        Assert.Null(tx.DurationMs);
        Assert.True(tx.IsError);
        Assert.Equal(TransactionErrorType.Malformed, tx.ErrorType);
        Assert.Equal(TransactionStatusCode.Malformed, tx.StatusCode);
        Assert.Empty(output.DataPoints);
        Assert.Empty(output.CommandEvents);
        Assert.Empty(output.UnmappedRegisters);
    }

    [Fact]
    public void ProcessFrame_ReadRequestAndResponseCorrelationByTxIdAndUnitId_CalculatesVirtualClockDurationAndIsolatesUnitIds()
    {
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine);
        var pair = CreatePair(unitId: null);

        // Request: TxId = 42 (0x002A), UnitId = 1, FC = 03, Start = 0, Quantity = 1
        var reqFrame = CreateFrame(
            frameNumber: 1,
            timestampUtc: BaseTime,
            direction: TrafficDirection.ClientToServer,
            payload: [0x00, 0x2A, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01]);

        var reqOutput = decoder.ProcessFrame(reqFrame, pair, TrafficDirection.ClientToServer);
        Assert.Empty(reqOutput.Transactions);

        // Unmatched response with same TxId (42) but different UnitId (2) at T + 15ms -> must not consume UnitId 1's request
        var wrongUnitRespFrame = CreateFrame(
            frameNumber: 2,
            timestampUtc: BaseTime.AddMilliseconds(15),
            direction: TrafficDirection.ServerToClient,
            payload: [0x00, 0x2A, 0x00, 0x00, 0x00, 0x05, 0x02, 0x03, 0x02, 0x00, 0x64]);

        var wrongUnitOutput = decoder.ProcessFrame(wrongUnitRespFrame, pair, TrafficDirection.ServerToClient);
        Assert.Empty(wrongUnitOutput.Transactions);

        // Matching response for TxId = 42, UnitId = 1 at T + 37.5ms
        var respFrame = CreateFrame(
            frameNumber: 3,
            timestampUtc: BaseTime.AddMilliseconds(37.5),
            direction: TrafficDirection.ServerToClient,
            payload: [0x00, 0x2A, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x00, 0x64]);

        var respOutput = decoder.ProcessFrame(respFrame, pair, TrafficDirection.ServerToClient);
        var tx = Assert.Single(respOutput.Transactions);
        Assert.Equal(BaseTime.AddMilliseconds(37.5), tx.Timestamp);
        Assert.Equal(SessionId, tx.SessionId);
        Assert.Equal(PairId, tx.DevicePairId);
        Assert.Equal(3, tx.FrameNumber);
        Assert.Equal(TrafficDirection.ServerToClient, tx.Direction);
        Assert.Equal("42", tx.TransactionId);
        Assert.Equal(3, tx.FunctionCode);
        Assert.Equal(37.5, tx.DurationMs!.Value, precision: 5);
        Assert.False(tx.IsError);
        Assert.Equal(TransactionErrorType.None, tx.ErrorType);
        Assert.Equal(TransactionStatusCode.Success, tx.StatusCode);
    }

    [Theory]
    [InlineData(0x81, 0x01, TransactionStatusCode.ModbusEx01)]
    [InlineData(0x82, 0x02, TransactionStatusCode.ModbusEx02)]
    [InlineData(0x83, 0x03, TransactionStatusCode.ModbusEx03)]
    [InlineData(0x84, 0x04, TransactionStatusCode.ModbusEx04)]
    [InlineData(0x83, 0x05, TransactionStatusCode.ModbusEx05)]
    [InlineData(0x83, 0x06, TransactionStatusCode.ModbusEx06)]
    [InlineData(0x83, 0x08, TransactionStatusCode.ModbusEx08)]
    [InlineData(0x83, 0x0A, TransactionStatusCode.ModbusEx0A)]
    [InlineData(0x83, 0x0B, TransactionStatusCode.ModbusEx0B)]
    [InlineData(0x83, 0xFF, TransactionStatusCode.ModbusExceptionUnknown)]
    public void ProcessFrame_ExceptionResponse_EmitsRedTransactionWithExceptionErrorTypeAndMappedStatusCode(
        byte exceptionFc,
        byte exceptionCode,
        TransactionStatusCode expectedStatus)
    {
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine([]);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine);
        var pair = CreatePair();

        byte requestFc = (byte)(exceptionFc & 0x7F);
        var reqFrame = CreateFrame(
            frameNumber: 10,
            timestampUtc: BaseTime,
            direction: TrafficDirection.ClientToServer,
            payload: [0x00, 0x15, 0x00, 0x00, 0x00, 0x06, 0x01, requestFc, 0x00, 0x10, 0x00, 0x02]);

        decoder.ProcessFrame(reqFrame, pair, TrafficDirection.ClientToServer);

        var respFrame = CreateFrame(
            frameNumber: 11,
            timestampUtc: BaseTime.AddMilliseconds(22.25),
            direction: TrafficDirection.ServerToClient,
            payload: [0x00, 0x15, 0x00, 0x00, 0x00, 0x03, 0x01, exceptionFc, exceptionCode]);

        var output = decoder.ProcessFrame(respFrame, pair, TrafficDirection.ServerToClient);

        var tx = Assert.Single(output.Transactions);
        Assert.Equal(BaseTime.AddMilliseconds(22.25), tx.Timestamp);
        Assert.Equal("21", tx.TransactionId);
        Assert.Equal(exceptionFc, tx.FunctionCode);
        Assert.Equal(22.25, tx.DurationMs!.Value, precision: 5);
        Assert.True(tx.IsError);
        Assert.Equal(TransactionErrorType.Exception, tx.ErrorType);
        Assert.Equal(expectedStatus, tx.StatusCode);
        Assert.Empty(output.DataPoints);
        Assert.Empty(output.UnmappedRegisters);
    }

    [Fact]
    public void ProcessFrame_Fc03AndFc04ReadRegisters_UnpacksAllNumericFormatsEmitsScaledDataPointsAndRespectsUnmappedToggle()
    {
        var tags = new[]
        {
            // Offset 0 (HR:40001): UINT16 -> 1380 * 0.1 + 0 = 138.0
            new TagDefinition(
                Id: Guid.Parse("30000000-0000-0000-0000-000000000001"),
                DevicePairId: PairId,
                TagName: "Bus_Volts_A",
                ProtocolAddress: ProtocolAddress.Parse("HR:40001"),
                DataType: TagDataType.UInt16,
                ScaleMultiplier: 0.1,
                ScaleOffset: 0.0,
                EngineeringUnits: "kV",
                Description: null),

            // Offset 1 (HR:40002): INT16 -> -250 * 0.1 + 0 = -25.0
            new TagDefinition(
                Id: Guid.Parse("30000000-0000-0000-0000-000000000002"),
                DevicePairId: PairId,
                TagName: "Reactive_MVAR",
                ProtocolAddress: ProtocolAddress.Parse("HR:40002"),
                DataType: TagDataType.Int16,
                ScaleMultiplier: 0.1,
                ScaleOffset: 0.0,
                EngineeringUnits: "MVAR",
                Description: null),

            // Offset 2..3 (HR:40003): INT32 -> 100,000 (0x000186A0) * 0.01 + 5.0 = 1005.0
            new TagDefinition(
                Id: Guid.Parse("30000000-0000-0000-0000-000000000003"),
                DevicePairId: PairId,
                TagName: "Energy_Wh",
                ProtocolAddress: ProtocolAddress.Parse("HR:40003"),
                DataType: TagDataType.Int32,
                ScaleMultiplier: 0.01,
                ScaleOffset: 5.0,
                EngineeringUnits: "kWh",
                Description: null),

            // Offset 4..5 (HR:40005): FLOAT32_BE -> 12.5f (0x41480000) * 2.0 + 1.0 = 26.0
            new TagDefinition(
                Id: Guid.Parse("30000000-0000-0000-0000-000000000004"),
                DevicePairId: PairId,
                TagName: "Current_A",
                ProtocolAddress: ProtocolAddress.Parse("HR:40005"),
                DataType: TagDataType.Float32Be,
                ScaleMultiplier: 2.0,
                ScaleOffset: 1.0,
                EngineeringUnits: "A",
                Description: null),

            // Offset 6..7 (HR:40007): FLOAT32_SWAPPED -> 50.25f (IEEE 754 BE is 0x42490000 -> word-swapped on wire: 0x0000, 0x4249)
            new TagDefinition(
                Id: Guid.Parse("30000000-0000-0000-0000-000000000005"),
                DevicePairId: PairId,
                TagName: "Freq_Hz",
                ProtocolAddress: ProtocolAddress.Parse("HR:40007"),
                DataType: TagDataType.Float32Swapped,
                ScaleMultiplier: 1.0,
                ScaleOffset: 0.0,
                EngineeringUnits: "Hz",
                Description: null),

            // Input Register Offset 10 (IR:30011): INT16 -> -40 * 0.5 + 10.0 = -10.0
            new TagDefinition(
                Id: Guid.Parse("30000000-0000-0000-0000-000000000006"),
                DevicePairId: PairId,
                TagName: "Ambient_Temp",
                ProtocolAddress: ProtocolAddress.Parse("IR:30011"),
                DataType: TagDataType.Int16,
                ScaleMultiplier: 0.5,
                ScaleOffset: 10.0,
                EngineeringUnits: "C",
                Description: null)
        };

        var pair = CreatePair(unitId: 1);

        // 1. Test FC 03 with storeUnmappedRegisters = true (9 registers requested starting at offset 0; offset 8 is unmapped 0xBEEF)
        var redEngine1 = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine1 = new TagResolutionEngine(tags);
        var decoderWithUnmapped = new ModbusTcpDecoder(redEngine1, tagEngine1, storeUnmappedRegisters: true);

        // FC 03 Request: TxId = 1, UnitId = 1, StartAddress = 0, Quantity = 9
        decoderWithUnmapped.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer,
                [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x09]),
            pair,
            TrafficDirection.ClientToServer);

        // FC 03 Response: 9 registers = 18 bytes (0x12)
        // Reg 0: 0x0564 (1380)
        // Reg 1: 0xFF06 (-250)
        // Reg 2..3: 0x0001, 0x86A0 (100000)
        // Reg 4..5: 0x4148, 0x0000 (12.5f BE)
        // Reg 6..7: 0x0000, 0x4249 (50.25f word-swapped)
        // Reg 8 (unmapped): 0xBEEF
        var fc03Resp = decoderWithUnmapped.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(20), TrafficDirection.ServerToClient,
            [
                0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x01, 0x03, 0x12,
                0x05, 0x64,
                0xFF, 0x06,
                0x00, 0x01, 0x86, 0xA0,
                0x41, 0x48, 0x00, 0x00,
                0x00, 0x00, 0x42, 0x49,
                0xBE, 0xEF
            ]),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Single(fc03Resp.Transactions);
        Assert.Equal(5, fc03Resp.DataPoints.Count);

        // UINT16
        Assert.Equal(1380.0, fc03Resp.DataPoints[0].UnscaledNumericValue);
        Assert.Equal(138.0, fc03Resp.DataPoints[0].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("0564", fc03Resp.DataPoints[0].RawHex);
        Assert.True(fc03Resp.DataPoints[0].IsValueChange);

        // INT16
        Assert.Equal(-250.0, fc03Resp.DataPoints[1].UnscaledNumericValue);
        Assert.Equal(-25.0, fc03Resp.DataPoints[1].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("FF06", fc03Resp.DataPoints[1].RawHex);

        // INT32
        Assert.Equal(100000.0, fc03Resp.DataPoints[2].UnscaledNumericValue);
        Assert.Equal(1005.0, fc03Resp.DataPoints[2].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("000186A0", fc03Resp.DataPoints[2].RawHex);

        // FLOAT32_BE
        Assert.Equal(12.5, fc03Resp.DataPoints[3].UnscaledNumericValue!.Value, precision: 5);
        Assert.Equal(26.0, fc03Resp.DataPoints[3].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("41480000", fc03Resp.DataPoints[3].RawHex);

        // FLOAT32_SWAPPED
        Assert.Equal(50.25, fc03Resp.DataPoints[4].UnscaledNumericValue!.Value, precision: 5);
        Assert.Equal(50.25, fc03Resp.DataPoints[4].ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("00004249", fc03Resp.DataPoints[4].RawHex);

        // Unmapped register at offset 8
        var unmappedHr = Assert.Single(fc03Resp.UnmappedRegisters);
        Assert.Equal(ModbusRegisterType.Holding, unmappedHr.RegisterType);
        Assert.Equal(8, unmappedHr.RegisterOffset);
        Assert.Equal(1, unmappedHr.UnitId);
        Assert.Equal("BEEF", unmappedHr.RawValueHex);

        // 2. Test FC 04 (Read Input Registers) with storeUnmappedRegisters = false (offset 10 mapped, offset 11 unmapped -> suppressed)
        var redEngine2 = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine2 = new TagResolutionEngine(tags);
        var decoderWithoutUnmapped = new ModbusTcpDecoder(redEngine2, tagEngine2, storeUnmappedRegisters: false);

        // FC 04 Request: TxId = 2, UnitId = 1, StartAddress = 10 (0x000A), Quantity = 2
        decoderWithoutUnmapped.ProcessFrame(
            CreateFrame(3, BaseTime.AddMilliseconds(100), TrafficDirection.ClientToServer,
                [0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x04, 0x00, 0x0A, 0x00, 0x02]),
            pair,
            TrafficDirection.ClientToServer);

        // FC 04 Response: Reg 10 = -40 (0xFFD8), Reg 11 (unmapped) = 0xCAFE
        var fc04Resp = decoderWithoutUnmapped.ProcessFrame(
            CreateFrame(4, BaseTime.AddMilliseconds(115), TrafficDirection.ServerToClient,
                [0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x01, 0x04, 0x04, 0xFF, 0xD8, 0xCA, 0xFE]),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Single(fc04Resp.Transactions);
        var irPoint = Assert.Single(fc04Resp.DataPoints);
        Assert.Equal(-40.0, irPoint.UnscaledNumericValue);
        Assert.Equal(-10.0, irPoint.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("FFD8", irPoint.RawHex);
        Assert.Empty(fc04Resp.UnmappedRegisters);
    }

    [Fact]
    public void ProcessFrame_Fc01ReadCoilsAndFc02ReadDiscreteInputs_UnpacksLsbFirstBitsIgnoresPaddingAndEmitsUnmappedWhenEnabled()
    {
        var coilTagId = Guid.Parse("40000000-0000-0000-0000-000000000001");
        var diTag0Id = Guid.Parse("40000000-0000-0000-0000-000000000002");
        var diTag2Id = Guid.Parse("40000000-0000-0000-0000-000000000003");

        var tags = new[]
        {
            new TagDefinition(
                Id: coilTagId,
                DevicePairId: PairId,
                TagName: "Breaker_52A",
                ProtocolAddress: ProtocolAddress.Parse("COIL:00005"),
                DataType: TagDataType.Bool,
                ScaleMultiplier: 1.0,
                ScaleOffset: 0.0,
                EngineeringUnits: null,
                Description: "Breaker Status"),

            new TagDefinition(
                Id: diTag0Id,
                DevicePairId: PairId,
                TagName: "Isolator_Closed",
                ProtocolAddress: ProtocolAddress.Parse("DI:10001"),
                DataType: TagDataType.Bool,
                ScaleMultiplier: 1.0,
                ScaleOffset: 0.0,
                EngineeringUnits: null,
                Description: null),

            new TagDefinition(
                Id: diTag2Id,
                DevicePairId: PairId,
                TagName: "Earth_Switch_On",
                ProtocolAddress: ProtocolAddress.Parse("DI:10003"),
                DataType: TagDataType.Bool,
                ScaleMultiplier: 1.0,
                ScaleOffset: 0.0,
                EngineeringUnits: null,
                Description: null)
        };

        var pair = CreatePair(unitId: 1);
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine, storeUnmappedRegisters: true);

        // 1. FC 01 (Read Coils): StartAddress = 4, Quantity = 3 (offsets 4, 5, 6; bits 3..7 in byte are padding)
        decoder.ProcessFrame(
            CreateFrame(1, BaseTime, TrafficDirection.ClientToServer,
                [0x00, 0x0A, 0x00, 0x00, 0x00, 0x06, 0x01, 0x01, 0x00, 0x04, 0x00, 0x03]),
            pair,
            TrafficDirection.ClientToServer);

        // FC 01 Response: ByteCount = 1, Value = 0b1111_0010 (0xF2)
        // Bit 0 (offset 4, unmapped) = 0 ("00")
        // Bit 1 (offset 5, mapped COIL:00005) = 1 (true, "01")
        // Bit 2 (offset 6, unmapped) = 0 ("00")
        // Bits 3..7 are 1s in 0xF2, but beyond Quantity=3 -> must be ignored!
        var fc01Resp = decoder.ProcessFrame(
            CreateFrame(2, BaseTime.AddMilliseconds(10), TrafficDirection.ServerToClient,
                [0x00, 0x0A, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0xF2]),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Single(fc01Resp.Transactions);
        var coilDp = Assert.Single(fc01Resp.DataPoints);
        Assert.Equal(coilTagId, coilDp.TagId);
        Assert.True(coilDp.BooleanValue);
        Assert.Null(coilDp.UnscaledNumericValue);
        Assert.Null(coilDp.ScaledNumericValue);
        Assert.Equal("01", coilDp.RawHex);
        Assert.True(coilDp.IsValueChange);

        Assert.Equal(2, fc01Resp.UnmappedRegisters.Count);
        Assert.Equal(ModbusRegisterType.Coil, fc01Resp.UnmappedRegisters[0].RegisterType);
        Assert.Equal(4, fc01Resp.UnmappedRegisters[0].RegisterOffset);
        Assert.Equal("00", fc01Resp.UnmappedRegisters[0].RawValueHex);
        Assert.Equal(ModbusRegisterType.Coil, fc01Resp.UnmappedRegisters[1].RegisterType);
        Assert.Equal(6, fc01Resp.UnmappedRegisters[1].RegisterOffset);
        Assert.Equal("00", fc01Resp.UnmappedRegisters[1].RawValueHex);

        // 2. FC 02 (Read Discrete Inputs): StartAddress = 0, Quantity = 3 (offsets 0, 1, 2)
        decoder.ProcessFrame(
            CreateFrame(3, BaseTime.AddMilliseconds(50), TrafficDirection.ClientToServer,
                [0x00, 0x0B, 0x00, 0x00, 0x00, 0x06, 0x01, 0x02, 0x00, 0x00, 0x00, 0x03]),
            pair,
            TrafficDirection.ClientToServer);

        // FC 02 Response: ByteCount = 1, Value = 0b0000_0011 (0x03)
        // Bit 0 (offset 0, mapped DI:10001) = true ("01")
        // Bit 1 (offset 1, unmapped) = true ("01")
        // Bit 2 (offset 2, mapped DI:10003) = false ("00")
        var fc02Resp = decoder.ProcessFrame(
            CreateFrame(4, BaseTime.AddMilliseconds(65), TrafficDirection.ServerToClient,
                [0x00, 0x0B, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x01, 0x03]),
            pair,
            TrafficDirection.ServerToClient);

        Assert.Single(fc02Resp.Transactions);
        Assert.Equal(2, fc02Resp.DataPoints.Count);
        Assert.Equal(diTag0Id, fc02Resp.DataPoints[0].TagId);
        Assert.True(fc02Resp.DataPoints[0].BooleanValue);
        Assert.Equal("01", fc02Resp.DataPoints[0].RawHex);

        Assert.Equal(diTag2Id, fc02Resp.DataPoints[1].TagId);
        Assert.False(fc02Resp.DataPoints[1].BooleanValue);
        Assert.Equal("00", fc02Resp.DataPoints[1].RawHex);

        var unmappedDi = Assert.Single(fc02Resp.UnmappedRegisters);
        Assert.Equal(ModbusRegisterType.DiscreteInput, unmappedDi.RegisterType);
        Assert.Equal(1, unmappedDi.RegisterOffset);
        Assert.Equal("01", unmappedDi.RawValueHex);
    }

    [Fact]
    public void ProcessFrame_Fc05WriteSingleCoilAndFc06WriteSingleRegister_EmitsCommandEventsUpdatesMappedTagsAndCorrelatesEchoAndExceptionResponses()
    {
        var coilTagId = Guid.Parse("50000000-0000-0000-0000-000000000001");
        var hrTagId = Guid.Parse("50000000-0000-0000-0000-000000000002");

        var tags = new[]
        {
            new TagDefinition(
                Id: coilTagId,
                DevicePairId: PairId,
                TagName: "Breaker_52A_Cmd",
                ProtocolAddress: ProtocolAddress.Parse("COIL:00005"),
                DataType: TagDataType.Bool,
                ScaleMultiplier: 1.0,
                ScaleOffset: 0.0,
                EngineeringUnits: null,
                Description: "Breaker Close Coil"),

            new TagDefinition(
                Id: hrTagId,
                DevicePairId: PairId,
                TagName: "Setpoint_kV",
                ProtocolAddress: ProtocolAddress.Parse("HR:40005"),
                DataType: TagDataType.UInt16,
                ScaleMultiplier: 0.1,
                ScaleOffset: 0.0,
                EngineeringUnits: "kV",
                Description: "Voltage Setpoint")
        };

        var pair = CreatePair(unitId: 1);
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine, storeUnmappedRegisters: false);

        // 1. FC 05 Write Single Coil (ClientToServer): TxId = 100 (0x0064), UnitId = 1, Address = 5 (0x0005), Value = 0xFF00 (ON)
        byte[] fc05ReqBytes = [0x00, 0x64, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x05, 0xFF, 0x00];
        var fc05ReqOut = decoder.ProcessFrame(
            CreateFrame(10, BaseTime, TrafficDirection.ClientToServer, fc05ReqBytes),
            pair,
            TrafficDirection.ClientToServer);

        Assert.Empty(fc05ReqOut.Transactions);
        var fc05Cmd = Assert.Single(fc05ReqOut.CommandEvents);
        Assert.Equal(BaseTime, fc05Cmd.Timestamp);
        Assert.Equal(SessionId, fc05Cmd.SessionId);
        Assert.Equal(PairId, fc05Cmd.DevicePairId);
        Assert.Equal(10, fc05Cmd.FrameNumber);
        Assert.Equal(TrafficDirection.ClientToServer, fc05Cmd.Direction);
        Assert.Equal(ProtocolType.ModbusTcp, fc05Cmd.Protocol);
        Assert.Equal(5, fc05Cmd.FunctionCode);
        Assert.Equal(CommandType.ModbusWriteSingleCoil, fc05Cmd.CommandType);
        Assert.Equal(ProtocolAddress.Parse("COIL:00005"), fc05Cmd.TargetAddress);
        Assert.Null(fc05Cmd.ControlAction);
        Assert.Equal((short)1, fc05Cmd.CommandCount);
        Assert.Null(fc05Cmd.PulseOnMs);
        Assert.Null(fc05Cmd.PulseOffMs);
        Assert.Equal(1.0, fc05Cmd.UnscaledCommandValue);
        Assert.Equal(fc05ReqBytes, fc05Cmd.RawPduBytes);

        var fc05Dp = Assert.Single(fc05ReqOut.DataPoints);
        Assert.Equal(coilTagId, fc05Dp.TagId);
        Assert.Equal(TrafficDirection.ClientToServer, fc05Dp.Direction);
        Assert.True(fc05Dp.BooleanValue);
        Assert.Equal("01", fc05Dp.RawHex);
        Assert.True(fc05Dp.IsValueChange);

        // FC 05 Echo Response (ServerToClient) at T + 12.5ms
        var fc05RespOut = decoder.ProcessFrame(
            CreateFrame(11, BaseTime.AddMilliseconds(12.5), TrafficDirection.ServerToClient, fc05ReqBytes),
            pair,
            TrafficDirection.ServerToClient);

        var fc05Tx = Assert.Single(fc05RespOut.Transactions);
        Assert.Equal("100", fc05Tx.TransactionId);
        Assert.Equal(5, fc05Tx.FunctionCode);
        Assert.Equal(12.5, fc05Tx.DurationMs!.Value, precision: 5);
        Assert.False(fc05Tx.IsError);
        Assert.Equal(TransactionStatusCode.Success, fc05Tx.StatusCode);
        Assert.Empty(fc05RespOut.CommandEvents);
        Assert.Empty(fc05RespOut.DataPoints);

        // 2. FC 06 Write Single Register (ClientToServer): TxId = 101 (0x0065), UnitId = 1, Address = 4 (HR:40005), Value = 1320 (0x0528 -> 132.0 kV)
        byte[] fc06ReqBytes = [0x00, 0x65, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x04, 0x05, 0x28];
        var fc06ReqOut = decoder.ProcessFrame(
            CreateFrame(12, BaseTime.AddMilliseconds(50), TrafficDirection.ClientToServer, fc06ReqBytes),
            pair,
            TrafficDirection.ClientToServer);

        var fc06Cmd = Assert.Single(fc06ReqOut.CommandEvents);
        Assert.Equal(6, fc06Cmd.FunctionCode);
        Assert.Equal(CommandType.ModbusWriteSingleReg, fc06Cmd.CommandType);
        Assert.Equal(ProtocolAddress.Parse("HR:40005"), fc06Cmd.TargetAddress);
        Assert.Equal((short)1, fc06Cmd.CommandCount);
        Assert.Equal(1320.0, fc06Cmd.UnscaledCommandValue);
        Assert.Equal(fc06ReqBytes, fc06Cmd.RawPduBytes);

        var fc06Dp = Assert.Single(fc06ReqOut.DataPoints);
        Assert.Equal(hrTagId, fc06Dp.TagId);
        Assert.Equal(TrafficDirection.ClientToServer, fc06Dp.Direction);
        Assert.Equal(1320.0, fc06Dp.UnscaledNumericValue);
        Assert.Equal(132.0, fc06Dp.ScaledNumericValue!.Value, precision: 5);
        Assert.Equal("0528", fc06Dp.RawHex);

        // FC 06 Exception Response (ServerToClient, 0x86 with Illegal Data Value 0x03) at T + 68ms
        var fc06ExOut = decoder.ProcessFrame(
            CreateFrame(13, BaseTime.AddMilliseconds(68), TrafficDirection.ServerToClient,
                [0x00, 0x65, 0x00, 0x00, 0x00, 0x03, 0x01, 0x86, 0x03]),
            pair,
            TrafficDirection.ServerToClient);

        var fc06Tx = Assert.Single(fc06ExOut.Transactions);
        Assert.Equal("101", fc06Tx.TransactionId);
        Assert.Equal(0x86, fc06Tx.FunctionCode);
        Assert.Equal(18.0, fc06Tx.DurationMs!.Value, precision: 5);
        Assert.True(fc06Tx.IsError);
        Assert.Equal(TransactionErrorType.Exception, fc06Tx.ErrorType);
        Assert.Equal(TransactionStatusCode.ModbusEx03, fc06Tx.StatusCode);
    }

    [Fact]
    public void ProcessFrame_Fc15WriteMultiCoilsAndFc16WriteMultiRegisters_EmitsCommandEventsUpdatesMappedTagsAndCorrelatesResponses()
    {
        var coil10Id = Guid.Parse("60000000-0000-0000-0000-000000000001");
        var coil12Id = Guid.Parse("60000000-0000-0000-0000-000000000002");
        var floatTagId = Guid.Parse("60000000-0000-0000-0000-000000000003");
        var reg20Id = Guid.Parse("60000000-0000-0000-0000-000000000004");
        var reg21Id = Guid.Parse("60000000-0000-0000-0000-000000000005");

        var tags = new[]
        {
            new TagDefinition(coil10Id, PairId, "Coil_10", ProtocolAddress.Parse("COIL:00010"), TagDataType.Bool, 1.0, 0.0, null, null),
            new TagDefinition(coil12Id, PairId, "Coil_12", ProtocolAddress.Parse("COIL:00012"), TagDataType.Bool, 1.0, 0.0, null, null),
            new TagDefinition(floatTagId, PairId, "Target_MW", ProtocolAddress.Parse("HR:40011"), TagDataType.Float32Be, 2.0, 0.0, "MW", null),
            new TagDefinition(reg20Id, PairId, "Limit_Lo", ProtocolAddress.Parse("HR:40021"), TagDataType.UInt16, 1.0, 0.0, null, null),
            new TagDefinition(reg21Id, PairId, "Limit_Hi", ProtocolAddress.Parse("HR:40022"), TagDataType.UInt16, 1.0, 0.0, null, null)
        };

        var pair = CreatePair(unitId: 1);
        var redEngine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var tagEngine = new TagResolutionEngine(tags);
        var decoder = new ModbusTcpDecoder(redEngine, tagEngine, storeUnmappedRegisters: true);

        // 1. FC 15 (0x0F) Write Multiple Coils: TxId = 200 (0x00C8), StartAddress = 10 (0x000A), Quantity = 3 (0x0003), ByteCount = 1, Value = 0b0000_0101 (0x05)
        // Coil 10 = true, Coil 11 (unmapped) = false, Coil 12 = true
        byte[] fc15ReqBytes = [0x00, 0xC8, 0x00, 0x00, 0x00, 0x08, 0x01, 0x0F, 0x00, 0x0A, 0x00, 0x03, 0x01, 0x05];
        var fc15ReqOut = decoder.ProcessFrame(
            CreateFrame(20, BaseTime, TrafficDirection.ClientToServer, fc15ReqBytes),
            pair,
            TrafficDirection.ClientToServer);

        var fc15Cmd = Assert.Single(fc15ReqOut.CommandEvents);
        Assert.Equal(15, fc15Cmd.FunctionCode);
        Assert.Equal(CommandType.ModbusWriteMultiCoils, fc15Cmd.CommandType);
        Assert.Equal(ProtocolAddress.Parse("COIL:00010"), fc15Cmd.TargetAddress);
        Assert.Equal((short)3, fc15Cmd.CommandCount);
        Assert.Null(fc15Cmd.UnscaledCommandValue);
        Assert.Equal(fc15ReqBytes, fc15Cmd.RawPduBytes);

        Assert.Equal(2, fc15ReqOut.DataPoints.Count);
        Assert.Equal(coil10Id, fc15ReqOut.DataPoints[0].TagId);
        Assert.True(fc15ReqOut.DataPoints[0].BooleanValue);
        Assert.Equal(coil12Id, fc15ReqOut.DataPoints[1].TagId);
        Assert.True(fc15ReqOut.DataPoints[1].BooleanValue);

        var unmappedCoil11 = Assert.Single(fc15ReqOut.UnmappedRegisters);
        Assert.Equal(ModbusRegisterType.Coil, unmappedCoil11.RegisterType);
        Assert.Equal(11, unmappedCoil11.RegisterOffset);
        Assert.Equal("00", unmappedCoil11.RawValueHex);

        // FC 15 Response (ServerToClient): echoes StartAddress = 10, Quantity = 3
        var fc15RespOut = decoder.ProcessFrame(
            CreateFrame(21, BaseTime.AddMilliseconds(14), TrafficDirection.ServerToClient,
                [0x00, 0xC8, 0x00, 0x00, 0x00, 0x06, 0x01, 0x0F, 0x00, 0x0A, 0x00, 0x03]),
            pair,
            TrafficDirection.ServerToClient);

        var fc15Tx = Assert.Single(fc15RespOut.Transactions);
        Assert.Equal("200", fc15Tx.TransactionId);
        Assert.Equal(15, fc15Tx.FunctionCode);
        Assert.Equal(14.0, fc15Tx.DurationMs!.Value, precision: 5);
        Assert.False(fc15Tx.IsError);

        // 2. FC 16 (0x10) Write Multiple Registers for a single 32-bit float tag (Start = 10 -> HR:40011, Quantity = 2, Value = 12.5f = 0x41480000)
        byte[] fc16FloatReqBytes =
        [
            0x00, 0xC9, 0x00, 0x00, 0x00, 0x0B, 0x01,
            0x10, 0x00, 0x0A, 0x00, 0x02, 0x04, 0x41, 0x48, 0x00, 0x00
        ];
        var fc16FloatOut = decoder.ProcessFrame(
            CreateFrame(22, BaseTime.AddMilliseconds(30), TrafficDirection.ClientToServer, fc16FloatReqBytes),
            pair,
            TrafficDirection.ClientToServer);

        var fc16FloatCmd = Assert.Single(fc16FloatOut.CommandEvents);
        Assert.Equal(16, fc16FloatCmd.FunctionCode);
        Assert.Equal(CommandType.ModbusWriteMultiRegs, fc16FloatCmd.CommandType);
        Assert.Equal(ProtocolAddress.Parse("HR:40011"), fc16FloatCmd.TargetAddress);
        Assert.Equal((short)2, fc16FloatCmd.CommandCount);
        Assert.Equal(12.5, fc16FloatCmd.UnscaledCommandValue!.Value, precision: 5);
        Assert.Equal(fc16FloatReqBytes, fc16FloatCmd.RawPduBytes);

        var fc16FloatDp = Assert.Single(fc16FloatOut.DataPoints);
        Assert.Equal(floatTagId, fc16FloatDp.TagId);
        Assert.Equal(12.5, fc16FloatDp.UnscaledNumericValue!.Value, precision: 5);
        Assert.Equal(25.0, fc16FloatDp.ScaledNumericValue!.Value, precision: 5);

        // 3. FC 16 (0x10) Write Multiple Registers for two 16-bit tags (Start = 20 -> HR:40021..40022, Quantity = 2, Values = 100, 200)
        byte[] fc16MultiReqBytes =
        [
            0x00, 0xCA, 0x00, 0x00, 0x00, 0x0B, 0x01,
            0x10, 0x00, 0x14, 0x00, 0x02, 0x04, 0x00, 0x64, 0x00, 0xC8
        ];
        var fc16MultiOut = decoder.ProcessFrame(
            CreateFrame(23, BaseTime.AddMilliseconds(50), TrafficDirection.ClientToServer, fc16MultiReqBytes),
            pair,
            TrafficDirection.ClientToServer);

        var fc16MultiCmd = Assert.Single(fc16MultiOut.CommandEvents);
        Assert.Equal(CommandType.ModbusWriteMultiRegs, fc16MultiCmd.CommandType);
        Assert.Equal(ProtocolAddress.Parse("HR:40021"), fc16MultiCmd.TargetAddress);
        Assert.Equal((short)2, fc16MultiCmd.CommandCount);
        Assert.Null(fc16MultiCmd.UnscaledCommandValue);
        Assert.Equal(2, fc16MultiOut.DataPoints.Count);
        Assert.Equal(100.0, fc16MultiOut.DataPoints[0].UnscaledNumericValue);
        Assert.Equal(200.0, fc16MultiOut.DataPoints[1].UnscaledNumericValue);

        // FC 16 Response (ServerToClient) for TxId = 202 (0x00CA) at T + 75ms (Duration = 25ms)
        var fc16RespOut = decoder.ProcessFrame(
            CreateFrame(24, BaseTime.AddMilliseconds(75), TrafficDirection.ServerToClient,
                [0x00, 0xCA, 0x00, 0x00, 0x00, 0x06, 0x01, 0x10, 0x00, 0x14, 0x00, 0x02]),
            pair,
            TrafficDirection.ServerToClient);

        var fc16Tx = Assert.Single(fc16RespOut.Transactions);
        Assert.Equal("202", fc16Tx.TransactionId);
        Assert.Equal(16, fc16Tx.FunctionCode);
        Assert.Equal(25.0, fc16Tx.DurationMs!.Value, precision: 5);
    }
}
