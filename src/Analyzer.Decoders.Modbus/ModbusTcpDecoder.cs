using System.Buffers.Binary;
using System.Globalization;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Modbus;

public enum ModbusFunctionCode : byte
{
    ReadCoils = 0x01,
    ReadDiscreteInputs = 0x02,
    ReadHoldingRegisters = 0x03,
    ReadInputRegisters = 0x04,
    WriteSingleCoil = 0x05,
    WriteSingleRegister = 0x06,
    WriteMultipleCoils = 0x0F,
    WriteMultipleRegisters = 0x10
}

public class ModbusTcpDecoder : IProtocolDecoder
{
    private const byte ExceptionFlag = 0x80;
    private const byte FunctionCodeMask = 0x7F;

    private readonly record struct ModbusRequestContext(
        byte UnitId,
        ModbusFunctionCode FunctionCode,
        ushort StartAddress,
        ushort Quantity);

    private readonly record struct FrameExtractionContext(
        DissectedFrame Frame,
        DeviceEndpointPair Pair,
        TrafficDirection Direction,
        byte UnitId,
        ModbusRegisterType RegisterType);

    private readonly VirtualClockRedEngine _redEngine;
    private readonly TagResolutionEngine _tagEngine;
    private readonly bool _storeUnmappedRegisters;

    public ModbusTcpDecoder(
        VirtualClockRedEngine redEngine,
        TagResolutionEngine tagEngine,
        bool storeUnmappedRegisters = false)
    {
        ArgumentNullException.ThrowIfNull(redEngine);
        ArgumentNullException.ThrowIfNull(tagEngine);
        _redEngine = redEngine;
        _tagEngine = tagEngine;
        _storeUnmappedRegisters = storeUnmappedRegisters;
    }

    public ProtocolType Protocol => ProtocolType.ModbusTcp;

    public ProtocolDecodeOutput ProcessFrame(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction)
    {
        ArgumentNullException.ThrowIfNull(frame);
        ArgumentNullException.ThrowIfNull(pair);

        ReadOnlySpan<byte> payload = frame.RawApplicationPayload;

        string transactionId = payload.Length >= 2
            ? BinaryPrimitives.ReadUInt16BigEndian(payload[..2]).ToString(CultureInfo.InvariantCulture)
            : "0";
        short functionCode = payload.Length >= 8 ? payload[7] : (short)0;

        if (!TryValidateMbapAndPdu(payload, direction))
        {
            var malformedTx = new ProtocolTransactionRecord(
                Timestamp: frame.TimestampUtc,
                SessionId: pair.SessionId,
                DevicePairId: pair.Id,
                FrameNumber: frame.FrameNumber,
                Direction: direction,
                TransactionId: transactionId,
                FunctionCode: functionCode,
                DurationMs: null,
                IsError: true,
                ErrorType: TransactionErrorType.Malformed,
                StatusCode: TransactionStatusCode.Malformed);

            return new ProtocolDecodeOutput([malformedTx], [], [], []);
        }

        ushort mbapLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
        byte unitId = payload[6];
        ReadOnlySpan<byte> pdu = payload.Slice(7, mbapLength - 1);
        byte rawFc = pdu[0];
        bool isException = (rawFc & ExceptionFlag) != 0;
        byte baseFcByte = (byte)(rawFc & FunctionCodeMask);
        string correlationKey = $"{unitId}:{transactionId}:{baseFcByte}";

        var transactions = new List<ProtocolTransactionRecord>();
        var dataPoints = new List<ExtractedDataPointRecord>();
        var commandEvents = new List<CapturedCommandEventRecord>();
        var unmappedRegisters = new List<ModbusUnmappedRecord>();

        if (direction == TrafficDirection.ClientToServer)
        {
            if (!isException && TryParseReadFunctionCode(rawFc, out var readFc))
            {
                ushort startAddress = BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(1, 2));
                ushort quantity = BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(3, 2));
                var context = new ModbusRequestContext(unitId, readFc, startAddress, quantity);

                _redEngine.RegisterRequest(
                    sessionId: pair.SessionId,
                    devicePairId: pair.Id,
                    frameNumber: frame.FrameNumber,
                    timestampUtc: frame.TimestampUtc,
                    transactionId: transactionId,
                    functionCode: rawFc,
                    requestContext: context,
                    correlationKey: correlationKey);
            }
            else if (!isException && TryParseWriteFunctionCode(rawFc, out var writeFc))
            {
                var extractionContext = new FrameExtractionContext(
                    frame,
                    pair,
                    direction,
                    unitId,
                    ToRegisterType(writeFc));

                ProcessWriteRequest(
                    extractionContext,
                    transactionId,
                    correlationKey,
                    writeFc,
                    pdu,
                    dataPoints,
                    commandEvents,
                    unmappedRegisters);
            }
        }
        else
        {
            if (isException)
            {
                var statusCode = MapExceptionStatusCode(pdu[1]);
                if (_redEngine.TryCompleteResponse<ModbusRequestContext>(
                        devicePairId: pair.Id,
                        transactionId: transactionId,
                        responseFrameNumber: frame.FrameNumber,
                        responseTimestampUtc: frame.TimestampUtc,
                        responseFunctionCode: rawFc,
                        isException: true,
                        statusCode: statusCode,
                        out var exTx,
                        out _,
                        correlationKey: correlationKey))
                {
                    transactions.Add(exTx);
                }
            }
            else if (TryParseReadFunctionCode(rawFc, out var readFc))
            {
                if (_redEngine.TryCompleteResponse<ModbusRequestContext>(
                        devicePairId: pair.Id,
                        transactionId: transactionId,
                        responseFrameNumber: frame.FrameNumber,
                        responseTimestampUtc: frame.TimestampUtc,
                        responseFunctionCode: rawFc,
                        isException: false,
                        statusCode: TransactionStatusCode.Success,
                        out var okTx,
                        out var reqContext,
                        correlationKey: correlationKey))
                {
                    transactions.Add(okTx);

                    int byteCount = pdu[1];
                    ReadOnlySpan<byte> dataBytes = pdu.Slice(2, byteCount);
                    var extractionContext = new FrameExtractionContext(
                        frame,
                        pair,
                        direction,
                        unitId,
                        ToRegisterType(readFc));

                    if (IsBitFunction(readFc))
                    {
                        ExtractBits(
                            extractionContext,
                            reqContext.StartAddress,
                            reqContext.Quantity,
                            dataBytes,
                            dataPoints,
                            unmappedRegisters);
                    }
                    else
                    {
                        ExtractRegisters(
                            extractionContext,
                            reqContext.StartAddress,
                            reqContext.Quantity,
                            dataBytes,
                            dataPoints,
                            unmappedRegisters);
                    }
                }
            }
            else if (TryParseWriteFunctionCode(rawFc, out _))
            {
                if (_redEngine.TryCompleteResponse<ModbusRequestContext>(
                        devicePairId: pair.Id,
                        transactionId: transactionId,
                        responseFrameNumber: frame.FrameNumber,
                        responseTimestampUtc: frame.TimestampUtc,
                        responseFunctionCode: rawFc,
                        isException: false,
                        statusCode: TransactionStatusCode.Success,
                        out var okTx,
                        out _,
                        correlationKey: correlationKey))
                {
                    transactions.Add(okTx);
                }
            }
        }

        return new ProtocolDecodeOutput(transactions, dataPoints, commandEvents, unmappedRegisters);
    }

    public IReadOnlyList<ProtocolTransactionRecord> FlushExpiredTimeouts(DateTime currentVirtualTime, bool isEndOfFile) =>
        _redEngine.FlushExpiredTimeouts(currentVirtualTime, isEndOfFile);

    private void ProcessWriteRequest(
        FrameExtractionContext extractionContext,
        string transactionId,
        string correlationKey,
        ModbusFunctionCode writeFc,
        ReadOnlySpan<byte> pdu,
        List<ExtractedDataPointRecord> dataPoints,
        List<CapturedCommandEventRecord> commandEvents,
        List<ModbusUnmappedRecord> unmappedRegisters)
    {
        ushort startAddress = BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(1, 2));
        bool isSingleWrite = writeFc is ModbusFunctionCode.WriteSingleCoil or ModbusFunctionCode.WriteSingleRegister;
        ushort quantity = isSingleWrite ? (ushort)1 : BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(3, 2));

        var reqContext = new ModbusRequestContext(extractionContext.UnitId, writeFc, startAddress, quantity);
        _redEngine.RegisterRequest(
            sessionId: extractionContext.Pair.SessionId,
            devicePairId: extractionContext.Pair.Id,
            frameNumber: extractionContext.Frame.FrameNumber,
            timestampUtc: extractionContext.Frame.TimestampUtc,
            transactionId: transactionId,
            functionCode: (byte)writeFc,
            requestContext: reqContext,
            correlationKey: correlationKey);

        bool hasTag = TryFindMappedTag(extractionContext.Pair.Id, extractionContext.RegisterType, startAddress, out var tag);
        ProtocolAddress targetAddress = hasTag
            ? tag.ProtocolAddress
            : FormatDefaultAddress(extractionContext.RegisterType, startAddress);

        double? unscaledCommandValue;
        CommandType commandType;

        if (writeFc == ModbusFunctionCode.WriteSingleCoil)
        {
            commandType = CommandType.ModbusWriteSingleCoil;
            ReadOnlySpan<byte> valueBytes = pdu.Slice(3, 2);
            bool coilOn = BinaryPrimitives.ReadUInt16BigEndian(valueBytes) != 0;
            unscaledCommandValue = coilOn ? 1.0 : 0.0;
            Span<byte> bitByte = stackalloc byte[1] { coilOn ? (byte)1 : (byte)0 };
            ExtractBits(extractionContext, startAddress, requestedQuantity: 1, bitByte, dataPoints, unmappedRegisters);
        }
        else if (writeFc == ModbusFunctionCode.WriteSingleRegister)
        {
            commandType = CommandType.ModbusWriteSingleReg;
            ReadOnlySpan<byte> valueBytes = pdu.Slice(3, 2);
            unscaledCommandValue = ReadSingleRegisterCommandValue(valueBytes, hasTag, tag);
            ExtractRegisters(extractionContext, startAddress, requestedQuantity: 1, valueBytes, dataPoints, unmappedRegisters);
        }
        else if (writeFc == ModbusFunctionCode.WriteMultipleCoils)
        {
            commandType = CommandType.ModbusWriteMultiCoils;
            int byteCount = pdu[5];
            ReadOnlySpan<byte> dataBytes = pdu.Slice(6, byteCount);
            ExtractBits(extractionContext, startAddress, quantity, dataBytes, dataPoints, unmappedRegisters);
            unscaledCommandValue = quantity == 1
                ? ((dataBytes[0] & 0x01) != 0 ? 1.0 : 0.0)
                : null;
        }
        else
        {
            commandType = CommandType.ModbusWriteMultiRegs;
            int byteCount = pdu[5];
            ReadOnlySpan<byte> dataBytes = pdu.Slice(6, byteCount);
            int pointsBefore = dataPoints.Count;
            ExtractRegisters(extractionContext, startAddress, quantity, dataBytes, dataPoints, unmappedRegisters);

            if (quantity == 1)
            {
                unscaledCommandValue = ReadSingleRegisterCommandValue(dataBytes[..2], hasTag, tag);
            }
            else if (quantity == 2 &&
                     hasTag &&
                     tag.DataType is TagDataType.Int32 or TagDataType.Float32Be or TagDataType.Float32Swapped &&
                     dataPoints.Count == pointsBefore + 1)
            {
                unscaledCommandValue = dataPoints[pointsBefore].UnscaledNumericValue;
            }
            else
            {
                unscaledCommandValue = null;
            }
        }

        commandEvents.Add(new CapturedCommandEventRecord(
            Timestamp: extractionContext.Frame.TimestampUtc,
            SessionId: extractionContext.Pair.SessionId,
            DevicePairId: extractionContext.Pair.Id,
            FrameNumber: extractionContext.Frame.FrameNumber,
            Direction: extractionContext.Direction,
            Protocol: ProtocolType.ModbusTcp,
            FunctionCode: (byte)writeFc,
            CommandType: commandType,
            TargetAddress: targetAddress,
            ControlAction: null,
            CommandCount: (short)quantity,
            PulseOnMs: null,
            PulseOffMs: null,
            UnscaledCommandValue: unscaledCommandValue,
            RawPduBytes: extractionContext.Frame.RawApplicationPayload.ToArray()));
    }

    private static double ReadSingleRegisterCommandValue(ReadOnlySpan<byte> twoBytes, bool hasTag, TagDefinition? tag) =>
        hasTag && tag is not null && tag.DataType == TagDataType.Int16
            ? BinaryPrimitives.ReadInt16BigEndian(twoBytes)
            : BinaryPrimitives.ReadUInt16BigEndian(twoBytes);

    private void ExtractBits(
        FrameExtractionContext context,
        ushort startAddress,
        ushort requestedQuantity,
        ReadOnlySpan<byte> dataBytes,
        List<ExtractedDataPointRecord> dataPoints,
        List<ModbusUnmappedRecord> unmappedRegisters)
    {
        int availableBits = Math.Min((int)requestedQuantity, dataBytes.Length * 8);

        for (int bitIndex = 0; bitIndex < availableBits; bitIndex++)
        {
            int wireOffset = startAddress + bitIndex;
            bool bitValue = (dataBytes[bitIndex / 8] & (1 << (bitIndex % 8))) != 0;
            string rawHex = bitValue ? "01" : "00";

            if (TryFindMappedTag(context.Pair.Id, context.RegisterType, wireOffset, out var tag))
            {
                double? unscaledNumeric = tag.DataType == TagDataType.Bool ? null : (bitValue ? 1.0 : 0.0);
                bool? boolVal = tag.DataType == TagDataType.Bool ? bitValue : null;
                ProjectTagPoint(context, tag.ProtocolAddress, unscaledNumeric, boolVal, rawHex, dataPoints);
            }
            else
            {
                AppendUnmappedIfEnabled(context, wireOffset, rawHex, unmappedRegisters);
            }
        }
    }

    private void ExtractRegisters(
        FrameExtractionContext context,
        ushort startAddress,
        ushort requestedQuantity,
        ReadOnlySpan<byte> dataBytes,
        List<ExtractedDataPointRecord> dataPoints,
        List<ModbusUnmappedRecord> unmappedRegisters)
    {
        int availableRegisters = Math.Min((int)requestedQuantity, dataBytes.Length / 2);
        int regIndex = 0;

        while (regIndex < availableRegisters)
        {
            int wireOffset = startAddress + regIndex;
            if (TryFindMappedTag(context.Pair.Id, context.RegisterType, wireOffset, out var tag))
            {
                bool is32Bit = tag.DataType is TagDataType.Int32 or TagDataType.Float32Be or TagDataType.Float32Swapped;
                if (is32Bit)
                {
                    if (regIndex + 1 < availableRegisters)
                    {
                        ReadOnlySpan<byte> fourBytes = dataBytes.Slice(regIndex * 2, 4);
                        double unscaled = Unpack32BitRegister(tag.DataType, fourBytes);
                        string rawHex = Convert.ToHexString(fourBytes);
                        ProjectTagPoint(context, tag.ProtocolAddress, unscaled, null, rawHex, dataPoints);
                        regIndex += 2;
                    }
                    else
                    {
                        regIndex++;
                    }

                    continue;
                }

                ReadOnlySpan<byte> twoBytes = dataBytes.Slice(regIndex * 2, 2);
                string regHex = Convert.ToHexString(twoBytes);
                double? unscaledNumeric = null;
                bool? boolVal = null;

                switch (tag.DataType)
                {
                    case TagDataType.Int16:
                        unscaledNumeric = BinaryPrimitives.ReadInt16BigEndian(twoBytes);
                        break;
                    case TagDataType.UInt16:
                        unscaledNumeric = BinaryPrimitives.ReadUInt16BigEndian(twoBytes);
                        break;
                    case TagDataType.Bool:
                        boolVal = BinaryPrimitives.ReadUInt16BigEndian(twoBytes) != 0;
                        break;
                }

                ProjectTagPoint(context, tag.ProtocolAddress, unscaledNumeric, boolVal, regHex, dataPoints);
                regIndex++;
                continue;
            }

            ReadOnlySpan<byte> rawReg = dataBytes.Slice(regIndex * 2, 2);
            AppendUnmappedIfEnabled(context, wireOffset, Convert.ToHexString(rawReg), unmappedRegisters);
            regIndex++;
        }
    }

    private void ProjectTagPoint(
        FrameExtractionContext context,
        ProtocolAddress protocolAddress,
        double? unscaledNumericValue,
        bool? booleanValue,
        string rawHex,
        List<ExtractedDataPointRecord> dataPoints)
    {
        if (_tagEngine.TryResolveAndProject(
                sessionId: context.Pair.SessionId,
                devicePairId: context.Pair.Id,
                protocolAddress: protocolAddress,
                packetTimestamp: context.Frame.TimestampUtc,
                eventTimestamp: null,
                frameNumber: context.Frame.FrameNumber,
                direction: context.Direction,
                unscaledNumericValue: unscaledNumericValue,
                booleanValue: booleanValue,
                rawHex: rawHex,
                qualityFlags: PointQualityFlags.Online,
                out var dp))
        {
            dataPoints.Add(dp);
        }
    }

    private void AppendUnmappedIfEnabled(
        FrameExtractionContext context,
        int wireOffset,
        string rawValueHex,
        List<ModbusUnmappedRecord> unmappedRegisters)
    {
        if (!_storeUnmappedRegisters)
        {
            return;
        }

        unmappedRegisters.Add(new ModbusUnmappedRecord(
            Timestamp: context.Frame.TimestampUtc,
            SessionId: context.Pair.SessionId,
            DevicePairId: context.Pair.Id,
            FrameNumber: context.Frame.FrameNumber,
            Direction: context.Direction,
            UnitId: context.UnitId,
            RegisterType: context.RegisterType,
            RegisterOffset: wireOffset,
            RawValueHex: rawValueHex));
    }

    private static double Unpack32BitRegister(TagDataType dataType, ReadOnlySpan<byte> fourBytes) =>
        dataType switch
        {
            TagDataType.Int32 => BinaryPrimitives.ReadInt32BigEndian(fourBytes),
            TagDataType.Float32Be => BinaryPrimitives.ReadSingleBigEndian(fourBytes),
            TagDataType.Float32Swapped => ReadSwappedFloat32(fourBytes),
            _ => 0.0
        };

    private static float ReadSwappedFloat32(ReadOnlySpan<byte> fourBytes)
    {
        Span<byte> swapped = stackalloc byte[4];
        swapped[0] = fourBytes[2];
        swapped[1] = fourBytes[3];
        swapped[2] = fourBytes[0];
        swapped[3] = fourBytes[1];
        return BinaryPrimitives.ReadSingleBigEndian(swapped);
    }

    private bool TryFindMappedTag(
        Guid devicePairId,
        ModbusRegisterType registerType,
        int wireOffset,
        out TagDefinition tag)
    {
        var (prefix, modiconBase) = GetAddressScheme(registerType);

        if (TryLookupAddress(devicePairId, $"{prefix}:{wireOffset}", out tag) ||
            TryLookupAddress(devicePairId, $"{prefix}:{wireOffset:D5}", out tag))
        {
            return true;
        }

        if (modiconBase.HasValue)
        {
            int modiconAddr = modiconBase.Value + wireOffset;
            if (TryLookupAddress(devicePairId, $"{prefix}:{modiconAddr}", out tag) ||
                TryLookupAddress(devicePairId, $"{prefix}:{modiconAddr:D5}", out tag))
            {
                return true;
            }
        }

        tag = default!;
        return false;
    }

    private bool TryLookupAddress(Guid devicePairId, string candidateAddress, out TagDefinition tag)
    {
        if (ProtocolAddress.TryParse(candidateAddress, out var protocolAddress) &&
            _tagEngine.TryGetTag(devicePairId, protocolAddress, out var found) &&
            found is not null)
        {
            tag = found;
            return true;
        }

        tag = default!;
        return false;
    }

    private static ProtocolAddress FormatDefaultAddress(ModbusRegisterType registerType, int wireOffset)
    {
        var (prefix, modiconBase) = GetAddressScheme(registerType);
        return modiconBase.HasValue
            ? ProtocolAddress.Parse($"{prefix}:{modiconBase.Value + wireOffset}")
            : ProtocolAddress.Parse($"{prefix}:{wireOffset:D5}");
    }

    private static (string Prefix, int? ModiconBase) GetAddressScheme(ModbusRegisterType registerType) =>
        registerType switch
        {
            ModbusRegisterType.Holding => ("HR", 40001),
            ModbusRegisterType.Input => ("IR", 30001),
            ModbusRegisterType.Coil => ("COIL", null),
            ModbusRegisterType.DiscreteInput => ("DI", 10001),
            _ => ("HR", 40001)
        };

    private static bool TryParseReadFunctionCode(byte rawFc, out ModbusFunctionCode functionCode)
    {
        switch ((ModbusFunctionCode)rawFc)
        {
            case ModbusFunctionCode.ReadCoils:
            case ModbusFunctionCode.ReadDiscreteInputs:
            case ModbusFunctionCode.ReadHoldingRegisters:
            case ModbusFunctionCode.ReadInputRegisters:
                functionCode = (ModbusFunctionCode)rawFc;
                return true;
            default:
                functionCode = default;
                return false;
        }
    }

    private static bool TryParseWriteFunctionCode(byte rawFc, out ModbusFunctionCode functionCode)
    {
        switch ((ModbusFunctionCode)rawFc)
        {
            case ModbusFunctionCode.WriteSingleCoil:
            case ModbusFunctionCode.WriteSingleRegister:
            case ModbusFunctionCode.WriteMultipleCoils:
            case ModbusFunctionCode.WriteMultipleRegisters:
                functionCode = (ModbusFunctionCode)rawFc;
                return true;
            default:
                functionCode = default;
                return false;
        }
    }

    private static bool IsBitFunction(ModbusFunctionCode functionCode) =>
        functionCode is ModbusFunctionCode.ReadCoils
            or ModbusFunctionCode.ReadDiscreteInputs
            or ModbusFunctionCode.WriteSingleCoil
            or ModbusFunctionCode.WriteMultipleCoils;

    private static ModbusRegisterType ToRegisterType(ModbusFunctionCode functionCode) =>
        functionCode switch
        {
            ModbusFunctionCode.ReadCoils
                or ModbusFunctionCode.WriteSingleCoil
                or ModbusFunctionCode.WriteMultipleCoils => ModbusRegisterType.Coil,
            ModbusFunctionCode.ReadDiscreteInputs => ModbusRegisterType.DiscreteInput,
            ModbusFunctionCode.ReadHoldingRegisters
                or ModbusFunctionCode.WriteSingleRegister
                or ModbusFunctionCode.WriteMultipleRegisters => ModbusRegisterType.Holding,
            ModbusFunctionCode.ReadInputRegisters => ModbusRegisterType.Input,
            _ => ModbusRegisterType.Holding
        };

    private static TransactionStatusCode MapExceptionStatusCode(byte exceptionCode) =>
        exceptionCode switch
        {
            0x01 => TransactionStatusCode.ModbusEx01,
            0x02 => TransactionStatusCode.ModbusEx02,
            0x03 => TransactionStatusCode.ModbusEx03,
            0x04 => TransactionStatusCode.ModbusEx04,
            0x05 => TransactionStatusCode.ModbusEx05,
            0x06 => TransactionStatusCode.ModbusEx06,
            0x08 => TransactionStatusCode.ModbusEx08,
            0x0A => TransactionStatusCode.ModbusEx0A,
            0x0B => TransactionStatusCode.ModbusEx0B,
            _ => TransactionStatusCode.ModbusExceptionUnknown
        };

    private static bool TryValidateMbapAndPdu(ReadOnlySpan<byte> payload, TrafficDirection direction)
    {
        if (payload.Length < 8)
        {
            return false;
        }

        ushort protocolId = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        if (protocolId != 0)
        {
            return false;
        }

        ushort mbapLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(4, 2));
        if (mbapLength < 2 || payload.Length < 6 + mbapLength)
        {
            return false;
        }

        ReadOnlySpan<byte> pdu = payload.Slice(7, mbapLength - 1);
        byte rawFc = pdu[0];

        if (direction == TrafficDirection.ClientToServer)
        {
            if (TryParseReadFunctionCode(rawFc, out _))
            {
                if (pdu.Length < 5)
                {
                    return false;
                }

                ushort quantity = BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(3, 2));
                if (quantity == 0)
                {
                    return false;
                }
            }
            else if (TryParseWriteFunctionCode(rawFc, out var writeFc))
            {
                if (writeFc is ModbusFunctionCode.WriteSingleCoil or ModbusFunctionCode.WriteSingleRegister)
                {
                    if (pdu.Length < 5)
                    {
                        return false;
                    }
                }
                else
                {
                    if (pdu.Length < 6)
                    {
                        return false;
                    }

                    ushort quantity = BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(3, 2));
                    int byteCount = pdu[5];
                    if (quantity == 0 || byteCount == 0 || pdu.Length < 6 + byteCount)
                    {
                        return false;
                    }

                    if (writeFc == ModbusFunctionCode.WriteMultipleCoils)
                    {
                        int requiredBytes = (quantity + 7) / 8;
                        if (byteCount < requiredBytes)
                        {
                            return false;
                        }
                    }
                    else if (byteCount != quantity * 2)
                    {
                        return false;
                    }
                }
            }
        }
        else
        {
            if ((rawFc & ExceptionFlag) != 0)
            {
                if (pdu.Length < 2)
                {
                    return false;
                }
            }
            else if (TryParseReadFunctionCode(rawFc, out var readFc))
            {
                if (pdu.Length < 2)
                {
                    return false;
                }

                int byteCount = pdu[1];
                if (pdu.Length < 2 + byteCount)
                {
                    return false;
                }

                if (!IsBitFunction(readFc) && byteCount % 2 != 0)
                {
                    return false;
                }
            }
            else if (TryParseWriteFunctionCode(rawFc, out _))
            {
                if (pdu.Length < 5)
                {
                    return false;
                }
            }
        }

        return true;
    }
}
