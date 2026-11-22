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
        ushort Quantity,
        TagChangeEventCollector? WriteTagCollector = null);

    private readonly record struct FrameExtractionContext(
        DissectedFrame Frame,
        DeviceEndpointPair Pair,
        TrafficDirection Direction,
        byte UnitId,
        ModbusRegisterType RegisterType,
        TraceId? TraceId,
        SpanId? SpanId,
        TagChangeEventCollector? TagChangeCollector);

    private readonly VirtualClockRedEngine _redEngine;
    private readonly TagResolutionEngine _tagEngine;
    private readonly bool _storeUnmappedRegisters;
    private readonly bool _storeTraceSpans;

    public ModbusTcpDecoder(
        VirtualClockRedEngine redEngine,
        TagResolutionEngine tagEngine,
        bool storeUnmappedRegisters = false,
        bool storeTraceSpans = true)
    {
        ArgumentNullException.ThrowIfNull(redEngine);
        ArgumentNullException.ThrowIfNull(tagEngine);
        _redEngine = redEngine;
        _tagEngine = tagEngine;
        _storeUnmappedRegisters = storeUnmappedRegisters;
        _storeTraceSpans = storeTraceSpans;
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
            TraceId? malformedTraceId = null;
            SpanId? malformedSpanId = null;
            List<TraceSpanRecord> malformedSpans = [];

            if (_storeTraceSpans)
            {
                var ids = SpanCorrelationIds.Allocate(pair, frame.FrameNumber, SpanCorrelationRole.Malformed);
                malformedTraceId = ids.TraceId;
                malformedSpanId = ids.SpanId;
                byte? unitIdForMalformed = payload.Length >= 7 ? payload[6] : null;
                var metadata = new ModbusFrameMetadata(frame, pair, transactionId, unitIdForMalformed, functionCode);
                malformedSpans.Add(ModbusSpanFactory.CreateMalformedSpan(metadata, direction, ids));
            }

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
                StatusCode: TransactionStatusCode.Malformed,
                TraceId: malformedTraceId,
                SpanId: malformedSpanId);

            return new ProtocolDecodeOutput([malformedTx], [], [], [], malformedSpans);
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
        var traceSpans = new List<TraceSpanRecord>();

        if (direction == TrafficDirection.ClientToServer)
        {
            if (!isException && TryParseReadFunctionCode(rawFc, out var readFc))
            {
                ushort startAddress = BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(1, 2));
                ushort quantity = BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(3, 2));
                var context = new ModbusRequestContext(unitId, readFc, startAddress, quantity);

                PendingSpanContext? spanContext = null;
                if (_storeTraceSpans)
                {
                    var ids = SpanCorrelationIds.Allocate(pair, frame.FrameNumber, SpanCorrelationRole.Transaction);
                    var metadata = new ModbusFrameMetadata(frame, pair, transactionId, unitId, rawFc);
                    spanContext = ModbusSpanFactory.CreateRequestPendingSpanContext(
                        metadata,
                        ids,
                        ToRegisterType(readFc),
                        startAddress,
                        quantity);
                }

                _redEngine.RegisterRequest(
                    sessionId: pair.SessionId,
                    devicePairId: pair.Id,
                    frameNumber: frame.FrameNumber,
                    timestampUtc: frame.TimestampUtc,
                    transactionId: transactionId,
                    functionCode: rawFc,
                    requestContext: context,
                    correlationKey: correlationKey,
                    spanContext: spanContext);
            }
            else if (!isException && TryParseWriteFunctionCode(rawFc, out var writeFc))
            {
                TraceId? writeTraceId = null;
                SpanId? writeSpanId = null;
                TagChangeEventCollector? writeTagCollector = null;

                if (_storeTraceSpans)
                {
                    var ids = SpanCorrelationIds.Allocate(pair, frame.FrameNumber, SpanCorrelationRole.Transaction);
                    writeTraceId = ids.TraceId;
                    writeSpanId = ids.SpanId;
                    writeTagCollector = new TagChangeEventCollector();
                }

                var extractionContext = new FrameExtractionContext(
                    frame,
                    pair,
                    direction,
                    unitId,
                    ToRegisterType(writeFc),
                    writeTraceId,
                    writeSpanId,
                    writeTagCollector);

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
            var serverMetadata = new ModbusFrameMetadata(frame, pair, transactionId, unitId, baseFcByte);
            if (isException)
            {
                byte exceptionCode = pdu[1];
                var statusCode = MapExceptionStatusCode(exceptionCode);
                if (_redEngine.TryCompleteResponse<ModbusRequestContext>(
                        devicePairId: pair.Id,
                        transactionId: transactionId,
                        responseFrameNumber: frame.FrameNumber,
                        responseTimestampUtc: frame.TimestampUtc,
                        responseFunctionCode: rawFc,
                        isException: true,
                        statusCode: statusCode,
                        out var exTx,
                        out var reqContext,
                        out var spanContext,
                        correlationKey: correlationKey))
                {
                    transactions.Add(exTx);
                    EmitMatchedResponseSpanIfTracing(
                        traceSpans,
                        frame,
                        exTx,
                        reqContext,
                        spanContext,
                        baseFcByte,
                        isException: true,
                        exceptionCode: exceptionCode,
                        responseTagCollector: null);
                }
                else
                {
                    EmitOrphanSpanIfTracing(
                        traceSpans,
                        serverMetadata,
                        TryResolveRegisterType(baseFcByte),
                        isException: true,
                        exceptionCode: exceptionCode,
                        exceptionStatusCode: statusCode);
                }
            }
            else if (TryParseReadFunctionCode(rawFc, out var readFc))
            {
                var registerType = ToRegisterType(readFc);
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
                        out var spanContext,
                        correlationKey: correlationKey))
                {
                    transactions.Add(okTx);

                    var responseTagCollector = _storeTraceSpans && spanContext is not null
                        ? new TagChangeEventCollector()
                        : null;

                    int byteCount = pdu[1];
                    ReadOnlySpan<byte> dataBytes = pdu.Slice(2, byteCount);
                    var extractionContext = new FrameExtractionContext(
                        frame,
                        pair,
                        direction,
                        unitId,
                        registerType,
                        spanContext?.TraceId,
                        spanContext?.SpanId,
                        responseTagCollector);

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

                    EmitMatchedResponseSpanIfTracing(
                        traceSpans,
                        frame,
                        okTx,
                        reqContext,
                        spanContext,
                        baseFcByte,
                        isException: false,
                        exceptionCode: null,
                        responseTagCollector: responseTagCollector);
                }
                else
                {
                    EmitOrphanSpanIfTracing(
                        traceSpans,
                        serverMetadata,
                        registerType,
                        isException: false,
                        exceptionCode: null,
                        exceptionStatusCode: null);
                }
            }
            else if (TryParseWriteFunctionCode(rawFc, out var writeFc))
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
                        out var spanContext,
                        correlationKey: correlationKey))
                {
                    transactions.Add(okTx);
                    EmitMatchedResponseSpanIfTracing(
                        traceSpans,
                        frame,
                        okTx,
                        reqContext,
                        spanContext,
                        baseFcByte,
                        isException: false,
                        exceptionCode: null,
                        responseTagCollector: null);
                }
                else
                {
                    EmitOrphanSpanIfTracing(
                        traceSpans,
                        serverMetadata,
                        ToRegisterType(writeFc),
                        isException: false,
                        exceptionCode: null,
                        exceptionStatusCode: null);
                }
            }
            else
            {
                EmitOrphanSpanIfTracing(
                    traceSpans,
                    serverMetadata,
                    registerType: null,
                    isException: false,
                    exceptionCode: null,
                    exceptionStatusCode: null);
            }
        }

        return new ProtocolDecodeOutput(transactions, dataPoints, commandEvents, unmappedRegisters, traceSpans);
    }

    public TimeoutFlushOutput FlushExpiredTimeouts(DateTime currentVirtualTime, bool isEndOfFile) =>
        _redEngine.FlushExpiredTimeouts(currentVirtualTime, isEndOfFile);

    private void EmitMatchedResponseSpanIfTracing(
        List<TraceSpanRecord> traceSpans,
        DissectedFrame frame,
        ProtocolTransactionRecord transaction,
        ModbusRequestContext reqContext,
        PendingSpanContext? spanContext,
        byte baseFunctionCode,
        bool isException,
        byte? exceptionCode,
        TagChangeEventCollector? responseTagCollector)
    {
        if (!_storeTraceSpans || spanContext is null)
        {
            return;
        }

        traceSpans.Add(ModbusSpanFactory.CreateResponseSpan(
            frame,
            transaction,
            spanContext,
            baseFunctionCode,
            isException,
            exceptionCode,
            reqContext.WriteTagCollector,
            responseTagCollector));
    }

    private void EmitOrphanSpanIfTracing(
        List<TraceSpanRecord> traceSpans,
        ModbusFrameMetadata metadata,
        ModbusRegisterType? registerType,
        bool isException,
        byte? exceptionCode,
        TransactionStatusCode? exceptionStatusCode)
    {
        if (!_storeTraceSpans)
        {
            return;
        }

        traceSpans.Add(ModbusSpanFactory.CreateOrphanResponseSpan(
            metadata,
            registerType,
            isException,
            exceptionCode,
            exceptionStatusCode));
    }

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
            unscaledCommandValue = ExtractRegistersAndComputeCommandValue(
                extractionContext,
                startAddress,
                quantity: 1,
                valueBytes,
                hasTag,
                tag,
                dataPoints,
                unmappedRegisters);
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
            unscaledCommandValue = ExtractRegistersAndComputeCommandValue(
                extractionContext,
                startAddress,
                quantity,
                dataBytes,
                hasTag,
                tag,
                dataPoints,
                unmappedRegisters);
        }

        var commandEvent = new CapturedCommandEventRecord(
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
            RawPduBytes: extractionContext.Frame.RawApplicationPayload.ToArray(),
            TraceId: extractionContext.TraceId,
            SpanId: extractionContext.SpanId);

        commandEvents.Add(commandEvent);

        PendingSpanContext? spanContext = null;
        if (_storeTraceSpans &&
            extractionContext.TraceId.HasValue &&
            extractionContext.SpanId.HasValue)
        {
            var ids = new SpanCorrelationIds(extractionContext.TraceId.Value, extractionContext.SpanId.Value);
            var metadata = new ModbusFrameMetadata(
                extractionContext.Frame,
                extractionContext.Pair,
                transactionId,
                extractionContext.UnitId,
                (byte)writeFc);
            spanContext = ModbusSpanFactory.CreateRequestPendingSpanContext(
                metadata,
                ids,
                extractionContext.RegisterType,
                startAddress,
                quantity,
                writeCommand: commandEvent,
                writeTagCollector: extractionContext.TagChangeCollector);
        }

        var reqContext = new ModbusRequestContext(
            extractionContext.UnitId,
            writeFc,
            startAddress,
            quantity,
            extractionContext.TagChangeCollector);
        _redEngine.RegisterRequest(
            sessionId: extractionContext.Pair.SessionId,
            devicePairId: extractionContext.Pair.Id,
            frameNumber: extractionContext.Frame.FrameNumber,
            timestampUtc: extractionContext.Frame.TimestampUtc,
            transactionId: transactionId,
            functionCode: (byte)writeFc,
            requestContext: reqContext,
            correlationKey: correlationKey,
            spanContext: spanContext);
    }

    private double? ExtractRegistersAndComputeCommandValue(
        FrameExtractionContext extractionContext,
        ushort startAddress,
        ushort quantity,
        ReadOnlySpan<byte> dataBytes,
        bool hasTag,
        TagDefinition? tag,
        List<ExtractedDataPointRecord> dataPoints,
        List<ModbusUnmappedRecord> unmappedRegisters)
    {
        int pointsBefore = dataPoints.Count;
        ExtractRegisters(extractionContext, startAddress, quantity, dataBytes, dataPoints, unmappedRegisters);

        if (hasTag &&
            tag is not null &&
            GetRegisterWidth(tag.DataType) == quantity &&
            dataPoints.Count == pointsBefore + 1)
        {
            var point = dataPoints[pointsBefore];
            return point.UnscaledNumericValue ?? (point.BooleanValue.HasValue ? (point.BooleanValue.Value ? 1.0 : 0.0) : null);
        }

        if (!hasTag && quantity == 1)
        {
            return BinaryPrimitives.ReadUInt16BigEndian(dataBytes[..2]);
        }

        return null;
    }

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
                ProjectTagPoint(context, tag, unscaledNumeric, boolVal, rawHex, dataPoints);
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
                int registerWidth = GetRegisterWidth(tag.DataType);
                if (regIndex + registerWidth <= availableRegisters)
                {
                    ReadOnlySpan<byte> rawSlice = dataBytes.Slice(regIndex * 2, registerWidth * 2);
                    string rawHex = Convert.ToHexString(rawSlice);

                    if (tag.DataType == TagDataType.Bool)
                    {
                        bool boolVal = BinaryPrimitives.ReadUInt16BigEndian(rawSlice) != 0;
                        ProjectTagPoint(context, tag, null, boolVal, rawHex, dataPoints);
                    }
                    else
                    {
                        double unscaled = UnpackNumericRegister(tag.DataType, tag.Endianness, rawSlice);
                        ProjectTagPoint(context, tag, unscaled, null, rawHex, dataPoints);
                    }

                    regIndex += registerWidth;
                }
                else
                {
                    regIndex++;
                }

                continue;
            }

            ReadOnlySpan<byte> rawReg = dataBytes.Slice(regIndex * 2, 2);
            AppendUnmappedIfEnabled(context, wireOffset, Convert.ToHexString(rawReg), unmappedRegisters);
            regIndex++;
        }
    }

    private void ProjectTagPoint(
        FrameExtractionContext context,
        TagDefinition tag,
        double? unscaledNumericValue,
        bool? booleanValue,
        string rawHex,
        List<ExtractedDataPointRecord> dataPoints)
    {
        if (_tagEngine.TryResolveAndProject(
                sessionId: context.Pair.SessionId,
                devicePairId: context.Pair.Id,
                protocolAddress: tag.ProtocolAddress,
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
            var stamped = context.TraceId.HasValue && context.SpanId.HasValue
                ? dp with { TraceId = context.TraceId, SpanId = context.SpanId }
                : dp;

            dataPoints.Add(stamped);
            context.TagChangeCollector?.Record(tag, stamped);
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

    private static int GetRegisterWidth(TagDataType dataType) =>
        dataType switch
        {
            TagDataType.Int32 or TagDataType.UInt32 or TagDataType.Float32 => 2,
            TagDataType.Int64 or TagDataType.UInt64 or TagDataType.Float64 => 4,
            _ => 1
        };

    private static double UnpackNumericRegister(
        TagDataType dataType,
        RegisterEndianness endianness,
        ReadOnlySpan<byte> wireBytes)
    {
        Span<byte> bigEndianBytes = stackalloc byte[wireBytes.Length];
        PermuteToBigEndian(wireBytes, endianness, bigEndianBytes);

        return dataType switch
        {
            TagDataType.Int16 => BinaryPrimitives.ReadInt16BigEndian(bigEndianBytes),
            TagDataType.UInt16 => BinaryPrimitives.ReadUInt16BigEndian(bigEndianBytes),
            TagDataType.Int32 => BinaryPrimitives.ReadInt32BigEndian(bigEndianBytes),
            TagDataType.UInt32 => BinaryPrimitives.ReadUInt32BigEndian(bigEndianBytes),
            TagDataType.Int64 => BinaryPrimitives.ReadInt64BigEndian(bigEndianBytes),
            TagDataType.UInt64 => BinaryPrimitives.ReadUInt64BigEndian(bigEndianBytes),
            TagDataType.Float32 => BinaryPrimitives.ReadSingleBigEndian(bigEndianBytes),
            TagDataType.Float64 => BinaryPrimitives.ReadDoubleBigEndian(bigEndianBytes),
            _ => 0.0
        };
    }

    private static void PermuteToBigEndian(
        ReadOnlySpan<byte> wireBytes,
        RegisterEndianness endianness,
        Span<byte> destination)
    {
        bool swapWords = endianness is RegisterEndianness.Cdab or RegisterEndianness.Dcba;
        bool swapBytesWithinWord = endianness is RegisterEndianness.Badc or RegisterEndianness.Dcba;
        int wordCount = wireBytes.Length / 2;

        for (int wordIndex = 0; wordIndex < wordCount; wordIndex++)
        {
            int srcWordIndex = swapWords ? (wordCount - 1 - wordIndex) : wordIndex;
            int srcByteOffset = srcWordIndex * 2;
            int dstByteOffset = wordIndex * 2;

            if (swapBytesWithinWord)
            {
                destination[dstByteOffset] = wireBytes[srcByteOffset + 1];
                destination[dstByteOffset + 1] = wireBytes[srcByteOffset];
            }
            else
            {
                destination[dstByteOffset] = wireBytes[srcByteOffset];
                destination[dstByteOffset + 1] = wireBytes[srcByteOffset + 1];
            }
        }
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

    private static ModbusRegisterType? TryResolveRegisterType(byte baseFunctionCode) =>
        TryParseReadFunctionCode(baseFunctionCode, out var readFc)
            ? ToRegisterType(readFc)
            : TryParseWriteFunctionCode(baseFunctionCode, out var writeFc)
                ? ToRegisterType(writeFc)
                : null;

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
