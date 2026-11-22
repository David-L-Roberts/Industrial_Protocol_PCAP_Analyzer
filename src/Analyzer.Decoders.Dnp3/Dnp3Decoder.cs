using System.Buffers.Binary;
using System.Globalization;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Services;
using Analyzer.Decoders.Dnp3.Handlers;
using Analyzer.Decoders.Dnp3.Registry;

namespace Analyzer.Decoders.Dnp3;

public enum Dnp3FunctionCode : byte
{
    Confirm = 0x00,
    Read = 0x01,
    Write = 0x02,
    Select = 0x03,
    Operate = 0x04,
    DirectOperate = 0x05,
    DirectOperateNoAck = 0x06,
    ColdRestart = 0x0D,
    WarmRestart = 0x0E,
    EnableUnsolicited = 0x14,
    DisableUnsolicited = 0x15,
    DelayMeasure = 0x17,
    Response = 0x81,
    UnsolicitedResponse = 0x82
}

public class Dnp3Decoder : IProtocolDecoder
{
    public const int DefaultSboWindowMs = 10_000;

    private const byte StartByte1 = 0x05;
    private const byte StartByte2 = 0x64;
    private const int MinLinkHeaderBytes = 10;
    private const int MinLinkLengthField = 5;

    private readonly record struct Dnp3RequestContext(
        byte RequestFunctionCode,
        Dnp3TagChangeEventCollector? RequestTagCollector,
        IReadOnlyList<ProtocolAddress>? SelectTargetAddresses = null);

    private readonly VirtualClockRedEngine _redEngine;
    private readonly Dnp3HandlerRegistry _handlerRegistry;
    private readonly TagResolutionEngine? _tagEngine;
    private readonly bool _storeTraceSpans;
    private readonly Dnp3SboTracker? _sboTracker;
    private readonly Dnp3ConfirmTracker? _confirmTracker;

    public Dnp3Decoder(
        VirtualClockRedEngine redEngine,
        Dnp3HandlerRegistry handlerRegistry,
        TagResolutionEngine? tagEngine = null,
        bool storeTraceSpans = true,
        int sboWindowMs = DefaultSboWindowMs)
    {
        ArgumentNullException.ThrowIfNull(redEngine);
        ArgumentNullException.ThrowIfNull(handlerRegistry);
        if (sboWindowMs <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(sboWindowMs), "SBO window must be positive.");
        }

        _redEngine = redEngine;
        _handlerRegistry = handlerRegistry;
        _tagEngine = tagEngine;
        _storeTraceSpans = storeTraceSpans;

        if (storeTraceSpans)
        {
            _sboTracker = new Dnp3SboTracker(sboWindowMs, redEngine.TimeoutThresholdMs);
            _confirmTracker = new Dnp3ConfirmTracker(redEngine.TimeoutThresholdMs);
        }
    }

    public ProtocolType Protocol => ProtocolType.Dnp3;

    public ProtocolDecodeOutput ProcessFrame(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction)
    {
        ArgumentNullException.ThrowIfNull(frame);
        ArgumentNullException.ThrowIfNull(pair);

        ReadOnlySpan<byte> payload = frame.RawApplicationPayload;

        if (!TryStripDataLinkAndTransport(payload, out ushort destinationAddress, out ushort sourceAddress, out byte[] appFragment))
        {
            return CreateMalformedOutput(
                frame,
                pair,
                direction,
                transactionId: "0",
                functionCode: 0,
                sourceAddress: null,
                destinationAddress: null,
                appControl: null);
        }

        if (!MatchesEndpointAddresses(pair, direction, sourceAddress, destinationAddress))
        {
            return new ProtocolDecodeOutput([], [], [], [], []);
        }

        ReadOnlySpan<byte> appSpan = appFragment;
        int minAppHeaderLen = direction == TrafficDirection.ServerToClient ? 4 : 2;
        if (appSpan.Length < minAppHeaderLen)
        {
            Dnp3AppControl? partialAppControl = appSpan.Length >= 1
                ? Dnp3AppControl.Parse(appSpan[0])
                : null;
            string partialSeq = partialAppControl.HasValue
                ? partialAppControl.Value.Seq.ToString(CultureInfo.InvariantCulture)
                : "0";
            short partialFc = appSpan.Length >= 2 ? appSpan[1] : (short)0;

            return CreateMalformedOutput(
                frame,
                pair,
                direction,
                partialSeq,
                partialFc,
                sourceAddress,
                destinationAddress,
                partialAppControl);
        }

        var appControl = Dnp3AppControl.Parse(appSpan[0]);
        byte functionCode = appSpan[1];
        string transactionId = appControl.Seq.ToString(CultureInfo.InvariantCulture);

        int clientAddr = direction == TrafficDirection.ClientToServer ? sourceAddress : destinationAddress;
        int serverAddr = direction == TrafficDirection.ClientToServer ? destinationAddress : sourceAddress;
        string correlationKey = $"{clientAddr}:{serverAddr}:{transactionId}";

        var metadata = new Dnp3FrameMetadata(
            Frame: frame,
            Pair: pair,
            Direction: direction,
            TransactionId: transactionId,
            FunctionCode: functionCode,
            SourceAddress: sourceAddress,
            DestinationAddress: destinationAddress,
            AppControl: appControl);

        var transactions = new List<ProtocolTransactionRecord>();
        var dataPoints = new List<ExtractedDataPointRecord>();
        var commandEvents = new List<CapturedCommandEventRecord>();
        var traceSpans = new List<TraceSpanRecord>();

        if (direction == TrafficDirection.ClientToServer)
        {
            ProcessClientFrame(
                metadata,
                functionCode,
                correlationKey,
                appSpan[2..],
                dataPoints,
                commandEvents,
                traceSpans);
        }
        else
        {
            ProcessServerFrame(
                metadata,
                appControl,
                functionCode,
                correlationKey,
                appSpan[2],
                appSpan[3],
                appSpan[4..],
                transactions,
                dataPoints,
                commandEvents,
                traceSpans);
        }

        return new ProtocolDecodeOutput(transactions, dataPoints, commandEvents, [], traceSpans);
    }

    public TimeoutFlushOutput FlushExpiredTimeouts(DateTime currentVirtualTime, bool isEndOfFile)
    {
        var redFlushed = _redEngine.FlushExpiredTimeouts(currentVirtualTime, isEndOfFile);
        if (!_storeTraceSpans)
        {
            return redFlushed;
        }

        _sboTracker?.PruneExpired(currentVirtualTime, isEndOfFile, redFlushed.TraceSpans);
        var confirmTimeouts = _confirmTracker?.FlushExpired(currentVirtualTime, isEndOfFile);
        if (confirmTimeouts is null or { Count: 0 })
        {
            return redFlushed;
        }

        var combinedSpans = new List<TraceSpanRecord>(redFlushed.TraceSpans.Count + confirmTimeouts.Count);
        combinedSpans.AddRange(redFlushed.TraceSpans);
        combinedSpans.AddRange(confirmTimeouts);
        return new TimeoutFlushOutput(redFlushed.Transactions, combinedSpans);
    }

    private void ProcessClientFrame(
        Dnp3FrameMetadata metadata,
        byte functionCode,
        string correlationKey,
        ReadOnlySpan<byte> objectsPayload,
        List<ExtractedDataPointRecord> dataPoints,
        List<CapturedCommandEventRecord> commandEvents,
        List<TraceSpanRecord> traceSpans)
    {
        var dnp3Fc = (Dnp3FunctionCode)functionCode;

        if (dnp3Fc == Dnp3FunctionCode.DirectOperateNoAck)
        {
            var objectGroups = new List<Dnp3ObjectGroupId>();
            ScanObjectSections(
                metadata.Frame,
                metadata.Pair,
                metadata.Direction,
                objectsPayload,
                dispatchHandlers: true,
                dataPoints,
                commandEvents,
                objectGroups);

            if (_storeTraceSpans)
            {
                var ids = Dnp3SpanCorrelationIds.Allocate(metadata.Pair, metadata.Frame.FrameNumber, SpanCorrelationRole.DirectNoAck);
                StampCorrelationIds(dataPoints, commandEvents, ids.TraceId, ids.SpanId);
                var tagCollector = CollectTagChanges(dataPoints);
                traceSpans.Add(Dnp3SpanFactory.CreateDirectNoAckSpan(
                    metadata,
                    ids,
                    objectGroups,
                    commandEvents,
                    tagCollector));
            }

            return;
        }

        if (dnp3Fc == Dnp3FunctionCode.Confirm)
        {
            if (_storeTraceSpans && _confirmTracker is not null && metadata.AppControl is { } appControl)
            {
                _confirmTracker.TryConsume(
                    metadata.Pair.Id,
                    appControl.Seq,
                    appControl.Uns,
                    out var pendingConfirm);
                traceSpans.Add(Dnp3SpanFactory.CreateConfirmSpan(metadata, pendingConfirm));
            }

            return;
        }

        var requestObjectGroups = new List<Dnp3ObjectGroupId>();
        ScanObjectSections(
            metadata.Frame,
            metadata.Pair,
            metadata.Direction,
            objectsPayload,
            dispatchHandlers: IsPayloadBearingClientFunction(functionCode),
            dataPoints,
            commandEvents,
            requestObjectGroups);

        PendingSpanContext? spanContext = null;
        Dnp3TagChangeEventCollector? requestTagCollector = null;
        IReadOnlyList<ProtocolAddress>? selectTargetAddresses = null;

        if (_storeTraceSpans)
        {
            Dnp3SpanCorrelationIds ids;
            SpanId? parentSpanId = null;
            bool? sboLinked = null;

            if (dnp3Fc == Dnp3FunctionCode.Select)
            {
                ids = Dnp3SpanCorrelationIds.Allocate(metadata.Pair, metadata.Frame.FrameNumber, SpanCorrelationRole.SboSelect);
                if (commandEvents.Count > 0)
                {
                    var distinctTargets = new List<ProtocolAddress>(commandEvents.Count);
                    for (int i = 0; i < commandEvents.Count; i++)
                    {
                        var addr = commandEvents[i].TargetAddress;
                        if (!distinctTargets.Contains(addr))
                        {
                            distinctTargets.Add(addr);
                        }
                    }

                    selectTargetAddresses = distinctTargets;
                    _sboTracker?.RegisterSelect(
                        metadata.Pair.Id,
                        distinctTargets,
                        ids.TraceId,
                        ids.SpanId,
                        metadata.Frame.TimestampUtc);
                }
            }
            else if (dnp3Fc == Dnp3FunctionCode.Operate)
            {
                bool linked = false;
                TraceId linkedTraceId = default;
                SpanId linkedParentSpanId = default;

                if (_sboTracker is not null)
                {
                    for (int i = 0; i < commandEvents.Count; i++)
                    {
                        if (_sboTracker.TryConsumeForOperate(
                            metadata.Pair.Id,
                            commandEvents[i].TargetAddress,
                            metadata.Frame.TimestampUtc,
                            out linkedTraceId,
                            out linkedParentSpanId))
                        {
                            linked = true;
                            break;
                        }
                    }
                }

                if (linked)
                {
                    ids = new Dnp3SpanCorrelationIds(
                        linkedTraceId,
                        DeterministicTraceIdGenerator.CreateSpanId(
                            metadata.Pair.SessionId,
                            metadata.Pair.Id,
                            metadata.Frame.FrameNumber,
                            SpanCorrelationRole.SboOperate));
                    parentSpanId = linkedParentSpanId;
                    sboLinked = true;
                }
                else
                {
                    ids = Dnp3SpanCorrelationIds.Allocate(metadata.Pair, metadata.Frame.FrameNumber, SpanCorrelationRole.Transaction);
                    sboLinked = false;
                }
            }
            else
            {
                ids = Dnp3SpanCorrelationIds.Allocate(metadata.Pair, metadata.Frame.FrameNumber, SpanCorrelationRole.Transaction);
            }

            StampCorrelationIds(dataPoints, commandEvents, ids.TraceId, ids.SpanId);

            if (dataPoints.Count > 0)
            {
                requestTagCollector = CollectTagChanges(dataPoints);
            }

            spanContext = Dnp3SpanFactory.CreateRequestPendingSpanContext(
                metadata,
                ids,
                requestObjectGroups,
                commandEvents,
                requestTagCollector,
                parentSpanId,
                sboLinked);
        }

        var reqContext = new Dnp3RequestContext(functionCode, requestTagCollector, selectTargetAddresses);
        _redEngine.RegisterRequest(
            sessionId: metadata.Pair.SessionId,
            devicePairId: metadata.Pair.Id,
            frameNumber: metadata.Frame.FrameNumber,
            timestampUtc: metadata.Frame.TimestampUtc,
            transactionId: metadata.TransactionId,
            functionCode: functionCode,
            requestContext: reqContext,
            correlationKey: correlationKey,
            spanContext: spanContext);
    }

    private void ProcessServerFrame(
        Dnp3FrameMetadata metadata,
        Dnp3AppControl appControl,
        byte functionCode,
        string correlationKey,
        byte iin1,
        byte iin2,
        ReadOnlySpan<byte> objectsPayload,
        List<ProtocolTransactionRecord> transactions,
        List<ExtractedDataPointRecord> dataPoints,
        List<CapturedCommandEventRecord> commandEvents,
        List<TraceSpanRecord> traceSpans)
    {
        bool isException = TryMapIinErrorStatusCode(iin1, iin2, out var statusCode);
        var iinStatus = new Dnp3IinStatus(iin1, iin2, isException, statusCode);
        var responseObjectGroups = new List<Dnp3ObjectGroupId>();
        ScanObjectSections(
            metadata.Frame,
            metadata.Pair,
            metadata.Direction,
            objectsPayload,
            dispatchHandlers: true,
            dataPoints,
            commandEvents,
            responseObjectGroups);

        if (functionCode == (byte)Dnp3FunctionCode.Response &&
            _redEngine.TryCompleteResponse<Dnp3RequestContext>(
                devicePairId: metadata.Pair.Id,
                transactionId: metadata.TransactionId,
                responseFrameNumber: metadata.Frame.FrameNumber,
                responseTimestampUtc: metadata.Frame.TimestampUtc,
                responseFunctionCode: functionCode,
                isException: isException,
                statusCode: statusCode,
                out var tx,
                out var reqContext,
                out var spanContext,
                correlationKey: correlationKey))
        {
            transactions.Add(tx);

            if (_storeTraceSpans && spanContext is not null)
            {
                if (reqContext.RequestFunctionCode == (byte)Dnp3FunctionCode.Select &&
                    reqContext.SelectTargetAddresses is { Count: > 0 })
                {
                    _sboTracker?.OnSelectResponse(
                        metadata.Pair.Id,
                        reqContext.SelectTargetAddresses,
                        spanContext.SpanId,
                        metadata.Frame.TimestampUtc,
                        isException);
                }

                StampCorrelationIds(dataPoints, commandEvents, spanContext.TraceId, spanContext.SpanId);
                var responseTagCollector = CollectTagChanges(dataPoints);
                traceSpans.Add(Dnp3SpanFactory.CreateResponseSpan(
                    responseFrame: metadata.Frame,
                    transaction: tx,
                    spanContext: spanContext,
                    requestFunctionCode: reqContext.RequestFunctionCode,
                    responseAppControl: appControl,
                    iinStatus: iinStatus,
                    responseObjectGroups: responseObjectGroups,
                    responseCommands: commandEvents,
                    requestTagCollector: reqContext.RequestTagCollector,
                    responseTagCollector: responseTagCollector));

                if (appControl.Con)
                {
                    RegisterPendingConfirm(metadata, appControl, spanContext.TraceId, spanContext.SpanId, isUnsolicited: false);
                }
            }

            return;
        }

        if (!_storeTraceSpans)
        {
            return;
        }

        bool isUnsolicited = functionCode == (byte)Dnp3FunctionCode.UnsolicitedResponse;
        var role = isUnsolicited ? SpanCorrelationRole.UnsolicitedResponse : SpanCorrelationRole.OrphanResponse;
        var ids = Dnp3SpanCorrelationIds.Allocate(metadata.Pair, metadata.Frame.FrameNumber, role);

        StampCorrelationIds(dataPoints, commandEvents, ids.TraceId, ids.SpanId);
        var tagCollector = CollectTagChanges(dataPoints);
        var span = isUnsolicited
            ? Dnp3SpanFactory.CreateUnsolicitedSpan(metadata, ids, iinStatus, responseObjectGroups, commandEvents, tagCollector)
            : Dnp3SpanFactory.CreateOrphanResponseSpan(metadata, ids, iinStatus, responseObjectGroups, commandEvents, tagCollector);
        traceSpans.Add(span);

        if (appControl.Con &&
            (functionCode == (byte)Dnp3FunctionCode.Response || isUnsolicited))
        {
            RegisterPendingConfirm(metadata, appControl, ids.TraceId, ids.SpanId, isUnsolicited);
        }
    }

    private void RegisterPendingConfirm(
        Dnp3FrameMetadata metadata,
        Dnp3AppControl appControl,
        TraceId traceId,
        SpanId parentSpanId,
        bool isUnsolicited)
    {
        if (_confirmTracker is null ||
            !metadata.SourceAddress.HasValue ||
            !metadata.DestinationAddress.HasValue)
        {
            return;
        }

        _confirmTracker?.Register(PendingConfirmContext.FromMetadata(
            metadata,
            appControl,
            traceId,
            parentSpanId,
            isUnsolicited));
    }

    private void ScanObjectSections(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction,
        ReadOnlySpan<byte> objectsPayload,
        bool dispatchHandlers,
        List<ExtractedDataPointRecord> dataPoints,
        List<CapturedCommandEventRecord> commandEvents,
        List<Dnp3ObjectGroupId> objectGroupsOut)
    {
        int cursor = 0;

        while (cursor + 3 <= objectsPayload.Length)
        {
            ushort group = objectsPayload[cursor];
            ushort variation = objectsPayload[cursor + 1];
            ReadOnlySpan<byte> remainingFromQualifier = objectsPayload[(cursor + 2)..];

            bool parsedSection = dispatchHandlers
                ? Dnp3ObjectAddressing.TryComputeObjectSectionLength(group, variation, remainingFromQualifier, out int sectionLength)
                : Dnp3ObjectAddressing.TryComputeRequestHeaderSectionLength(remainingFromQualifier, out sectionLength);

            if (!parsedSection)
            {
                break;
            }

            var groupId = new Dnp3ObjectGroupId(group, variation);
            if (!objectGroupsOut.Contains(groupId))
            {
                objectGroupsOut.Add(groupId);
            }

            if (dispatchHandlers && _handlerRegistry.TryGetHandler(group, out var handler))
            {
                ReadOnlySpan<byte> objectData = remainingFromQualifier[..sectionLength];
                handler.ExtractObjects(
                    frame,
                    pair,
                    direction,
                    variation,
                    objectData,
                    dataPoints,
                    commandEvents);
            }

            cursor += 2 + sectionLength;
        }
    }

    private Dnp3TagChangeEventCollector CollectTagChanges(IReadOnlyList<ExtractedDataPointRecord> dataPoints)
    {
        var collector = new Dnp3TagChangeEventCollector();
        collector.Record(dataPoints, _tagEngine);
        return collector;
    }

    private static void StampCorrelationIds(
        List<ExtractedDataPointRecord> dataPoints,
        List<CapturedCommandEventRecord> commandEvents,
        TraceId traceId,
        SpanId spanId)
    {
        for (int i = 0; i < dataPoints.Count; i++)
        {
            dataPoints[i] = dataPoints[i] with { TraceId = traceId, SpanId = spanId };
        }

        for (int i = 0; i < commandEvents.Count; i++)
        {
            commandEvents[i] = commandEvents[i] with { TraceId = traceId, SpanId = spanId };
        }
    }

    private static bool IsPayloadBearingClientFunction(byte functionCode) =>
        functionCode is (byte)Dnp3FunctionCode.Write
            or (byte)Dnp3FunctionCode.Select
            or (byte)Dnp3FunctionCode.Operate
            or (byte)Dnp3FunctionCode.DirectOperate
            or (byte)Dnp3FunctionCode.DirectOperateNoAck;

    public static bool TryStripDataLinkAndTransport(
        ReadOnlySpan<byte> payload,
        out ushort destinationAddress,
        out ushort sourceAddress,
        out byte[] applicationFragment)
    {
        destinationAddress = 0;
        sourceAddress = 0;
        applicationFragment = [];

        if (payload.Length < MinLinkHeaderBytes || payload[0] != StartByte1 || payload[1] != StartByte2)
        {
            return false;
        }

        byte linkLength = payload[2];
        if (linkLength < MinLinkLengthField)
        {
            return false;
        }

        destinationAddress = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(4, 2));
        sourceAddress = BinaryPrimitives.ReadUInt16LittleEndian(payload.Slice(6, 2));

        int userDataBytesCount = linkLength - MinLinkLengthField;
        if (userDataBytesCount < 1)
        {
            return false;
        }

        int numBlocks = (userDataBytesCount + 15) / 16;
        int requiredTotalLength = MinLinkHeaderBytes + userDataBytesCount + (numBlocks * 2);
        if (payload.Length < requiredTotalLength)
        {
            return false;
        }

        byte[] reassembledUserBytes = new byte[userDataBytesCount];
        int srcOffset = MinLinkHeaderBytes;
        int dstOffset = 0;

        while (dstOffset < userDataBytesCount)
        {
            int blockDataLen = Math.Min(16, userDataBytesCount - dstOffset);
            payload.Slice(srcOffset, blockDataLen).CopyTo(reassembledUserBytes.AsSpan(dstOffset, blockDataLen));
            srcOffset += blockDataLen + 2; // Skip 2-byte block CRC
            dstOffset += blockDataLen;
        }

        // First byte of reassembled user data is the DNP3 Transport Header; remaining bytes are the Application Fragment
        applicationFragment = reassembledUserBytes[1..];
        return true;
    }

    private static bool MatchesEndpointAddresses(
        DeviceEndpointPair pair,
        TrafficDirection direction,
        ushort sourceAddress,
        ushort destinationAddress)
    {
        int actualClientAddress = direction == TrafficDirection.ClientToServer ? sourceAddress : destinationAddress;
        int actualServerAddress = direction == TrafficDirection.ClientToServer ? destinationAddress : sourceAddress;

        if (pair.ClientProtocolAddressId.HasValue && pair.ClientProtocolAddressId.Value != actualClientAddress)
        {
            return false;
        }

        if (pair.ServerProtocolAddressId.HasValue && pair.ServerProtocolAddressId.Value != actualServerAddress)
        {
            return false;
        }

        return true;
    }

    private static bool TryMapIinErrorStatusCode(byte iin1, byte iin2, out TransactionStatusCode statusCode)
    {
        // IIN2 (Second byte / MSB of IIN):
        // Bit 0 (0x01): NO_FUNC_CODE_SUPPORT
        // Bit 1 (0x02): OBJECT_UNKNOWN
        // Bit 2 (0x04): PARAMETER_ERROR
        // Bit 3 (0x08): EVENT_BUFFER_OVERFLOW
        // Bit 4 (0x10): ALREADY_EXECUTING
        // Bit 5 (0x20): CONFIG_CORRUPT
        _ = iin1;

        if ((iin2 & 0x01) != 0)
        {
            statusCode = TransactionStatusCode.Dnp3IinFuncNotSupported;
            return true;
        }

        if ((iin2 & 0x02) != 0)
        {
            statusCode = TransactionStatusCode.Dnp3IinObjectUnknown;
            return true;
        }

        if ((iin2 & 0x04) != 0)
        {
            statusCode = TransactionStatusCode.Dnp3IinParamErr;
            return true;
        }

        if ((iin2 & 0x08) != 0)
        {
            statusCode = TransactionStatusCode.Dnp3IinEventBufferOverflow;
            return true;
        }

        if ((iin2 & 0x10) != 0)
        {
            statusCode = TransactionStatusCode.Dnp3IinAlreadyExecuting;
            return true;
        }

        if ((iin2 & 0x20) != 0)
        {
            statusCode = TransactionStatusCode.Dnp3IinConfigCorrupt;
            return true;
        }

        statusCode = TransactionStatusCode.Success;
        return false;
    }

    private ProtocolDecodeOutput CreateMalformedOutput(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction,
        string transactionId,
        short functionCode,
        ushort? sourceAddress,
        ushort? destinationAddress,
        Dnp3AppControl? appControl)
    {
        TraceId? traceId = null;
        SpanId? spanId = null;
        List<TraceSpanRecord> malformedSpans = [];

        if (_storeTraceSpans)
        {
            var ids = Dnp3SpanCorrelationIds.Allocate(pair, frame.FrameNumber, SpanCorrelationRole.Malformed);
            traceId = ids.TraceId;
            spanId = ids.SpanId;
            var metadata = new Dnp3FrameMetadata(
                frame,
                pair,
                direction,
                transactionId,
                functionCode,
                sourceAddress,
                destinationAddress,
                appControl);
            malformedSpans.Add(Dnp3SpanFactory.CreateMalformedSpan(metadata, ids));
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
            TraceId: traceId,
            SpanId: spanId);

        return new ProtocolDecodeOutput([malformedTx], [], [], [], malformedSpans);
    }
}
