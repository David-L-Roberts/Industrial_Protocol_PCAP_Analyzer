using System.Buffers.Binary;
using System.Globalization;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Services;
using Analyzer.Decoders.Dnp3.Handlers;
using Analyzer.Decoders.Dnp3.Registry;

namespace Analyzer.Decoders.Dnp3;

public class Dnp3Decoder : IProtocolDecoder
{
    private const byte StartByte1 = 0x05;
    private const byte StartByte2 = 0x64;
    private const int MinLinkHeaderBytes = 10;
    private const int MinLinkLengthField = 5;
    private const byte AppSequenceMask = 0x0F;

    private readonly VirtualClockRedEngine _redEngine;
    private readonly Dnp3HandlerRegistry _handlerRegistry;

    public Dnp3Decoder(
        VirtualClockRedEngine redEngine,
        Dnp3HandlerRegistry handlerRegistry)
    {
        ArgumentNullException.ThrowIfNull(redEngine);
        ArgumentNullException.ThrowIfNull(handlerRegistry);
        _redEngine = redEngine;
        _handlerRegistry = handlerRegistry;
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
            return CreateMalformedOutput(frame, pair, direction, transactionId: "0", functionCode: 0);
        }

        if (!MatchesEndpointAddresses(pair, direction, sourceAddress, destinationAddress))
        {
            return new ProtocolDecodeOutput([], [], [], []);
        }

        ReadOnlySpan<byte> appSpan = appFragment;
        int minAppHeaderLen = direction == TrafficDirection.ServerToClient ? 4 : 2;
        if (appSpan.Length < minAppHeaderLen)
        {
            string partialSeq = appSpan.Length >= 1
                ? (appSpan[0] & AppSequenceMask).ToString(CultureInfo.InvariantCulture)
                : "0";
            short partialFc = appSpan.Length >= 2 ? appSpan[1] : (short)0;
            return CreateMalformedOutput(frame, pair, direction, partialSeq, partialFc);
        }

        byte appControl = appSpan[0];
        byte functionCode = appSpan[1];
        int appSeq = appControl & AppSequenceMask;
        string transactionId = appSeq.ToString(CultureInfo.InvariantCulture);

        int clientAddr = direction == TrafficDirection.ClientToServer ? sourceAddress : destinationAddress;
        int serverAddr = direction == TrafficDirection.ClientToServer ? destinationAddress : sourceAddress;
        string correlationKey = $"{clientAddr}:{serverAddr}:{transactionId}";

        var transactions = new List<ProtocolTransactionRecord>();
        var dataPoints = new List<ExtractedDataPointRecord>();
        var commandEvents = new List<CapturedCommandEventRecord>();

        if (direction == TrafficDirection.ClientToServer)
        {
            if (IsResponseExpectedRequestFunction(functionCode))
            {
                _redEngine.RegisterRequest(
                    sessionId: pair.SessionId,
                    devicePairId: pair.Id,
                    frameNumber: frame.FrameNumber,
                    timestampUtc: frame.TimestampUtc,
                    transactionId: transactionId,
                    functionCode: functionCode,
                    correlationKey: correlationKey);
            }

            if (IsPayloadBearingClientFunction(functionCode))
            {
                DispatchObjects(frame, pair, direction, appSpan[2..], dataPoints, commandEvents);
            }
        }
        else
        {
            byte iin1 = appSpan[2];
            byte iin2 = appSpan[3];
            bool isException = TryMapIinErrorStatusCode(iin1, iin2, out var statusCode);

            if (functionCode == 0x81 &&
                _redEngine.TryCompleteResponse(
                    devicePairId: pair.Id,
                    transactionId: transactionId,
                    responseFrameNumber: frame.FrameNumber,
                    responseTimestampUtc: frame.TimestampUtc,
                    responseFunctionCode: functionCode,
                    isException: isException,
                    statusCode: statusCode,
                    out var tx,
                    correlationKey: correlationKey))
            {
                transactions.Add(tx);
            }

            DispatchObjects(frame, pair, direction, appSpan[4..], dataPoints, commandEvents);
        }

        return new ProtocolDecodeOutput(transactions, dataPoints, commandEvents, []);
    }

    public IReadOnlyList<ProtocolTransactionRecord> FlushExpiredTimeouts(DateTime currentVirtualTime, bool isEndOfFile) =>
        _redEngine.FlushExpiredTimeouts(currentVirtualTime, isEndOfFile);

    private void DispatchObjects(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction,
        ReadOnlySpan<byte> objectsPayload,
        List<ExtractedDataPointRecord> dataPoints,
        List<CapturedCommandEventRecord> commandEvents)
    {
        int cursor = 0;

        while (cursor + 3 <= objectsPayload.Length)
        {
            ushort group = objectsPayload[cursor];
            ushort variation = objectsPayload[cursor + 1];
            ReadOnlySpan<byte> remainingFromQualifier = objectsPayload[(cursor + 2)..];

            if (!Dnp3ObjectAddressing.TryComputeObjectSectionLength(
                    group,
                    variation,
                    remainingFromQualifier,
                    out int sectionLength))
            {
                break;
            }

            ReadOnlySpan<byte> objectData = remainingFromQualifier[..sectionLength];
            if (_handlerRegistry.TryGetHandler(group, out var handler))
            {
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

    private static bool IsResponseExpectedRequestFunction(byte functionCode) =>
        functionCode is not (0x00 or 0x06); // Exclude Confirm (0x00) and Direct Operate No Ack (0x06)

    private static bool IsPayloadBearingClientFunction(byte functionCode) =>
        functionCode is 0x02 or 0x03 or 0x04 or 0x05 or 0x06; // Write, Select, Operate, DirectOperate, DirectOperateNoAck

    private static bool TryStripDataLinkAndTransport(
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

    private static ProtocolDecodeOutput CreateMalformedOutput(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction,
        string transactionId,
        short functionCode)
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
}

