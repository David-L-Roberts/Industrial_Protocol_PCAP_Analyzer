using System.Globalization;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Modbus;

internal sealed class TagChangeEventCollector
{
    public const int MaxEventsPerSpan = 10;

    public int MatchedCount { get; private set; }
    public int ChangedCount { get; private set; }
    public bool ChangesTruncated { get; private set; }
    public List<SpanEventRecord> Events { get; } = [];

    public void Record(TagDefinition tag, ExtractedDataPointRecord dataPoint)
    {
        MatchedCount++;

        if (!dataPoint.IsValueChange)
        {
            return;
        }

        ChangedCount++;

        if (Events.Count < MaxEventsPerSpan)
        {
            object? scaledValue = dataPoint.BooleanValue.HasValue
                ? dataPoint.BooleanValue.Value
                : dataPoint.ScaledNumericValue;

            Events.Add(new SpanEventRecord(
                TimestampUtc: dataPoint.PacketTimestamp,
                Kind: SpanEventKind.TagValueChanged,
                Name: string.Empty,
                Fields: new Dictionary<string, object?>
                {
                    ["tag_name"] = tag.TagName,
                    ["scaled_value"] = scaledValue,
                    ["quality_flags"] = dataPoint.QualityFlags
                }));
        }
        else
        {
            ChangesTruncated = true;
        }
    }
}

internal static class ModbusSpanFactory
{
    public const string MalformedOperationName = "Modbus MalformedFrame";

    public static string FormatOperationName(byte baseFunctionCode) => baseFunctionCode switch
    {
        0x01 => "Modbus FC01 ReadCoils",
        0x02 => "Modbus FC02 ReadDiscreteInputs",
        0x03 => "Modbus FC03 ReadHoldingRegisters",
        0x04 => "Modbus FC04 ReadInputRegisters",
        0x05 => "Modbus FC05 WriteSingleCoil",
        0x06 => "Modbus FC06 WriteSingleRegister",
        0x0F => "Modbus FC15 WriteMultipleCoils",
        0x10 => "Modbus FC16 WriteMultipleRegisters",
        _ => string.Create(CultureInfo.InvariantCulture, $"Modbus FC{baseFunctionCode:D2} Unknown")
    };

    public static string FormatExceptionStatusMessage(TransactionStatusCode statusCode) => statusCode switch
    {
        TransactionStatusCode.ModbusEx01 => "MODBUS_EX_01",
        TransactionStatusCode.ModbusEx02 => "MODBUS_EX_02",
        TransactionStatusCode.ModbusEx03 => "MODBUS_EX_03",
        TransactionStatusCode.ModbusEx04 => "MODBUS_EX_04",
        TransactionStatusCode.ModbusEx05 => "MODBUS_EX_05",
        TransactionStatusCode.ModbusEx06 => "MODBUS_EX_06",
        TransactionStatusCode.ModbusEx08 => "MODBUS_EX_08",
        TransactionStatusCode.ModbusEx0A => "MODBUS_EX_0A",
        TransactionStatusCode.ModbusEx0B => "MODBUS_EX_0B",
        _ => "MODBUS_EX_UNKNOWN"
    };

    public static PendingSpanContext CreateRequestPendingSpanContext(
        DissectedFrame requestFrame,
        DeviceEndpointPair pair,
        TraceId traceId,
        SpanId spanId,
        string transactionId,
        byte unitId,
        byte functionCode,
        ModbusRegisterType registerType,
        ushort startAddress,
        ushort quantity,
        CapturedCommandEventRecord? writeCommand = null,
        TagChangeEventCollector? writeTagCollector = null)
    {
        string clientEndpoint = pair.ResolveClientEndpoint();
        string serverEndpoint = pair.ResolveServerEndpoint();

        var attributes = CreateBaseAttributes(
            requestFrame,
            pair,
            TrafficDirection.ClientToServer,
            transactionId,
            functionCode);

        attributes["pcap.request_frame"] = requestFrame.FrameNumber;
        attributes["pcap.request_bytes"] = requestFrame.RawApplicationPayload.Length;
        attributes["modbus.unit_id"] = (int)unitId;
        attributes["modbus.register_type"] = registerType;
        attributes["modbus.start_address"] = (int)startAddress;
        attributes["modbus.quantity"] = (int)quantity;

        var events = new List<SpanEventRecord>
        {
            CreateFrameMilestoneEvent(requestFrame, SpanEventKind.RequestSent)
        };

        if (writeCommand is not null)
        {
            var cmdFields = new Dictionary<string, object?>
            {
                ["command_type"] = writeCommand.CommandType,
                ["target_address"] = writeCommand.TargetAddress
            };

            if (writeCommand.CommandCount.HasValue)
            {
                cmdFields["command_count"] = (int)writeCommand.CommandCount.Value;
            }

            if (writeCommand.UnscaledCommandValue.HasValue)
            {
                cmdFields["unscaled_value"] = writeCommand.UnscaledCommandValue.Value;
            }

            events.Add(new SpanEventRecord(
                TimestampUtc: requestFrame.TimestampUtc,
                Kind: SpanEventKind.CommandIssued,
                Name: string.Empty,
                Fields: cmdFields));
        }

        if (writeTagCollector is not null && writeTagCollector.MatchedCount > 0)
        {
            attributes["tags.matched_count"] = writeTagCollector.MatchedCount;
            attributes["tags.changed_count"] = writeTagCollector.ChangedCount;
            if (writeTagCollector.ChangesTruncated)
            {
                attributes["tags.changes_truncated"] = true;
            }

            events.AddRange(writeTagCollector.Events);
        }

        return new PendingSpanContext(
            TraceId: traceId,
            SpanId: spanId,
            ParentSpanId: null,
            ServiceName: serverEndpoint,
            OperationName: FormatOperationName(functionCode),
            Protocol: ProtocolType.ModbusTcp,
            ClientEndpoint: clientEndpoint,
            ServerEndpoint: serverEndpoint,
            Attributes: attributes,
            Events: events,
            SpanKind: SpanKind.Client,
            Direction: TrafficDirection.ClientToServer,
            RequestTimestampUtc: requestFrame.TimestampUtc,
            RequestFrameNumber: requestFrame.FrameNumber);
    }

    public static TraceSpanRecord CreateResponseSpan(
        DissectedFrame responseFrame,
        ProtocolTransactionRecord transaction,
        PendingSpanContext spanContext,
        byte baseFunctionCode,
        bool isException,
        byte? exceptionCode,
        TagChangeEventCollector? responseTagCollector)
    {
        var attributes = new Dictionary<string, object?>(spanContext.Attributes)
        {
            ["pcap.response_frame"] = responseFrame.FrameNumber,
            ["pcap.response_bytes"] = responseFrame.RawApplicationPayload.Length
        };

        int existingMatched = GetIntAttribute(attributes, "tags.matched_count");
        int existingChanged = GetIntAttribute(attributes, "tags.changed_count");
        bool existingTruncated = GetBoolAttribute(attributes, "tags.changes_truncated");

        int totalMatched = existingMatched + (responseTagCollector?.MatchedCount ?? 0);
        int totalChanged = existingChanged + (responseTagCollector?.ChangedCount ?? 0);

        attributes["tags.matched_count"] = totalMatched;
        attributes["tags.changed_count"] = totalChanged;

        if (existingTruncated ||
            (responseTagCollector?.ChangesTruncated ?? false) ||
            totalChanged > TagChangeEventCollector.MaxEventsPerSpan)
        {
            attributes["tags.changes_truncated"] = true;
        }

        if (isException && exceptionCode.HasValue)
        {
            attributes["modbus.exception_code"] = (int)exceptionCode.Value;
        }

        var events = new List<SpanEventRecord>(spanContext.Events.Count + 2 + (responseTagCollector?.Events.Count ?? 0));
        int existingTagEvents = 0;
        foreach (var existing in spanContext.Events)
        {
            events.Add(existing);
            if (existing.Kind == SpanEventKind.TagValueChanged)
            {
                existingTagEvents++;
            }
        }

        events.Add(CreateFrameMilestoneEvent(responseFrame, SpanEventKind.ResponseReceived));

        if (isException)
        {
            events.Add(CreateProtocolExceptionEvent(responseFrame.TimestampUtc, exceptionCode, transaction.StatusCode));
        }

        if (responseTagCollector is not null)
        {
            int remainingTagSlots = Math.Max(0, TagChangeEventCollector.MaxEventsPerSpan - existingTagEvents);
            for (int i = 0; i < responseTagCollector.Events.Count && i < remainingTagSlots; i++)
            {
                events.Add(responseTagCollector.Events[i]);
            }
        }

        DateTime startUtc = spanContext.RequestTimestampUtc == default
            ? responseFrame.TimestampUtc
            : spanContext.RequestTimestampUtc;

        return new TraceSpanRecord(
            StartTimeUtc: startUtc,
            EndTimeUtc: responseFrame.TimestampUtc,
            DurationMs: transaction.DurationMs ?? Math.Max(0.0, (responseFrame.TimestampUtc - startUtc).TotalMilliseconds),
            SessionId: transaction.SessionId,
            DevicePairId: transaction.DevicePairId,
            TraceId: spanContext.TraceId,
            SpanId: spanContext.SpanId,
            ParentSpanId: spanContext.ParentSpanId,
            ServiceName: spanContext.ServiceName,
            OperationName: spanContext.OperationName,
            SpanKind: spanContext.SpanKind,
            OriginKind: SpanOriginKind.RequestResponse,
            StatusCode: isException ? SpanStatusCode.Error : SpanStatusCode.Ok,
            StatusMessage: isException ? FormatExceptionStatusMessage(transaction.StatusCode) : null,
            Protocol: ProtocolType.ModbusTcp,
            ClientEndpoint: spanContext.ClientEndpoint,
            ServerEndpoint: spanContext.ServerEndpoint,
            Direction: spanContext.Direction,
            RequestFrameNumber: spanContext.RequestFrameNumber,
            ResponseFrameNumber: responseFrame.FrameNumber,
            TransactionId: transaction.TransactionId,
            FunctionCode: (short)baseFunctionCode,
            Attributes: attributes,
            Events: events);
    }

    public static TraceSpanRecord CreateOrphanResponseSpan(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        string transactionId,
        byte unitId,
        byte baseFunctionCode,
        ModbusRegisterType? registerType,
        bool isException,
        byte? exceptionCode,
        TransactionStatusCode? exceptionStatusCode)
    {
        var traceId = DeterministicTraceIdGenerator.CreateTraceId(
            pair.SessionId,
            pair.Id,
            frame.FrameNumber,
            SpanCorrelationRole.OrphanResponse);
        var spanId = DeterministicTraceIdGenerator.CreateSpanId(
            pair.SessionId,
            pair.Id,
            frame.FrameNumber,
            SpanCorrelationRole.OrphanResponse);

        string clientEndpoint = pair.ResolveClientEndpoint();
        string serverEndpoint = pair.ResolveServerEndpoint();

        var attributes = CreateBaseAttributes(
            frame,
            pair,
            TrafficDirection.ServerToClient,
            transactionId,
            baseFunctionCode);

        attributes["pcap.response_frame"] = frame.FrameNumber;
        attributes["pcap.response_bytes"] = frame.RawApplicationPayload.Length;
        attributes["modbus.unit_id"] = (int)unitId;
        attributes["protocol.unpaired"] = true;

        if (registerType.HasValue)
        {
            attributes["modbus.register_type"] = registerType.Value;
        }

        if (isException && exceptionCode.HasValue)
        {
            attributes["modbus.exception_code"] = (int)exceptionCode.Value;
        }

        var events = new List<SpanEventRecord>
        {
            CreateFrameMilestoneEvent(frame, SpanEventKind.ResponseReceived)
        };

        if (isException && exceptionStatusCode.HasValue)
        {
            events.Add(CreateProtocolExceptionEvent(frame.TimestampUtc, exceptionCode, exceptionStatusCode.Value));
        }

        return new TraceSpanRecord(
            StartTimeUtc: frame.TimestampUtc,
            EndTimeUtc: frame.TimestampUtc,
            DurationMs: 0.0,
            SessionId: pair.SessionId,
            DevicePairId: pair.Id,
            TraceId: traceId,
            SpanId: spanId,
            ParentSpanId: null,
            ServiceName: clientEndpoint,
            OperationName: FormatOperationName(baseFunctionCode),
            SpanKind: SpanKind.Consumer,
            OriginKind: SpanOriginKind.OrphanResponse,
            StatusCode: isException ? SpanStatusCode.Error : SpanStatusCode.Unset,
            StatusMessage: isException && exceptionStatusCode.HasValue
                ? FormatExceptionStatusMessage(exceptionStatusCode.Value)
                : "ORPHAN_RESPONSE",
            Protocol: ProtocolType.ModbusTcp,
            ClientEndpoint: clientEndpoint,
            ServerEndpoint: serverEndpoint,
            Direction: TrafficDirection.ServerToClient,
            RequestFrameNumber: null,
            ResponseFrameNumber: frame.FrameNumber,
            TransactionId: transactionId,
            FunctionCode: (short)baseFunctionCode,
            Attributes: attributes,
            Events: events);
    }

    public static TraceSpanRecord CreateMalformedSpan(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction,
        TraceId traceId,
        SpanId spanId,
        string transactionId,
        short functionCode,
        byte? unitId)
    {
        string clientEndpoint = pair.ResolveClientEndpoint();
        string serverEndpoint = pair.ResolveServerEndpoint();
        bool isClientToServer = direction == TrafficDirection.ClientToServer;

        var attributes = CreateBaseAttributes(frame, pair, direction, transactionId, functionCode);
        if (isClientToServer)
        {
            attributes["pcap.request_frame"] = frame.FrameNumber;
            attributes["pcap.request_bytes"] = frame.RawApplicationPayload.Length;
        }
        else
        {
            attributes["pcap.response_frame"] = frame.FrameNumber;
            attributes["pcap.response_bytes"] = frame.RawApplicationPayload.Length;
        }

        if (unitId.HasValue)
        {
            attributes["modbus.unit_id"] = (int)unitId.Value;
        }

        return new TraceSpanRecord(
            StartTimeUtc: frame.TimestampUtc,
            EndTimeUtc: frame.TimestampUtc,
            DurationMs: 0.0,
            SessionId: pair.SessionId,
            DevicePairId: pair.Id,
            TraceId: traceId,
            SpanId: spanId,
            ParentSpanId: null,
            ServiceName: isClientToServer ? serverEndpoint : clientEndpoint,
            OperationName: MalformedOperationName,
            SpanKind: isClientToServer ? SpanKind.Client : SpanKind.Consumer,
            OriginKind: SpanOriginKind.Malformed,
            StatusCode: SpanStatusCode.Error,
            StatusMessage: "MALFORMED",
            Protocol: ProtocolType.ModbusTcp,
            ClientEndpoint: clientEndpoint,
            ServerEndpoint: serverEndpoint,
            Direction: direction,
            RequestFrameNumber: isClientToServer ? frame.FrameNumber : null,
            ResponseFrameNumber: isClientToServer ? null : frame.FrameNumber,
            TransactionId: transactionId,
            FunctionCode: functionCode,
            Attributes: attributes,
            Events: []);
    }

    private static Dictionary<string, object?> CreateBaseAttributes(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction,
        string transactionId,
        int functionCode)
    {
        bool isClientToServer = direction == TrafficDirection.ClientToServer;
        string clientIp = (isClientToServer ? frame.SourceIp : frame.DestIp).ToString();
        int clientPort = isClientToServer ? frame.SourcePort : frame.DestPort;
        string serverIp = (isClientToServer ? frame.DestIp : frame.SourceIp).ToString();
        int serverPort = isClientToServer ? frame.DestPort : frame.SourcePort;

        return new Dictionary<string, object?>
        {
            ["protocol"] = ProtocolType.ModbusTcp,
            ["session.id"] = pair.SessionId,
            ["device_pair.id"] = pair.Id,
            ["device_pair.name"] = pair.Name,
            ["net.client.ip"] = clientIp,
            ["net.client.port"] = clientPort,
            ["net.server.ip"] = serverIp,
            ["net.server.port"] = serverPort,
            ["protocol.function_code"] = functionCode,
            ["protocol.transaction_id"] = transactionId
        };
    }

    private static SpanEventRecord CreateFrameMilestoneEvent(DissectedFrame frame, SpanEventKind kind) =>
        new(
            TimestampUtc: frame.TimestampUtc,
            Kind: kind,
            Name: string.Empty,
            Fields: new Dictionary<string, object?>
            {
                ["frame_number"] = frame.FrameNumber,
                ["bytes"] = frame.RawApplicationPayload.Length
            });

    private static SpanEventRecord CreateProtocolExceptionEvent(
        DateTime timestampUtc,
        byte? exceptionCode,
        TransactionStatusCode statusCode)
    {
        var fields = new Dictionary<string, object?>
        {
            ["status_code"] = statusCode
        };

        if (exceptionCode.HasValue)
        {
            fields["exception_code"] = (int)exceptionCode.Value;
        }

        return new SpanEventRecord(
            TimestampUtc: timestampUtc,
            Kind: SpanEventKind.ProtocolException,
            Name: string.Empty,
            Fields: fields);
    }

    private static int GetIntAttribute(IReadOnlyDictionary<string, object?> attributes, string key) =>
        attributes.TryGetValue(key, out object? raw) && raw is int value ? value : 0;

    private static bool GetBoolAttribute(IReadOnlyDictionary<string, object?> attributes, string key) =>
        attributes.TryGetValue(key, out object? raw) && raw is bool value && value;
}
