using System.Globalization;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Modbus;

internal readonly record struct SpanCorrelationIds(TraceId TraceId, SpanId SpanId)
{
    public static SpanCorrelationIds Allocate(DeviceEndpointPair pair, long frameNumber, SpanCorrelationRole role) =>
        new(
            DeterministicTraceIdGenerator.CreateTraceId(pair.SessionId, pair.Id, frameNumber, role),
            DeterministicTraceIdGenerator.CreateSpanId(pair.SessionId, pair.Id, frameNumber, role));
}

internal readonly record struct ModbusFrameMetadata(
    DissectedFrame Frame,
    DeviceEndpointPair Pair,
    string TransactionId,
    byte? UnitId,
    short FunctionCode);

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

    public static string FormatOperationName(byte baseFunctionCode) =>
        (ModbusFunctionCode)baseFunctionCode switch
        {
            ModbusFunctionCode.ReadCoils => "Modbus FC01 ReadCoils",
            ModbusFunctionCode.ReadDiscreteInputs => "Modbus FC02 ReadDiscreteInputs",
            ModbusFunctionCode.ReadHoldingRegisters => "Modbus FC03 ReadHoldingRegisters",
            ModbusFunctionCode.ReadInputRegisters => "Modbus FC04 ReadInputRegisters",
            ModbusFunctionCode.WriteSingleCoil => "Modbus FC05 WriteSingleCoil",
            ModbusFunctionCode.WriteSingleRegister => "Modbus FC06 WriteSingleRegister",
            ModbusFunctionCode.WriteMultipleCoils => "Modbus FC15 WriteMultipleCoils",
            ModbusFunctionCode.WriteMultipleRegisters => "Modbus FC16 WriteMultipleRegisters",
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
        ModbusFrameMetadata metadata,
        SpanCorrelationIds ids,
        ModbusRegisterType registerType,
        ushort startAddress,
        ushort quantity,
        CapturedCommandEventRecord? writeCommand = null,
        TagChangeEventCollector? writeTagCollector = null)
    {
        string clientEndpoint = metadata.Pair.ResolveClientEndpoint();
        string serverEndpoint = metadata.Pair.ResolveServerEndpoint();

        var attributes = CreateBaseAttributes(metadata, TrafficDirection.ClientToServer);
        attributes["pcap.request_frame"] = metadata.Frame.FrameNumber;
        attributes["pcap.request_bytes"] = metadata.Frame.RawApplicationPayload.Length;
        if (metadata.UnitId.HasValue)
        {
            attributes["modbus.unit_id"] = (int)metadata.UnitId.Value;
        }
        attributes["modbus.register_type"] = registerType;
        attributes["modbus.start_address"] = (int)startAddress;
        attributes["modbus.quantity"] = (int)quantity;

        var events = new List<SpanEventRecord>
        {
            CreateFrameMilestoneEvent(metadata.Frame, SpanEventKind.RequestSent)
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
                TimestampUtc: metadata.Frame.TimestampUtc,
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
            TraceId: ids.TraceId,
            SpanId: ids.SpanId,
            ParentSpanId: null,
            ServiceName: serverEndpoint,
            OperationName: FormatOperationName((byte)metadata.FunctionCode),
            Protocol: ProtocolType.ModbusTcp,
            ClientEndpoint: clientEndpoint,
            ServerEndpoint: serverEndpoint,
            Attributes: attributes,
            Events: events,
            SpanKind: SpanKind.Client,
            Direction: TrafficDirection.ClientToServer,
            RequestTimestampUtc: metadata.Frame.TimestampUtc,
            RequestFrameNumber: metadata.Frame.FrameNumber);
    }

    public static TraceSpanRecord CreateResponseSpan(
        DissectedFrame responseFrame,
        ProtocolTransactionRecord transaction,
        PendingSpanContext spanContext,
        byte baseFunctionCode,
        bool isException,
        byte? exceptionCode,
        TagChangeEventCollector? writeTagCollector,
        TagChangeEventCollector? responseTagCollector)
    {
        var attributes = new Dictionary<string, object?>(spanContext.Attributes)
        {
            ["pcap.response_frame"] = responseFrame.FrameNumber,
            ["pcap.response_bytes"] = responseFrame.RawApplicationPayload.Length
        };

        int totalMatched = (writeTagCollector?.MatchedCount ?? 0) + (responseTagCollector?.MatchedCount ?? 0);
        int totalChanged = (writeTagCollector?.ChangedCount ?? 0) + (responseTagCollector?.ChangedCount ?? 0);

        attributes["tags.matched_count"] = totalMatched;
        attributes["tags.changed_count"] = totalChanged;

        if ((writeTagCollector?.ChangesTruncated ?? false) ||
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
        events.AddRange(spanContext.Events);
        events.Add(CreateFrameMilestoneEvent(responseFrame, SpanEventKind.ResponseReceived));

        if (isException)
        {
            events.Add(CreateProtocolExceptionEvent(responseFrame.TimestampUtc, exceptionCode, transaction.StatusCode));
        }

        if (responseTagCollector is not null)
        {
            int existingTagEvents = writeTagCollector?.Events.Count ?? 0;
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
        ModbusFrameMetadata metadata,
        ModbusRegisterType? registerType,
        bool isException,
        byte? exceptionCode,
        TransactionStatusCode? exceptionStatusCode)
    {
        var ids = SpanCorrelationIds.Allocate(metadata.Pair, metadata.Frame.FrameNumber, SpanCorrelationRole.OrphanResponse);
        string clientEndpoint = metadata.Pair.ResolveClientEndpoint();
        string serverEndpoint = metadata.Pair.ResolveServerEndpoint();

        var attributes = CreateBaseAttributes(metadata, TrafficDirection.ServerToClient);
        attributes["pcap.response_frame"] = metadata.Frame.FrameNumber;
        attributes["pcap.response_bytes"] = metadata.Frame.RawApplicationPayload.Length;
        if (metadata.UnitId.HasValue)
        {
            attributes["modbus.unit_id"] = (int)metadata.UnitId.Value;
        }
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
            CreateFrameMilestoneEvent(metadata.Frame, SpanEventKind.ResponseReceived)
        };

        if (isException && exceptionStatusCode.HasValue)
        {
            events.Add(CreateProtocolExceptionEvent(metadata.Frame.TimestampUtc, exceptionCode, exceptionStatusCode.Value));
        }

        return new TraceSpanRecord(
            StartTimeUtc: metadata.Frame.TimestampUtc,
            EndTimeUtc: metadata.Frame.TimestampUtc,
            DurationMs: 0.0,
            SessionId: metadata.Pair.SessionId,
            DevicePairId: metadata.Pair.Id,
            TraceId: ids.TraceId,
            SpanId: ids.SpanId,
            ParentSpanId: null,
            ServiceName: clientEndpoint,
            OperationName: FormatOperationName((byte)metadata.FunctionCode),
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
            ResponseFrameNumber: metadata.Frame.FrameNumber,
            TransactionId: metadata.TransactionId,
            FunctionCode: metadata.FunctionCode,
            Attributes: attributes,
            Events: events);
    }

    public static TraceSpanRecord CreateMalformedSpan(
        ModbusFrameMetadata metadata,
        TrafficDirection direction,
        SpanCorrelationIds ids)
    {
        string clientEndpoint = metadata.Pair.ResolveClientEndpoint();
        string serverEndpoint = metadata.Pair.ResolveServerEndpoint();
        bool isClientToServer = direction == TrafficDirection.ClientToServer;

        var attributes = CreateBaseAttributes(metadata, direction);
        if (isClientToServer)
        {
            attributes["pcap.request_frame"] = metadata.Frame.FrameNumber;
            attributes["pcap.request_bytes"] = metadata.Frame.RawApplicationPayload.Length;
        }
        else
        {
            attributes["pcap.response_frame"] = metadata.Frame.FrameNumber;
            attributes["pcap.response_bytes"] = metadata.Frame.RawApplicationPayload.Length;
        }

        if (metadata.UnitId.HasValue)
        {
            attributes["modbus.unit_id"] = (int)metadata.UnitId.Value;
        }

        return new TraceSpanRecord(
            StartTimeUtc: metadata.Frame.TimestampUtc,
            EndTimeUtc: metadata.Frame.TimestampUtc,
            DurationMs: 0.0,
            SessionId: metadata.Pair.SessionId,
            DevicePairId: metadata.Pair.Id,
            TraceId: ids.TraceId,
            SpanId: ids.SpanId,
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
            RequestFrameNumber: isClientToServer ? metadata.Frame.FrameNumber : null,
            ResponseFrameNumber: isClientToServer ? null : metadata.Frame.FrameNumber,
            TransactionId: metadata.TransactionId,
            FunctionCode: metadata.FunctionCode,
            Attributes: attributes,
            Events: []);
    }

    private static Dictionary<string, object?> CreateBaseAttributes(
        ModbusFrameMetadata metadata,
        TrafficDirection direction)
    {
        bool isClientToServer = direction == TrafficDirection.ClientToServer;
        string clientIp = (isClientToServer ? metadata.Frame.SourceIp : metadata.Frame.DestIp).ToString();
        int clientPort = isClientToServer ? metadata.Frame.SourcePort : metadata.Frame.DestPort;
        string serverIp = (isClientToServer ? metadata.Frame.DestIp : metadata.Frame.SourceIp).ToString();
        int serverPort = isClientToServer ? metadata.Frame.DestPort : metadata.Frame.SourcePort;

        return new Dictionary<string, object?>
        {
            ["protocol"] = ProtocolType.ModbusTcp,
            ["session.id"] = metadata.Pair.SessionId,
            ["device_pair.id"] = metadata.Pair.Id,
            ["device_pair.name"] = metadata.Pair.Name,
            ["net.client.ip"] = clientIp,
            ["net.client.port"] = clientPort,
            ["net.server.ip"] = serverIp,
            ["net.server.port"] = serverPort,
            ["protocol.function_code"] = (int)metadata.FunctionCode,
            ["protocol.transaction_id"] = metadata.TransactionId
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
}
