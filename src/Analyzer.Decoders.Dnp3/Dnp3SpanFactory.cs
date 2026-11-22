using System.Globalization;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Dnp3;

internal readonly record struct Dnp3AppControl(
    bool Fir,
    bool Fin,
    bool Con,
    bool Uns,
    int Seq)
{
    private const byte FirMask = 0x80;
    private const byte FinMask = 0x40;
    private const byte ConMask = 0x20;
    private const byte UnsMask = 0x10;
    private const byte SeqMask = 0x0F;

    public static Dnp3AppControl Parse(byte appControl) =>
        new(
            Fir: (appControl & FirMask) != 0,
            Fin: (appControl & FinMask) != 0,
            Con: (appControl & ConMask) != 0,
            Uns: (appControl & UnsMask) != 0,
            Seq: appControl & SeqMask);
}

internal readonly record struct Dnp3ObjectGroupId(ushort Group, ushort Variation)
{
    public override string ToString() =>
        string.Create(CultureInfo.InvariantCulture, $"G{Group:D2}V{Variation:D2}");
}

internal readonly record struct Dnp3IinStatus(
    byte Iin1,
    byte Iin2,
    bool IsException,
    TransactionStatusCode StatusCode);

internal readonly record struct Dnp3SpanCorrelationIds(TraceId TraceId, SpanId SpanId)
{
    public static Dnp3SpanCorrelationIds Allocate(
        DeviceEndpointPair pair,
        long frameNumber,
        SpanCorrelationRole role) =>
        new(
            DeterministicTraceIdGenerator.CreateTraceId(pair.SessionId, pair.Id, frameNumber, role),
            DeterministicTraceIdGenerator.CreateSpanId(pair.SessionId, pair.Id, frameNumber, role));
}

internal readonly record struct Dnp3FrameMetadata(
    DissectedFrame Frame,
    DeviceEndpointPair Pair,
    TrafficDirection Direction,
    string TransactionId,
    short FunctionCode,
    ushort? SourceAddress,
    ushort? DestinationAddress,
    Dnp3AppControl? AppControl);

internal sealed class Dnp3TagChangeEventCollector
{
    public const int MaxEventsPerSpan = 10;

    public int MatchedCount { get; private set; }
    public int ChangedCount { get; private set; }
    public bool ChangesTruncated { get; private set; }
    public List<SpanEventRecord> Events { get; } = [];

    public void Record(IReadOnlyList<ExtractedDataPointRecord> dataPoints, TagResolutionEngine? tagEngine)
    {
        for (int i = 0; i < dataPoints.Count; i++)
        {
            var dp = dataPoints[i];
            MatchedCount++;

            if (!dp.IsValueChange)
            {
                continue;
            }

            ChangedCount++;

            if (Events.Count < MaxEventsPerSpan)
            {
                string tagName = tagEngine is not null && tagEngine.TryGetTagById(dp.TagId, out var tag)
                    ? tag.TagName
                    : dp.TagId.ToString("D");

                object? scaledValue = dp.BooleanValue.HasValue
                    ? dp.BooleanValue.Value
                    : dp.ScaledNumericValue;

                Events.Add(new SpanEventRecord(
                    TimestampUtc: dp.PacketTimestamp,
                    Kind: SpanEventKind.TagValueChanged,
                    Name: string.Empty,
                    Fields: new Dictionary<string, object?>
                    {
                        ["tag_name"] = tagName,
                        ["scaled_value"] = scaledValue,
                        ["quality_flags"] = dp.QualityFlags
                    }));
            }
            else
            {
                ChangesTruncated = true;
            }
        }
    }
}

internal static class Dnp3SpanFactory
{
    public const string MalformedOperationName = "DNP3 MalformedFrame";

    public static string FormatOperationName(byte functionCode) =>
        (Dnp3FunctionCode)functionCode switch
        {
            Dnp3FunctionCode.Confirm => "DNP3 FC00 Confirm",
            Dnp3FunctionCode.Read => "DNP3 FC01 Read",
            Dnp3FunctionCode.Write => "DNP3 FC02 Write",
            Dnp3FunctionCode.Select => "DNP3 FC03 Select",
            Dnp3FunctionCode.Operate => "DNP3 FC04 Operate",
            Dnp3FunctionCode.DirectOperate => "DNP3 FC05 DirectOperate",
            Dnp3FunctionCode.DirectOperateNoAck => "DNP3 FC06 DirectOperateNoAck",
            Dnp3FunctionCode.ColdRestart => "DNP3 FC13 ColdRestart",
            Dnp3FunctionCode.WarmRestart => "DNP3 FC14 WarmRestart",
            Dnp3FunctionCode.EnableUnsolicited => "DNP3 FC20 EnableUnsolicited",
            Dnp3FunctionCode.DisableUnsolicited => "DNP3 FC21 DisableUnsolicited",
            Dnp3FunctionCode.DelayMeasure => "DNP3 FC23 DelayMeasure",
            Dnp3FunctionCode.Response => "DNP3 FC129 Response",
            Dnp3FunctionCode.UnsolicitedResponse => "DNP3 FC130 UnsolicitedResponse",
            _ => string.Create(CultureInfo.InvariantCulture, $"DNP3 FC{functionCode:D2} Unknown")
        };

    public static string FormatIinErrorStatusMessage(TransactionStatusCode statusCode) => statusCode switch
    {
        TransactionStatusCode.Dnp3IinFuncNotSupported => "DNP3_IIN_FUNC_NOT_SUPPORTED",
        TransactionStatusCode.Dnp3IinObjectUnknown => "DNP3_IIN_OBJECT_UNKNOWN",
        TransactionStatusCode.Dnp3IinParamErr => "DNP3_IIN_PARAM_ERR",
        TransactionStatusCode.Dnp3IinEventBufferOverflow => "DNP3_IIN_EVENT_BUFFER_OVERFLOW",
        TransactionStatusCode.Dnp3IinAlreadyExecuting => "DNP3_IIN_ALREADY_EXECUTING",
        TransactionStatusCode.Dnp3IinConfigCorrupt => "DNP3_IIN_CONFIG_CORRUPT",
        _ => "DNP3_IIN_ERROR"
    };

    public static PendingSpanContext CreateRequestPendingSpanContext(
        Dnp3FrameMetadata metadata,
        Dnp3SpanCorrelationIds ids,
        IReadOnlyList<Dnp3ObjectGroupId> objectGroups,
        IReadOnlyList<CapturedCommandEventRecord> commandEvents,
        Dnp3TagChangeEventCollector? requestTagCollector)
    {
        string clientEndpoint = metadata.Pair.ResolveClientEndpoint();
        string serverEndpoint = metadata.Pair.ResolveServerEndpoint();

        var attributes = CreateBaseAttributes(metadata);
        attributes["pcap.request_frame"] = metadata.Frame.FrameNumber;
        attributes["pcap.request_bytes"] = metadata.Frame.RawApplicationPayload.Length;
        PopulateDnp3Attributes(attributes, metadata, objectGroups, commandEvents);

        if (requestTagCollector is { MatchedCount: > 0 })
        {
            PopulateTagSummaryAttributes(
                attributes,
                requestTagCollector.MatchedCount,
                requestTagCollector.ChangedCount,
                requestTagCollector.ChangesTruncated);
        }

        var events = new List<SpanEventRecord>
        {
            CreateFrameMilestoneEvent(metadata.Frame, SpanEventKind.RequestSent)
        };

        AppendCommandEvents(events, metadata.Frame.TimestampUtc, commandEvents);

        if (requestTagCollector is not null)
        {
            events.AddRange(requestTagCollector.Events);
        }

        return new PendingSpanContext(
            TraceId: ids.TraceId,
            SpanId: ids.SpanId,
            ParentSpanId: null,
            ServiceName: serverEndpoint,
            OperationName: FormatOperationName((byte)metadata.FunctionCode),
            Protocol: ProtocolType.Dnp3,
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
        byte requestFunctionCode,
        Dnp3AppControl responseAppControl,
        Dnp3IinStatus iinStatus,
        IReadOnlyList<Dnp3ObjectGroupId> responseObjectGroups,
        IReadOnlyList<CapturedCommandEventRecord> responseCommands,
        Dnp3TagChangeEventCollector? requestTagCollector,
        Dnp3TagChangeEventCollector? responseTagCollector)
    {
        var attributes = new Dictionary<string, object?>(spanContext.Attributes)
        {
            ["pcap.response_frame"] = responseFrame.FrameNumber,
            ["pcap.response_bytes"] = responseFrame.RawApplicationPayload.Length,
            ["dnp3.iin1"] = (int)iinStatus.Iin1,
            ["dnp3.iin2"] = (int)iinStatus.Iin2
        };

        PopulateAppControlFlags(attributes, responseAppControl);

        if (responseObjectGroups.Count > 0)
        {
            attributes["dnp3.object_groups"] = FormatObjectGroupList(responseObjectGroups);
        }

        if (!attributes.ContainsKey("dnp3.target_address") && responseCommands.Count > 0)
        {
            attributes["dnp3.target_address"] = responseCommands[0].TargetAddress;
        }

        int totalMatched = (requestTagCollector?.MatchedCount ?? 0) + (responseTagCollector?.MatchedCount ?? 0);
        int totalChanged = (requestTagCollector?.ChangedCount ?? 0) + (responseTagCollector?.ChangedCount ?? 0);
        bool truncated = (requestTagCollector?.ChangesTruncated ?? false) ||
                         (responseTagCollector?.ChangesTruncated ?? false) ||
                         totalChanged > Dnp3TagChangeEventCollector.MaxEventsPerSpan;

        PopulateTagSummaryAttributes(attributes, totalMatched, totalChanged, truncated);

        var events = new List<SpanEventRecord>(
            spanContext.Events.Count + 2 + responseCommands.Count + (responseTagCollector?.Events.Count ?? 0));
        events.AddRange(spanContext.Events);
        events.Add(CreateFrameMilestoneEvent(responseFrame, SpanEventKind.ResponseReceived));

        if (iinStatus.IsException)
        {
            events.Add(CreateProtocolExceptionEvent(responseFrame.TimestampUtc, iinStatus));
        }

        if (responseCommands.Count > 0)
        {
            AppendCommandEvents(events, responseFrame.TimestampUtc, responseCommands);
        }

        if (responseTagCollector is not null)
        {
            int existingTagEvents = requestTagCollector?.Events.Count ?? 0;
            int remainingSlots = Math.Max(0, Dnp3TagChangeEventCollector.MaxEventsPerSpan - existingTagEvents);
            for (int i = 0; i < responseTagCollector.Events.Count && i < remainingSlots; i++)
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
            StatusCode: iinStatus.IsException ? SpanStatusCode.Error : SpanStatusCode.Ok,
            StatusMessage: iinStatus.IsException ? FormatIinErrorStatusMessage(iinStatus.StatusCode) : null,
            Protocol: ProtocolType.Dnp3,
            ClientEndpoint: spanContext.ClientEndpoint,
            ServerEndpoint: spanContext.ServerEndpoint,
            Direction: spanContext.Direction,
            RequestFrameNumber: spanContext.RequestFrameNumber,
            ResponseFrameNumber: responseFrame.FrameNumber,
            TransactionId: transaction.TransactionId,
            FunctionCode: (short)requestFunctionCode,
            Attributes: attributes,
            Events: events);
    }

    public static TraceSpanRecord CreateUnsolicitedSpan(
        Dnp3FrameMetadata metadata,
        Dnp3SpanCorrelationIds ids,
        Dnp3IinStatus iinStatus,
        IReadOnlyList<Dnp3ObjectGroupId> objectGroups,
        IReadOnlyList<CapturedCommandEventRecord> commandEvents,
        Dnp3TagChangeEventCollector tagCollector) =>
        CreateServerResponseSpan(
            metadata,
            ids,
            SpanOriginKind.Unsolicited,
            iinStatus,
            objectGroups,
            commandEvents,
            tagCollector);

    public static TraceSpanRecord CreateOrphanResponseSpan(
        Dnp3FrameMetadata metadata,
        Dnp3SpanCorrelationIds ids,
        Dnp3IinStatus iinStatus,
        IReadOnlyList<Dnp3ObjectGroupId> objectGroups,
        IReadOnlyList<CapturedCommandEventRecord> commandEvents,
        Dnp3TagChangeEventCollector tagCollector) =>
        CreateServerResponseSpan(
            metadata,
            ids,
            SpanOriginKind.OrphanResponse,
            iinStatus,
            objectGroups,
            commandEvents,
            tagCollector);

    private static TraceSpanRecord CreateServerResponseSpan(
        Dnp3FrameMetadata metadata,
        Dnp3SpanCorrelationIds ids,
        SpanOriginKind originKind,
        Dnp3IinStatus iinStatus,
        IReadOnlyList<Dnp3ObjectGroupId> objectGroups,
        IReadOnlyList<CapturedCommandEventRecord> commandEvents,
        Dnp3TagChangeEventCollector tagCollector)
    {
        string clientEndpoint = metadata.Pair.ResolveClientEndpoint();
        string serverEndpoint = metadata.Pair.ResolveServerEndpoint();
        bool isOrphan = originKind == SpanOriginKind.OrphanResponse;

        var attributes = CreateBaseAttributes(metadata);
        attributes["pcap.response_frame"] = metadata.Frame.FrameNumber;
        attributes["pcap.response_bytes"] = metadata.Frame.RawApplicationPayload.Length;
        PopulateDnp3Attributes(attributes, metadata, objectGroups, commandEvents);
        attributes["dnp3.iin1"] = (int)iinStatus.Iin1;
        attributes["dnp3.iin2"] = (int)iinStatus.Iin2;
        if (isOrphan)
        {
            attributes["protocol.unpaired"] = true;
        }

        PopulateTagSummaryAttributes(
            attributes,
            tagCollector.MatchedCount,
            tagCollector.ChangedCount,
            tagCollector.ChangesTruncated);

        var events = new List<SpanEventRecord>(2 + tagCollector.Events.Count)
        {
            CreateFrameMilestoneEvent(metadata.Frame, SpanEventKind.ResponseReceived)
        };

        if (iinStatus.IsException)
        {
            events.Add(CreateProtocolExceptionEvent(metadata.Frame.TimestampUtc, iinStatus));
        }

        events.AddRange(tagCollector.Events);

        var spanStatusCode = iinStatus.IsException
            ? SpanStatusCode.Error
            : (isOrphan ? SpanStatusCode.Unset : SpanStatusCode.Ok);
        string? statusMessage = iinStatus.IsException
            ? FormatIinErrorStatusMessage(iinStatus.StatusCode)
            : (isOrphan ? "ORPHAN_RESPONSE" : null);

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
            OriginKind: originKind,
            StatusCode: spanStatusCode,
            StatusMessage: statusMessage,
            Protocol: ProtocolType.Dnp3,
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

    public static TraceSpanRecord CreateDirectNoAckSpan(
        Dnp3FrameMetadata metadata,
        Dnp3SpanCorrelationIds ids,
        IReadOnlyList<Dnp3ObjectGroupId> objectGroups,
        IReadOnlyList<CapturedCommandEventRecord> commandEvents,
        Dnp3TagChangeEventCollector tagCollector)
    {
        string clientEndpoint = metadata.Pair.ResolveClientEndpoint();
        string serverEndpoint = metadata.Pair.ResolveServerEndpoint();

        var attributes = CreateBaseAttributes(metadata);
        attributes["pcap.request_frame"] = metadata.Frame.FrameNumber;
        attributes["pcap.request_bytes"] = metadata.Frame.RawApplicationPayload.Length;
        PopulateDnp3Attributes(attributes, metadata, objectGroups, commandEvents);
        PopulateTagSummaryAttributes(
            attributes,
            tagCollector.MatchedCount,
            tagCollector.ChangedCount,
            tagCollector.ChangesTruncated);

        var events = new List<SpanEventRecord>(2 + commandEvents.Count + tagCollector.Events.Count)
        {
            CreateFrameMilestoneEvent(metadata.Frame, SpanEventKind.RequestSent)
        };

        if (commandEvents.Count > 0)
        {
            AppendCommandEvents(events, metadata.Frame.TimestampUtc, commandEvents);
        }
        else
        {
            events.Add(new SpanEventRecord(
                TimestampUtc: metadata.Frame.TimestampUtc,
                Kind: SpanEventKind.CommandIssued,
                Name: string.Empty,
                Fields: new Dictionary<string, object?>
                {
                    ["function_code"] = (int)Dnp3FunctionCode.DirectOperateNoAck
                }));
        }

        events.AddRange(tagCollector.Events);

        return new TraceSpanRecord(
            StartTimeUtc: metadata.Frame.TimestampUtc,
            EndTimeUtc: metadata.Frame.TimestampUtc,
            DurationMs: 0.0,
            SessionId: metadata.Pair.SessionId,
            DevicePairId: metadata.Pair.Id,
            TraceId: ids.TraceId,
            SpanId: ids.SpanId,
            ParentSpanId: null,
            ServiceName: serverEndpoint,
            OperationName: FormatOperationName((byte)Dnp3FunctionCode.DirectOperateNoAck),
            SpanKind: SpanKind.Producer,
            OriginKind: SpanOriginKind.DirectNoAck,
            StatusCode: SpanStatusCode.Ok,
            StatusMessage: null,
            Protocol: ProtocolType.Dnp3,
            ClientEndpoint: clientEndpoint,
            ServerEndpoint: serverEndpoint,
            Direction: TrafficDirection.ClientToServer,
            RequestFrameNumber: metadata.Frame.FrameNumber,
            ResponseFrameNumber: null,
            TransactionId: metadata.TransactionId,
            FunctionCode: metadata.FunctionCode,
            Attributes: attributes,
            Events: events);
    }

    public static TraceSpanRecord CreateMalformedSpan(
        Dnp3FrameMetadata metadata,
        Dnp3SpanCorrelationIds ids)
    {
        string clientEndpoint = metadata.Pair.ResolveClientEndpoint();
        string serverEndpoint = metadata.Pair.ResolveServerEndpoint();
        bool isClientToServer = metadata.Direction == TrafficDirection.ClientToServer;

        var attributes = CreateBaseAttributes(metadata);
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

        PopulateDnp3Attributes(attributes, metadata, [], []);

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
            Protocol: ProtocolType.Dnp3,
            ClientEndpoint: clientEndpoint,
            ServerEndpoint: serverEndpoint,
            Direction: metadata.Direction,
            RequestFrameNumber: isClientToServer ? metadata.Frame.FrameNumber : null,
            ResponseFrameNumber: isClientToServer ? null : metadata.Frame.FrameNumber,
            TransactionId: metadata.TransactionId,
            FunctionCode: metadata.FunctionCode,
            Attributes: attributes,
            Events: []);
    }

    private static Dictionary<string, object?> CreateBaseAttributes(Dnp3FrameMetadata metadata)
    {
        bool isClientToServer = metadata.Direction == TrafficDirection.ClientToServer;
        string clientIp = (isClientToServer ? metadata.Frame.SourceIp : metadata.Frame.DestIp).ToString();
        int clientPort = isClientToServer ? metadata.Frame.SourcePort : metadata.Frame.DestPort;
        string serverIp = (isClientToServer ? metadata.Frame.DestIp : metadata.Frame.SourceIp).ToString();
        int serverPort = isClientToServer ? metadata.Frame.DestPort : metadata.Frame.SourcePort;

        return new Dictionary<string, object?>
        {
            ["protocol"] = ProtocolType.Dnp3,
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

    private static void PopulateDnp3Attributes(
        Dictionary<string, object?> attributes,
        Dnp3FrameMetadata metadata,
        IReadOnlyList<Dnp3ObjectGroupId> objectGroups,
        IReadOnlyList<CapturedCommandEventRecord> commandEvents)
    {
        if (metadata.SourceAddress.HasValue)
        {
            attributes["dnp3.src"] = (int)metadata.SourceAddress.Value;
        }

        if (metadata.DestinationAddress.HasValue)
        {
            attributes["dnp3.dst"] = (int)metadata.DestinationAddress.Value;
        }

        if (metadata.AppControl is { } appControl)
        {
            attributes["dnp3.app_seq"] = appControl.Seq;
            PopulateAppControlFlags(attributes, appControl);
        }

        if (objectGroups.Count > 0)
        {
            attributes["dnp3.object_groups"] = FormatObjectGroupList(objectGroups);
        }

        if (commandEvents.Count > 0)
        {
            attributes["dnp3.target_address"] = commandEvents[0].TargetAddress;
        }
    }

    private static string FormatObjectGroupList(IReadOnlyList<Dnp3ObjectGroupId> objectGroups) =>
        string.Join(",", objectGroups.Select(static g => g.ToString()));

    private static void PopulateAppControlFlags(Dictionary<string, object?> attributes, Dnp3AppControl appControl)
    {
        attributes["dnp3.fir"] = appControl.Fir;
        attributes["dnp3.fin"] = appControl.Fin;
        attributes["dnp3.con"] = appControl.Con;
        attributes["dnp3.uns"] = appControl.Uns;
    }

    private static void PopulateTagSummaryAttributes(
        Dictionary<string, object?> attributes,
        int matchedCount,
        int changedCount,
        bool changesTruncated)
    {
        attributes["tags.matched_count"] = matchedCount;
        attributes["tags.changed_count"] = changedCount;
        if (changesTruncated)
        {
            attributes["tags.changes_truncated"] = true;
        }
    }

    private static void AppendCommandEvents(
        List<SpanEventRecord> events,
        DateTime timestampUtc,
        IReadOnlyList<CapturedCommandEventRecord> commandEvents)
    {
        for (int i = 0; i < commandEvents.Count; i++)
        {
            var cmd = commandEvents[i];
            var fields = new Dictionary<string, object?>
            {
                ["command_type"] = cmd.CommandType,
                ["target_address"] = cmd.TargetAddress
            };

            if (cmd.ControlAction.HasValue)
            {
                fields["control_action"] = cmd.ControlAction.Value;
            }

            if (cmd.CommandCount.HasValue)
            {
                fields["command_count"] = (int)cmd.CommandCount.Value;
            }

            if (cmd.PulseOnMs.HasValue)
            {
                fields["pulse_on_ms"] = cmd.PulseOnMs.Value;
            }

            if (cmd.PulseOffMs.HasValue)
            {
                fields["pulse_off_ms"] = cmd.PulseOffMs.Value;
            }

            if (cmd.UnscaledCommandValue.HasValue)
            {
                fields["unscaled_value"] = cmd.UnscaledCommandValue.Value;
            }

            events.Add(new SpanEventRecord(
                TimestampUtc: timestampUtc,
                Kind: SpanEventKind.CommandIssued,
                Name: string.Empty,
                Fields: fields));
        }
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

    private static SpanEventRecord CreateProtocolExceptionEvent(DateTime timestampUtc, Dnp3IinStatus iinStatus) =>
        new(
            TimestampUtc: timestampUtc,
            Kind: SpanEventKind.ProtocolException,
            Name: string.Empty,
            Fields: new Dictionary<string, object?>
            {
                ["status_code"] = iinStatus.StatusCode,
                ["iin1"] = (int)iinStatus.Iin1,
                ["iin2"] = (int)iinStatus.Iin2
            });
}
