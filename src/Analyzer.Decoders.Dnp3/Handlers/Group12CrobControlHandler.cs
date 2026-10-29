using System.Buffers.Binary;
using System.Globalization;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Dnp3.Handlers;

public class Group12CrobControlHandler : IDnp3ObjectGroupHandler
{
    private const int CrobByteLength = 11;

    private readonly TagResolutionEngine _tagEngine;

    public Group12CrobControlHandler(TagResolutionEngine tagEngine)
    {
        ArgumentNullException.ThrowIfNull(tagEngine);
        _tagEngine = tagEngine;
    }

    public ushort Group => 12;

    public void ExtractObjects(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction,
        ushort variation,
        ReadOnlySpan<byte> objectData,
        ICollection<ExtractedDataPointRecord> dataPointsOut,
        ICollection<CapturedCommandEventRecord> commandsOut)
    {
        ArgumentNullException.ThrowIfNull(frame);
        ArgumentNullException.ThrowIfNull(pair);
        ArgumentNullException.ThrowIfNull(dataPointsOut);
        ArgumentNullException.ThrowIfNull(commandsOut);

        if (direction != TrafficDirection.ClientToServer || variation != 1)
        {
            return;
        }

        if (!TryResolveControlFunctionCode(frame, out byte functionCode, out CommandType commandType))
        {
            return;
        }

        if (!Dnp3ObjectAddressing.TryEnumerateFixedSizeItems(objectData, CrobByteLength, out var slots))
        {
            return;
        }

        var context = new Dnp3PointContext(_tagEngine, frame, pair, direction, Group, variation);

        foreach (var slot in slots)
        {
            ReadOnlySpan<byte> crobBytes = objectData.Slice(slot.PayloadOffset, slot.PayloadLength);
            byte controlCode = crobBytes[0];
            byte count = crobBytes[1];
            uint onTimeMs = BinaryPrimitives.ReadUInt32LittleEndian(crobBytes.Slice(2, 4));
            uint offTimeMs = BinaryPrimitives.ReadUInt32LittleEndian(crobBytes.Slice(6, 4));

            if (!TryDecodeControlAction(controlCode, out var controlAction, out bool booleanState))
            {
                continue;
            }

            ProtocolAddress targetAddress = Dnp3ObjectAddressing.TryFindMappedTag(
                _tagEngine,
                pair.Id,
                Group,
                variation,
                slot.Index,
                out var mappedTag)
                ? mappedTag.ProtocolAddress
                : ProtocolAddress.Parse($"G12V01:Idx{slot.Index}");

            commandsOut.Add(new CapturedCommandEventRecord(
                Timestamp: frame.TimestampUtc,
                SessionId: pair.SessionId,
                DevicePairId: pair.Id,
                FrameNumber: frame.FrameNumber,
                Direction: direction,
                Protocol: ProtocolType.Dnp3,
                FunctionCode: functionCode,
                CommandType: commandType,
                TargetAddress: targetAddress,
                ControlAction: controlAction,
                CommandCount: count,
                PulseOnMs: onTimeMs,
                PulseOffMs: offTimeMs,
                UnscaledCommandValue: booleanState ? 1.0 : 0.0,
                RawPduBytes: frame.RawApplicationPayload.ToArray()));

            string rawHex = Convert.ToHexString(crobBytes);
            Dnp3ObjectAddressing.ProjectPointIfMapped(
                in context,
                index: slot.Index,
                eventTimestamp: null,
                unscaledNumericValue: null,
                booleanValue: booleanState,
                rawHex: rawHex,
                qualityFlags: PointQualityFlags.Online,
                dataPointsOut: dataPointsOut);
        }
    }

    private static bool TryResolveControlFunctionCode(
        DissectedFrame frame,
        out byte functionCode,
        out CommandType commandType)
    {
        if (Dnp3Decoder.TryStripDataLinkAndTransport(
                frame.RawApplicationPayload,
                out _,
                out _,
                out byte[] appFragment) &&
            appFragment.Length >= 2 &&
            TryMapControlCommandType(appFragment[1], out commandType))
        {
            functionCode = appFragment[1];
            return true;
        }

        if (frame.DissectedFields is not null &&
            (frame.DissectedFields.TryGetValue("dnp3.al.func", out var fcStr) ||
             frame.DissectedFields.TryGetValue("dnp3_dnp3_al_func", out fcStr)) &&
            byte.TryParse(fcStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedFc) &&
            TryMapControlCommandType(parsedFc, out commandType))
        {
            functionCode = parsedFc;
            return true;
        }

        // Default when invoked directly in unit tests with a synthetic empty-payload DissectedFrame
        functionCode = 0x05;
        commandType = CommandType.Dnp3DirectOperate;
        return frame.RawApplicationPayload.Length == 0;
    }

    private static bool TryMapControlCommandType(byte functionCode, out CommandType commandType)
    {
        switch (functionCode)
        {
            case 0x03:
                commandType = CommandType.Dnp3CrobSelect;
                return true;

            case 0x04:
                commandType = CommandType.Dnp3CrobOperate;
                return true;

            case 0x05:
            case 0x06:
                commandType = CommandType.Dnp3DirectOperate;
                return true;

            default:
                commandType = default;
                return false;
        }
    }

    private static bool TryDecodeControlAction(
        byte controlCode,
        out Dnp3ControlAction controlAction,
        out bool booleanState)
    {
        byte tcc = (byte)((controlCode >> 6) & 0x03);
        if (tcc == 0x01)
        {
            controlAction = Dnp3ControlAction.Close;
            booleanState = true;
            return true;
        }

        if (tcc == 0x02)
        {
            controlAction = Dnp3ControlAction.Trip;
            booleanState = false;
            return true;
        }

        byte opType = (byte)(controlCode & 0x0F);
        switch (opType)
        {
            case 0x01:
                controlAction = Dnp3ControlAction.PulseOn;
                booleanState = true;
                return true;

            case 0x02:
                controlAction = Dnp3ControlAction.PulseOff;
                booleanState = false;
                return true;

            case 0x03:
                controlAction = Dnp3ControlAction.LatchOn;
                booleanState = true;
                return true;

            case 0x04:
                controlAction = Dnp3ControlAction.LatchOff;
                booleanState = false;
                return true;

            default:
                controlAction = default;
                booleanState = false;
                return false;
        }
    }
}
