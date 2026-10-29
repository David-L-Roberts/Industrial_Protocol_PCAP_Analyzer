using System.Buffers.Binary;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Dnp3.Handlers;

public class Group32AnalogInputEventHandler : IDnp3ObjectGroupHandler
{
    private readonly TagResolutionEngine _tagEngine;

    public Group32AnalogInputEventHandler(TagResolutionEngine tagEngine)
    {
        ArgumentNullException.ThrowIfNull(tagEngine);
        _tagEngine = tagEngine;
    }

    public ushort Group => 32;

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

        int? itemSize = Dnp3ObjectAddressing.GetFixedObjectByteSize(Group, variation);
        if (!itemSize.HasValue ||
            !Dnp3ObjectAddressing.TryEnumerateFixedSizeItems(objectData, itemSize.Value, out var slots))
        {
            return;
        }

        var context = new Dnp3PointContext(_tagEngine, frame, pair, direction, Group, variation);

        foreach (var slot in slots)
        {
            ReadOnlySpan<byte> itemBytes = objectData.Slice(slot.PayloadOffset, slot.PayloadLength);
            PointQualityFlags qualityFlags = Dnp3ObjectAddressing.DecodeAnalogQualityFlags(itemBytes[0]);
            double unscaledValue;
            DateTime? eventTimestamp;

            switch (variation)
            {
                case 1:
                    unscaledValue = BinaryPrimitives.ReadInt32LittleEndian(itemBytes.Slice(1, 4));
                    eventTimestamp = null;
                    break;

                case 2:
                    unscaledValue = BinaryPrimitives.ReadInt16LittleEndian(itemBytes.Slice(1, 2));
                    eventTimestamp = null;
                    break;

                case 3:
                    unscaledValue = BinaryPrimitives.ReadInt32LittleEndian(itemBytes.Slice(1, 4));
                    eventTimestamp = Dnp3ObjectAddressing.DecodeDnp3Timestamp48(itemBytes.Slice(5, 6));
                    break;

                case 4:
                    unscaledValue = BinaryPrimitives.ReadInt16LittleEndian(itemBytes.Slice(1, 2));
                    eventTimestamp = Dnp3ObjectAddressing.DecodeDnp3Timestamp48(itemBytes.Slice(3, 6));
                    break;

                case 5:
                    unscaledValue = BinaryPrimitives.ReadSingleLittleEndian(itemBytes.Slice(1, 4));
                    eventTimestamp = null;
                    break;

                case 7:
                    unscaledValue = BinaryPrimitives.ReadSingleLittleEndian(itemBytes.Slice(1, 4));
                    eventTimestamp = Dnp3ObjectAddressing.DecodeDnp3Timestamp48(itemBytes.Slice(5, 6));
                    break;

                default:
                    continue;
            }

            string rawHex = Convert.ToHexString(itemBytes);

            Dnp3ObjectAddressing.ProjectPointIfMapped(
                in context,
                index: slot.Index,
                eventTimestamp: eventTimestamp,
                unscaledNumericValue: unscaledValue,
                booleanValue: null,
                rawHex: rawHex,
                qualityFlags: qualityFlags,
                dataPointsOut: dataPointsOut);
        }
    }
}
