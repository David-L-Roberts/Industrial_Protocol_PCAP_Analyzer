using System.Buffers.Binary;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Dnp3.Handlers;

public class Group2BinaryInputEventHandler : IDnp3ObjectGroupHandler
{
    private readonly TagResolutionEngine _tagEngine;

    public Group2BinaryInputEventHandler(TagResolutionEngine tagEngine)
    {
        ArgumentNullException.ThrowIfNull(tagEngine);
        _tagEngine = tagEngine;
    }

    public ushort Group => 2;

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
            byte flagByte = itemBytes[0];
            bool state = (flagByte & 0x80) != 0;
            PointQualityFlags qualityFlags = Dnp3ObjectAddressing.DecodeCommonQualityFlags(flagByte);
            DateTime? eventTimestamp;

            switch (variation)
            {
                case 1:
                    eventTimestamp = null;
                    break;

                case 2:
                    eventTimestamp = Dnp3ObjectAddressing.DecodeDnp3Timestamp48(itemBytes.Slice(1, 6));
                    break;

                case 3:
                    ushort relativeMs = BinaryPrimitives.ReadUInt16LittleEndian(itemBytes.Slice(1, 2));
                    eventTimestamp = frame.TimestampUtc.AddMilliseconds(relativeMs);
                    break;

                default:
                    continue;
            }

            string rawHex = Convert.ToHexString(itemBytes);

            Dnp3ObjectAddressing.ProjectPointIfMapped(
                in context,
                index: slot.Index,
                eventTimestamp: eventTimestamp,
                unscaledNumericValue: null,
                booleanValue: state,
                rawHex: rawHex,
                qualityFlags: qualityFlags,
                dataPointsOut: dataPointsOut);
        }
    }
}
