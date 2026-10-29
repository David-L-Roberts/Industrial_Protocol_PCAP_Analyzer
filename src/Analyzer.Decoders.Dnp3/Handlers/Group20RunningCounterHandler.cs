using System.Buffers.Binary;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Dnp3.Handlers;

public class Group20RunningCounterHandler : IDnp3ObjectGroupHandler
{
    private readonly TagResolutionEngine _tagEngine;

    public Group20RunningCounterHandler(TagResolutionEngine tagEngine)
    {
        ArgumentNullException.ThrowIfNull(tagEngine);
        _tagEngine = tagEngine;
    }

    public ushort Group => 20;

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
            PointQualityFlags qualityFlags;
            double unscaledValue;

            switch (variation)
            {
                case 1:
                    qualityFlags = Dnp3ObjectAddressing.DecodeCommonQualityFlags(itemBytes[0]);
                    unscaledValue = BinaryPrimitives.ReadUInt32LittleEndian(itemBytes.Slice(1, 4));
                    break;

                case 2:
                    qualityFlags = Dnp3ObjectAddressing.DecodeCommonQualityFlags(itemBytes[0]);
                    unscaledValue = BinaryPrimitives.ReadUInt16LittleEndian(itemBytes.Slice(1, 2));
                    break;

                case 5:
                    qualityFlags = PointQualityFlags.Online;
                    unscaledValue = BinaryPrimitives.ReadUInt32LittleEndian(itemBytes[..4]);
                    break;

                case 6:
                    qualityFlags = PointQualityFlags.Online;
                    unscaledValue = BinaryPrimitives.ReadUInt16LittleEndian(itemBytes[..2]);
                    break;

                default:
                    continue;
            }

            string rawHex = Convert.ToHexString(itemBytes);

            Dnp3ObjectAddressing.ProjectPointIfMapped(
                in context,
                index: slot.Index,
                eventTimestamp: null,
                unscaledNumericValue: unscaledValue,
                booleanValue: null,
                rawHex: rawHex,
                qualityFlags: qualityFlags,
                dataPointsOut: dataPointsOut);
        }
    }
}
