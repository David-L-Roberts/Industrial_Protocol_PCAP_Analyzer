using Analyzer.Core.Domain;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Dnp3.Handlers;

internal static class Dnp3BinaryGroupHelper
{
    public static void ExtractBinaryGroup(
        TagResolutionEngine tagEngine,
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction,
        ushort group,
        ushort variation,
        ReadOnlySpan<byte> objectData,
        ICollection<ExtractedDataPointRecord> dataPointsOut)
    {
        ArgumentNullException.ThrowIfNull(frame);
        ArgumentNullException.ThrowIfNull(pair);
        ArgumentNullException.ThrowIfNull(dataPointsOut);

        var context = new Dnp3PointContext(tagEngine, frame, pair, direction, group, variation);

        switch (variation)
        {
            case 1:
                ExtractPackedBinary(in context, objectData, dataPointsOut);
                break;

            case 2:
                ExtractFlaggedBinary(in context, objectData, dataPointsOut);
                break;
        }
    }

    private static void ExtractPackedBinary(
        in Dnp3PointContext context,
        ReadOnlySpan<byte> objectData,
        ICollection<ExtractedDataPointRecord> dataPointsOut)
    {
        if (!Dnp3ObjectAddressing.TryParsePackedBitHeader(
                objectData,
                out int startIndex,
                out int pointCount,
                out ReadOnlySpan<byte> packedBytes))
        {
            return;
        }

        for (int bitOffset = 0; bitOffset < pointCount; bitOffset++)
        {
            int pointIndex = startIndex + bitOffset;
            bool state = (packedBytes[bitOffset / 8] & (1 << (bitOffset % 8))) != 0;
            string rawHex = state ? "01" : "00";

            Dnp3ObjectAddressing.ProjectPointIfMapped(
                in context,
                index: pointIndex,
                eventTimestamp: null,
                unscaledNumericValue: null,
                booleanValue: state,
                rawHex: rawHex,
                qualityFlags: PointQualityFlags.Online,
                dataPointsOut: dataPointsOut);
        }
    }

    private static void ExtractFlaggedBinary(
        in Dnp3PointContext context,
        ReadOnlySpan<byte> objectData,
        ICollection<ExtractedDataPointRecord> dataPointsOut)
    {
        if (!Dnp3ObjectAddressing.TryEnumerateFixedSizeItems(
                objectData,
                itemSizeBytes: 1,
                out var slots))
        {
            return;
        }

        foreach (var slot in slots)
        {
            byte flagByte = objectData[slot.PayloadOffset];
            bool state = (flagByte & 0x80) != 0;
            PointQualityFlags qualityFlags = Dnp3ObjectAddressing.DecodeCommonQualityFlags(flagByte);
            string rawHex = Convert.ToHexString(objectData.Slice(slot.PayloadOffset, 1));

            Dnp3ObjectAddressing.ProjectPointIfMapped(
                in context,
                index: slot.Index,
                eventTimestamp: null,
                unscaledNumericValue: null,
                booleanValue: state,
                rawHex: rawHex,
                qualityFlags: qualityFlags,
                dataPointsOut: dataPointsOut);
        }
    }
}
