using System.Buffers.Binary;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Dnp3.Handlers;

internal readonly record struct Dnp3PointSlot(
    int Index,
    int PayloadOffset,
    int PayloadLength);

internal readonly record struct Dnp3PointContext(
    TagResolutionEngine TagEngine,
    DissectedFrame Frame,
    DeviceEndpointPair Pair,
    TrafficDirection Direction,
    ushort Group,
    ushort Variation);

internal static class Dnp3ObjectAddressing
{
    private readonly record struct ParsedRangeHeader(
        byte RangeCode,
        int PrefixSize,
        int StartIndex,
        int ItemCount,
        int HeaderAndRangeBytes);

    public static bool TryComputeObjectSectionLength(
        ushort group,
        ushort variation,
        ReadOnlySpan<byte> remainingFromQualifier,
        out int totalObjectSectionBytes)
    {
        totalObjectSectionBytes = 0;

        if (!TryParseRangeHeader(remainingFromQualifier, out var range))
        {
            return false;
        }

        if (range.RangeCode == 0x06)
        {
            totalObjectSectionBytes = 1;
            return true;
        }

        if (IsPackedSingleBitVariation(group, variation))
        {
            if (range.PrefixSize != 0)
            {
                return false;
            }

            int packedBytes = (range.ItemCount + 7) / 8;
            totalObjectSectionBytes = range.HeaderAndRangeBytes + packedBytes;
            return remainingFromQualifier.Length >= totalObjectSectionBytes;
        }

        int? itemSize = GetFixedObjectByteSize(group, variation);
        if (!itemSize.HasValue)
        {
            totalObjectSectionBytes = remainingFromQualifier.Length;
            return true;
        }

        totalObjectSectionBytes = range.HeaderAndRangeBytes + (range.ItemCount * (range.PrefixSize + itemSize.Value));
        return remainingFromQualifier.Length >= totalObjectSectionBytes;
    }

    public static bool TryParsePackedBitHeader(
        ReadOnlySpan<byte> objectData,
        out int startIndex,
        out int pointCount,
        out ReadOnlySpan<byte> packedBytes)
    {
        startIndex = 0;
        pointCount = 0;
        packedBytes = default;

        if (!TryParseRangeHeader(objectData, out var range) ||
            range.PrefixSize != 0 ||
            range.RangeCode is not (0x00 or 0x01))
        {
            return false;
        }

        int requiredPackedBytes = (range.ItemCount + 7) / 8;
        if (objectData.Length < range.HeaderAndRangeBytes + requiredPackedBytes)
        {
            return false;
        }

        startIndex = range.StartIndex;
        pointCount = range.ItemCount;
        packedBytes = objectData.Slice(range.HeaderAndRangeBytes, requiredPackedBytes);
        return true;
    }

    public static bool TryEnumerateFixedSizeItems(
        ReadOnlySpan<byte> objectData,
        int itemSizeBytes,
        out List<Dnp3PointSlot> slots)
    {
        slots = [];

        if (itemSizeBytes <= 0 || !TryParseRangeHeader(objectData, out var range))
        {
            return false;
        }

        if (range.RangeCode is 0x07 or 0x08 && range.PrefixSize == 0)
        {
            return false;
        }

        if (range.RangeCode == 0x06)
        {
            return false;
        }

        int cursor = range.HeaderAndRangeBytes;
        int stride = range.PrefixSize + itemSizeBytes;
        if (objectData.Length < cursor + (range.ItemCount * stride))
        {
            return false;
        }

        slots.Capacity = range.ItemCount;
        for (int i = 0; i < range.ItemCount; i++)
        {
            int pointIndex = range.PrefixSize switch
            {
                0 => range.StartIndex + i,
                1 => objectData[cursor],
                2 => BinaryPrimitives.ReadUInt16LittleEndian(objectData.Slice(cursor, 2)),
                4 => (int)BinaryPrimitives.ReadUInt32LittleEndian(objectData.Slice(cursor, 4)),
                _ => range.StartIndex + i
            };

            int payloadOffset = cursor + range.PrefixSize;
            slots.Add(new Dnp3PointSlot(pointIndex, payloadOffset, itemSizeBytes));
            cursor += stride;
        }

        return true;
    }

    public static PointQualityFlags DecodeCommonQualityFlags(byte rawFlags) =>
        (PointQualityFlags)(rawFlags & 0x3F);

    public static PointQualityFlags DecodeAnalogQualityFlags(byte rawFlags) =>
        (PointQualityFlags)(rawFlags & 0xFF);

    public static void ProjectPointIfMapped(
        in Dnp3PointContext context,
        int index,
        DateTime? eventTimestamp,
        double? unscaledNumericValue,
        bool? booleanValue,
        string rawHex,
        PointQualityFlags qualityFlags,
        ICollection<ExtractedDataPointRecord> dataPointsOut)
    {
        if (!TryFindMappedTag(context.TagEngine, context.Pair.Id, context.Group, context.Variation, index, out var tag))
        {
            return;
        }

        double? effectiveNumeric = unscaledNumericValue;
        bool? effectiveBool = booleanValue;

        if (tag.DataType == TagDataType.Bool && effectiveBool is null && effectiveNumeric.HasValue)
        {
            effectiveBool = effectiveNumeric.Value != 0.0;
            effectiveNumeric = null;
        }
        else if (tag.DataType != TagDataType.Bool && effectiveNumeric is null && effectiveBool.HasValue)
        {
            effectiveNumeric = effectiveBool.Value ? 1.0 : 0.0;
            effectiveBool = null;
        }

        if (context.TagEngine.TryResolveAndProject(
                sessionId: context.Pair.SessionId,
                devicePairId: context.Pair.Id,
                protocolAddress: tag.ProtocolAddress,
                packetTimestamp: context.Frame.TimestampUtc,
                eventTimestamp: eventTimestamp,
                frameNumber: context.Frame.FrameNumber,
                direction: context.Direction,
                unscaledNumericValue: effectiveNumeric,
                booleanValue: effectiveBool,
                rawHex: rawHex,
                qualityFlags: qualityFlags,
                out var dp))
        {
            dataPointsOut.Add(dp);
        }
    }

    public static bool TryFindMappedTag(
        TagResolutionEngine tagEngine,
        Guid devicePairId,
        ushort group,
        ushort variation,
        int index,
        out TagDefinition tag)
    {
        Span<string> candidates =
        [
            $"G{group:D2}V{variation:D2}:Idx{index}",
            $"G{group}V{variation:D2}:Idx{index}",
            $"G{group:D2}V{variation}:Idx{index}",
            $"G{group}V{variation}:Idx{index}"
        ];

        foreach (var candidate in candidates)
        {
            if (ProtocolAddress.TryParse(candidate, out var addr) &&
                tagEngine.TryGetTag(devicePairId, addr, out var found) &&
                found is not null)
            {
                tag = found;
                return true;
            }
        }

        tag = default!;
        return false;
    }

    public static int? GetFixedObjectByteSize(ushort group, ushort variation) =>
        (group, variation) switch
        {
            (1, 2) => 1,
            (2, 1) => 1,
            (2, 2) => 7,
            (2, 3) => 3,
            (10, 2) => 1,
            (12, 1) => 11,
            (20, 1) => 5,
            (20, 2) => 3,
            (20, 5) => 4,
            (20, 6) => 2,
            (22, 1) => 5,
            (22, 2) => 3,
            (22, 5) => 11,
            (22, 6) => 9,
            (30, 1) => 5,
            (30, 2) => 3,
            (30, 3) => 4,
            (30, 4) => 2,
            (30, 5) => 5,
            (32, 1) => 5,
            (32, 2) => 3,
            (32, 3) => 11,
            (32, 4) => 9,
            (32, 5) => 5,
            (32, 7) => 11,
            (50, 1) => 6,
            (60, _) => 0,
            _ => null
        };

    private static bool TryParseRangeHeader(ReadOnlySpan<byte> data, out ParsedRangeHeader header)
    {
        header = default;
        if (data.Length < 1)
        {
            return false;
        }

        byte qualifier = data[0];
        if (!TryGetPrefixSize(qualifier, out int prefixSize))
        {
            return false;
        }

        byte rangeCode = (byte)(qualifier & 0x0F);

        switch (rangeCode)
        {
            case 0x00:
                if (data.Length < 3)
                {
                    return false;
                }

                byte start8 = data[1];
                byte stop8 = data[2];
                if (stop8 < start8)
                {
                    return false;
                }

                header = new ParsedRangeHeader(rangeCode, prefixSize, start8, stop8 - start8 + 1, 3);
                return true;

            case 0x01:
                if (data.Length < 5)
                {
                    return false;
                }

                ushort start16 = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(1, 2));
                ushort stop16 = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(3, 2));
                if (stop16 < start16)
                {
                    return false;
                }

                header = new ParsedRangeHeader(rangeCode, prefixSize, start16, stop16 - start16 + 1, 5);
                return true;

            case 0x06:
                header = new ParsedRangeHeader(rangeCode, prefixSize, 0, 0, 1);
                return true;

            case 0x07:
                if (data.Length < 2)
                {
                    return false;
                }

                header = new ParsedRangeHeader(rangeCode, prefixSize, 0, data[1], 2);
                return true;

            case 0x08:
                if (data.Length < 3)
                {
                    return false;
                }

                ushort count16 = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(1, 2));
                header = new ParsedRangeHeader(rangeCode, prefixSize, 0, count16, 3);
                return true;

            default:
                return false;
        }
    }

    private static bool TryGetPrefixSize(byte qualifier, out int prefixSize)
    {
        byte indexSizeCode = (byte)((qualifier >> 4) & 0x07);
        switch (indexSizeCode)
        {
            case 0:
                prefixSize = 0;
                return true;
            case 1:
                prefixSize = 1;
                return true;
            case 2:
                prefixSize = 2;
                return true;
            case 3:
                prefixSize = 4;
                return true;
            default:
                prefixSize = 0;
                return false;
        }
    }

    private static bool IsPackedSingleBitVariation(ushort group, ushort variation) =>
        (group == 1 && variation == 1) || (group == 10 && variation == 1);
}
