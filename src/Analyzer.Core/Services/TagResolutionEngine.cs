using System.Diagnostics.CodeAnalysis;
using Analyzer.Core.Domain;

namespace Analyzer.Core.Services;

public class TagResolutionEngine
{
    private readonly record struct CachedTagState(
        double? ScaledNumericValue,
        bool? BooleanValue,
        PointQualityFlags QualityFlags);

    private readonly Dictionary<(Guid DevicePairId, ProtocolAddress ProtocolAddress), TagDefinition> _tagsByKey;
    private readonly Dictionary<Guid, CachedTagState> _lastKnownStateCache = new();
    private readonly Dictionary<Guid, TagInitialState> _initialStates = new();

    public TagResolutionEngine(IEnumerable<TagDefinition> tags)
    {
        ArgumentNullException.ThrowIfNull(tags);
        _tagsByKey = new Dictionary<(Guid, ProtocolAddress), TagDefinition>();
        foreach (var tag in tags)
        {
            _tagsByKey[(tag.DevicePairId, tag.ProtocolAddress)] = tag;
        }
    }

    public bool TryResolveAndProject(
        Guid sessionId,
        Guid devicePairId,
        ProtocolAddress protocolAddress,
        DateTime packetTimestamp,
        DateTime? eventTimestamp,
        long frameNumber,
        TrafficDirection direction,
        double? unscaledNumericValue,
        bool? booleanValue,
        string rawHex,
        PointQualityFlags qualityFlags,
        [NotNullWhen(true)] out ExtractedDataPointRecord? dataPoint)
    {
        if (!_tagsByKey.TryGetValue((devicePairId, protocolAddress), out var tag))
        {
            dataPoint = null;
            return false;
        }

        double? scaledValue = unscaledNumericValue.HasValue
            ? tag.ComputeScaledValue(unscaledNumericValue.Value)
            : null;

        var currentState = new CachedTagState(scaledValue, booleanValue, qualityFlags);
        bool isValueChange;

        if (!_lastKnownStateCache.TryGetValue(tag.Id, out var previousState))
        {
            isValueChange = true;
            _lastKnownStateCache[tag.Id] = currentState;
            _initialStates[tag.Id] = new TagInitialState(
                TagId: tag.Id,
                InitialUnscaledNumericValue: unscaledNumericValue,
                InitialScaledNumericValue: scaledValue,
                InitialBooleanValue: booleanValue,
                InitialRawHex: rawHex);
        }
        else if (!AreStatesEqual(previousState, currentState))
        {
            isValueChange = true;
            _lastKnownStateCache[tag.Id] = currentState;
        }
        else
        {
            isValueChange = false;
        }

        dataPoint = new ExtractedDataPointRecord(
            PacketTimestamp: packetTimestamp,
            EventTimestamp: eventTimestamp,
            SessionId: sessionId,
            TagId: tag.Id,
            FrameNumber: frameNumber,
            Direction: direction,
            UnscaledNumericValue: unscaledNumericValue,
            ScaledNumericValue: scaledValue,
            BooleanValue: booleanValue,
            RawHex: rawHex,
            QualityFlags: qualityFlags,
            IsValueChange: isValueChange);

        return true;
    }

    public IReadOnlyDictionary<Guid, TagInitialState> GetInitialStates() => _initialStates;

    private static bool AreStatesEqual(CachedTagState a, CachedTagState b) =>
        Nullable.Equals(a.ScaledNumericValue, b.ScaledNumericValue) &&
        a.BooleanValue == b.BooleanValue &&
        a.QualityFlags == b.QualityFlags;
}
