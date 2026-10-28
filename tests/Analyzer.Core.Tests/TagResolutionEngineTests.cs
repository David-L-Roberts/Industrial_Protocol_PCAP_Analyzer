using Analyzer.Core.Domain;
using Analyzer.Core.Services;

namespace Analyzer.Core.Tests;

public class TagResolutionEngineTests
{
    [Fact]
    public void TryResolveAndProject_FirstObservationOfMappedNumericTag_ScalesValueMarksValueChangeAndCapturesInitialState()
    {
        var sessionId = Guid.NewGuid();
        var pairId = Guid.NewGuid();
        var tagId = Guid.NewGuid();
        var address = ProtocolAddress.Parse("G30V02:Idx0");
        var tag = new TagDefinition(
            Id: tagId,
            DevicePairId: pairId,
            TagName: "Feeder_MW",
            ProtocolAddress: address,
            DataType: TagDataType.Int16,
            ScaleMultiplier: 0.01,
            ScaleOffset: 2.5,
            EngineeringUnits: "MW",
            Description: "Active Power");

        var engine = new TagResolutionEngine([tag]);
        var packetTime = new DateTime(2026, 10, 26, 10, 0, 0, DateTimeKind.Utc);
        var eventTime = new DateTime(2026, 10, 26, 9, 59, 59, 500, DateTimeKind.Utc);

        var resolved = engine.TryResolveAndProject(
            sessionId: sessionId,
            devicePairId: pairId,
            protocolAddress: address,
            packetTimestamp: packetTime,
            eventTimestamp: eventTime,
            frameNumber: 42,
            direction: TrafficDirection.ServerToClient,
            unscaledNumericValue: 1500.0,
            booleanValue: null,
            rawHex: "DC05",
            qualityFlags: PointQualityFlags.Online,
            out var dataPoint);

        Assert.True(resolved);
        Assert.NotNull(dataPoint);
        Assert.Equal(packetTime, dataPoint.PacketTimestamp);
        Assert.Equal(eventTime, dataPoint.EventTimestamp);
        Assert.Equal(sessionId, dataPoint.SessionId);
        Assert.Equal(tagId, dataPoint.TagId);
        Assert.Equal(42, dataPoint.FrameNumber);
        Assert.Equal(TrafficDirection.ServerToClient, dataPoint.Direction);
        Assert.Equal(1500.0, dataPoint.UnscaledNumericValue);
        Assert.Equal(17.5, dataPoint.ScaledNumericValue!.Value, precision: 5);
        Assert.Null(dataPoint.BooleanValue);
        Assert.Equal("DC05", dataPoint.RawHex);
        Assert.Equal(PointQualityFlags.Online, dataPoint.QualityFlags);
        Assert.True(dataPoint.IsValueChange);

        var initialStates = engine.GetInitialStates();
        Assert.True(initialStates.TryGetValue(tagId, out var t0));
        Assert.Equal(1500.0, t0.InitialUnscaledNumericValue);
        Assert.Equal(17.5, t0.InitialScaledNumericValue!.Value, precision: 5);
        Assert.Null(t0.InitialBooleanValue);
        Assert.Equal("DC05", t0.InitialRawHex);
    }

    [Fact]
    public void TryResolveAndProject_SubsequentObservations_TracksValueBooleanAndQualityChangesWhilePreservingT0()
    {
        var sessionId = Guid.NewGuid();
        var pairId = Guid.NewGuid();
        var numTagId = Guid.NewGuid();
        var boolTagId = Guid.NewGuid();
        var numAddr = ProtocolAddress.Parse("HR:40001");
        var boolAddr = ProtocolAddress.Parse("COIL:00005");
        var unmappedAddr = ProtocolAddress.Parse("HR:49999");

        var numTag = new TagDefinition(
            Id: numTagId,
            DevicePairId: pairId,
            TagName: "Bus_Volts_A",
            ProtocolAddress: numAddr,
            DataType: TagDataType.UInt16,
            ScaleMultiplier: 0.1,
            ScaleOffset: 0.0,
            EngineeringUnits: "kV",
            Description: null);

        var boolTag = new TagDefinition(
            Id: boolTagId,
            DevicePairId: pairId,
            TagName: "Breaker_52A",
            ProtocolAddress: boolAddr,
            DataType: TagDataType.Bool,
            ScaleMultiplier: 1.0,
            ScaleOffset: 0.0,
            EngineeringUnits: null,
            Description: null);

        var engine = new TagResolutionEngine([numTag, boolTag]);
        var t0Time = new DateTime(2026, 10, 26, 10, 0, 0, DateTimeKind.Utc);

        // 1. Unmapped address returns false
        Assert.False(engine.TryResolveAndProject(
            sessionId, pairId, unmappedAddr, t0Time, null, 1, TrafficDirection.ServerToClient,
            100.0, null, "0064", PointQualityFlags.Online, out var unmappedPoint));
        Assert.Null(unmappedPoint);

        // 2. First numeric observation -> IsValueChange = true, sets T0
        Assert.True(engine.TryResolveAndProject(
            sessionId, pairId, numAddr, t0Time, null, 2, TrafficDirection.ServerToClient,
            1380.0, null, "0564", PointQualityFlags.Online, out var dp1));
        Assert.True(dp1!.IsValueChange);

        // 3. Second numeric observation with identical value & quality -> IsValueChange = false
        Assert.True(engine.TryResolveAndProject(
            sessionId, pairId, numAddr, t0Time.AddSeconds(1), null, 3, TrafficDirection.ServerToClient,
            1380.0, null, "0564", PointQualityFlags.Online, out var dp2));
        Assert.False(dp2!.IsValueChange);

        // 4. Third numeric observation with changed quality -> IsValueChange = true
        Assert.True(engine.TryResolveAndProject(
            sessionId, pairId, numAddr, t0Time.AddSeconds(2), null, 4, TrafficDirection.ServerToClient,
            1380.0, null, "0564", PointQualityFlags.Online | PointQualityFlags.CommLost, out var dp3));
        Assert.True(dp3!.IsValueChange);

        // 5. Fourth numeric observation with changed numeric value -> IsValueChange = true, T0 unchanged
        Assert.True(engine.TryResolveAndProject(
            sessionId, pairId, numAddr, t0Time.AddSeconds(3), null, 5, TrafficDirection.ServerToClient,
            1400.0, null, "0578", PointQualityFlags.Online | PointQualityFlags.CommLost, out var dp4));
        Assert.True(dp4!.IsValueChange);
        Assert.Equal(140.0, dp4.ScaledNumericValue!.Value, precision: 5);

        // 6. Boolean observations: first (true), same (false), toggled (true)
        Assert.True(engine.TryResolveAndProject(
            sessionId, pairId, boolAddr, t0Time, null, 6, TrafficDirection.ServerToClient,
            null, false, "00", PointQualityFlags.Online, out var b1));
        Assert.True(b1!.IsValueChange);

        Assert.True(engine.TryResolveAndProject(
            sessionId, pairId, boolAddr, t0Time.AddSeconds(1), null, 7, TrafficDirection.ServerToClient,
            null, false, "00", PointQualityFlags.Online, out var b2));
        Assert.False(b2!.IsValueChange);

        Assert.True(engine.TryResolveAndProject(
            sessionId, pairId, boolAddr, t0Time.AddSeconds(2), null, 8, TrafficDirection.ServerToClient,
            null, true, "01", PointQualityFlags.Online, out var b3));
        Assert.True(b3!.IsValueChange);

        // Verify T0 initial states were preserved from first observations
        var initialStates = engine.GetInitialStates();
        Assert.Equal(1380.0, initialStates[numTagId].InitialUnscaledNumericValue);
        Assert.Equal(138.0, initialStates[numTagId].InitialScaledNumericValue!.Value, precision: 5);
        Assert.Equal("0564", initialStates[numTagId].InitialRawHex);

        Assert.False(initialStates[boolTagId].InitialBooleanValue);
        Assert.Equal("00", initialStates[boolTagId].InitialRawHex);
    }

    [Fact]
    public void TryGetTag_ConfiguredAndUnconfiguredAddresses_ReturnsMatchingTagDefinition()
    {
        var pairId = Guid.NewGuid();
        var otherPairId = Guid.NewGuid();
        var tagId = Guid.NewGuid();
        var address = ProtocolAddress.Parse("HR:40001");
        var tag = new TagDefinition(
            Id: tagId,
            DevicePairId: pairId,
            TagName: "Bus_Volts_A",
            ProtocolAddress: address,
            DataType: TagDataType.Float32Be,
            ScaleMultiplier: 0.1,
            ScaleOffset: 0.0,
            EngineeringUnits: "kV",
            Description: null);

        var engine = new TagResolutionEngine([tag]);

        Assert.True(engine.TryGetTag(pairId, ProtocolAddress.Parse("hr:40001"), out var resolved));
        Assert.Equal(tag, resolved);

        Assert.False(engine.TryGetTag(pairId, ProtocolAddress.Parse("HR:40002"), out var unmapped));
        Assert.Null(unmapped);

        Assert.False(engine.TryGetTag(otherPairId, address, out var wrongPair));
        Assert.Null(wrongPair);
    }
}
