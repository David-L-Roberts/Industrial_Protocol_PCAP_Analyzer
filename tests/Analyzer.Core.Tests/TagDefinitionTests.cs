using Analyzer.Core.Domain;

namespace Analyzer.Core.Tests;

public class TagDefinitionTests
{
    [Fact]
    public void ComputeScaledValue_AppliesLinearScalingFormula()
    {
        var tag = new TagDefinition(
            Id: Guid.NewGuid(),
            DevicePairId: Guid.NewGuid(),
            TagName: "Bus_Volts_A",
            ProtocolAddress: "HR:40001",
            DataType: "FLOAT32_BE",
            ScaleMultiplier: 0.1,
            ScaleOffset: 5.0,
            EngineeringUnits: "kV",
            Description: "Phase A Bus Voltage");

        var scaled = tag.ComputeScaledValue(1100.0);

        Assert.Equal(115.0, scaled, precision: 5);
    }
}

