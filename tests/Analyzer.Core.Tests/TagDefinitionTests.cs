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
            ProtocolAddress: ProtocolAddress.Parse("HR:40001"),
            DataType: TagDataType.Float32Be,
            ScaleMultiplier: 0.1,
            ScaleOffset: 5.0,
            EngineeringUnits: "kV",
            Description: "Phase A Bus Voltage");

        var scaled = tag.ComputeScaledValue(1100.0);

        Assert.Equal(115.0, scaled, precision: 5);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("40001")]
    [InlineData(":40001")]
    [InlineData("HR:")]
    public void ProtocolAddress_InvalidFormat_ThrowsArgumentExceptionAndFailsTryParse(string invalid)
    {
        Assert.False(ProtocolAddress.TryParse(invalid, out _));
        Assert.Throws<ArgumentException>(() => ProtocolAddress.Parse(invalid));
    }

    [Fact]
    public void ProtocolAddress_EqualsAndHashCode_AreCaseInsensitive()
    {
        var upper = ProtocolAddress.Parse("G30V02:Idx0");
        var lower = ProtocolAddress.Parse("g30v02:idx0");

        Assert.Equal(upper, lower);
        Assert.True(upper == lower);
        Assert.Equal(upper.GetHashCode(), lower.GetHashCode());
    }
}
