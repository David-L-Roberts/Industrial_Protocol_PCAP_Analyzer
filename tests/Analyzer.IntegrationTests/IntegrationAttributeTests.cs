using Analyzer.IntegrationTests.Attributes;

namespace Analyzer.IntegrationTests;

public class IntegrationAttributeTests
{
    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("false", true)]
    [InlineData("0", true)]
    [InlineData("true", false)]
    [InlineData("TRUE", false)]
    [InlineData("1", false)]
    public void ShouldSkip_EvaluatesRunIntegrationTestsEnvironmentVariable(string? envValue, bool expectedShouldSkip)
    {
        bool shouldSkip = IntegrationFactAttribute.ShouldSkipForEnvironmentValue(envValue);

        Assert.Equal(expectedShouldSkip, shouldSkip);

        var factAttr = new IntegrationFactAttribute(envValue);
        var theoryAttr = new IntegrationTheoryAttribute(envValue);
        if (expectedShouldSkip)
        {
            Assert.NotNull(factAttr.Skip);
            Assert.Contains("integration.runsettings", factAttr.Skip);
            Assert.NotNull(theoryAttr.Skip);
            Assert.Contains("integration.runsettings", theoryAttr.Skip);
        }
        else
        {
            Assert.Null(factAttr.Skip);
            Assert.Null(theoryAttr.Skip);
        }
    }
}
