using Xunit.Abstractions;
using Xunit.Sdk;

namespace Analyzer.IntegrationTests.Attributes;

[TraitDiscoverer("Analyzer.IntegrationTests.Attributes.IntegrationTraitDiscoverer", "Analyzer.IntegrationTests")]
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
public sealed class IntegrationTraitAttribute : Attribute, ITraitAttribute
{
}

public sealed class IntegrationTraitDiscoverer : ITraitDiscoverer
{
    public IEnumerable<KeyValuePair<string, string>> GetTraits(IAttributeInfo traitAttribute)
    {
        yield return new KeyValuePair<string, string>("Category", "Integration");
    }
}
