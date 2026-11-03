using Analyzer.IntegrationTests.Configuration;

namespace Analyzer.IntegrationTests.Attributes;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class IntegrationFactAttribute : FactAttribute
{
    public const string EnableEnvVarName = "RUN_INTEGRATION_TESTS";
    internal const string DefaultSkipReason =
        "Skipped live integration test. Run with `dotnet test --settings integration.runsettings` to execute.";

    public IntegrationFactAttribute()
        : this(Environment.GetEnvironmentVariable(EnableEnvVarName))
    {
    }

    internal IntegrationFactAttribute(string? environmentValue)
    {
        if (ShouldSkipForEnvironmentValue(environmentValue))
        {
            Skip = DefaultSkipReason;
        }
    }

    public static bool ShouldSkipForEnvironmentValue(string? value) =>
        !IntegrationTestConfig.IsTruthy(value);
}

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class IntegrationTheoryAttribute : TheoryAttribute
{
    public IntegrationTheoryAttribute()
        : this(Environment.GetEnvironmentVariable(IntegrationFactAttribute.EnableEnvVarName))
    {
    }

    internal IntegrationTheoryAttribute(string? environmentValue)
    {
        if (IntegrationFactAttribute.ShouldSkipForEnvironmentValue(environmentValue))
        {
            Skip = IntegrationFactAttribute.DefaultSkipReason;
        }
    }
}
