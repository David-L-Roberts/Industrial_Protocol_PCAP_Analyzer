using Analyzer.Core.Domain;

namespace Analyzer.Infrastructure.Mapping;

internal static class ProtocolTypeParser
{
    public static ProtocolType Parse(string? value)
    {
        if (string.Equals(value, "ModbusTCP", StringComparison.OrdinalIgnoreCase))
        {
            return ProtocolType.ModbusTcp;
        }

        if (string.Equals(value, "DNP3", StringComparison.OrdinalIgnoreCase))
        {
            return ProtocolType.Dnp3;
        }

        throw new FormatException($"Unsupported protocol '{value}'. Expected 'ModbusTCP' or 'DNP3'.");
    }
}
