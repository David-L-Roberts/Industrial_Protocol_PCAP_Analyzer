using System.Globalization;
using System.Text;
using Analyzer.Core.Domain;

namespace Analyzer.Infrastructure.Mapping;

public class CsvTagMappingLoader
{
    public IReadOnlyList<TagDefinition> Parse(
        TextReader reader,
        Guid devicePairId,
        ProtocolType? expectedProtocol = null)
    {
        ArgumentNullException.ThrowIfNull(reader);

        var tags = new List<TagDefinition>();
        var seenAddresses = new HashSet<ProtocolAddress>();
        string? line;
        int lineNumber = 0;
        bool headerRead = false;

        while ((line = reader.ReadLine()) is not null)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var columns = SplitCsvLine(line);
            if (!headerRead)
            {
                headerRead = true;
                if (columns.Count == 8 && string.Equals(columns[0].Trim(), "Protocol", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
            }

            if (columns.Count != 8)
            {
                throw new FormatException($"CSV line {lineNumber} has {columns.Count} columns; expected 8 (Protocol,Address,TagName,DataType,ScaleMultiplier,ScaleOffset,Units,Description).");
            }

            var protocol = ProtocolTypeParser.Parse(columns[0].Trim());
            if (expectedProtocol.HasValue && protocol != expectedProtocol.Value)
            {
                throw new FormatException($"CSV line {lineNumber} specifies protocol '{protocol}', which does not match expected device pair protocol '{expectedProtocol.Value}'.");
            }

            if (!ProtocolAddress.TryParse(columns[1], out var address))
            {
                throw new FormatException($"CSV line {lineNumber} has invalid protocol address '{columns[1]}'.");
            }

            if (!seenAddresses.Add(address))
            {
                throw new FormatException($"CSV line {lineNumber} contains duplicate protocol address '{address}' for device pair '{devicePairId}'.");
            }

            var tagName = columns[2].Trim();
            if (string.IsNullOrWhiteSpace(tagName))
            {
                throw new FormatException($"CSV line {lineNumber} is missing TagName.");
            }

            var dataType = ParseDataType(columns[3].Trim(), lineNumber);

            if (!double.TryParse(columns[4].Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var scaleMultiplier))
            {
                throw new FormatException($"CSV line {lineNumber} has invalid ScaleMultiplier '{columns[4]}'.");
            }

            if (!double.TryParse(columns[5].Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var scaleOffset))
            {
                throw new FormatException($"CSV line {lineNumber} has invalid ScaleOffset '{columns[5]}'.");
            }

            var units = string.IsNullOrWhiteSpace(columns[6]) ? null : columns[6].Trim();
            var description = string.IsNullOrWhiteSpace(columns[7]) ? null : columns[7].Trim();

            tags.Add(new TagDefinition(
                Id: Guid.NewGuid(),
                DevicePairId: devicePairId,
                TagName: tagName,
                ProtocolAddress: address,
                DataType: dataType,
                ScaleMultiplier: scaleMultiplier,
                ScaleOffset: scaleOffset,
                EngineeringUnits: units,
                Description: description));
        }

        return tags;
    }

    public async Task<IReadOnlyList<TagDefinition>> LoadFileAsync(
        string csvFilePath,
        Guid devicePairId,
        ProtocolType? expectedProtocol = null,
        CancellationToken ct = default)
    {
        var content = await File.ReadAllTextAsync(csvFilePath, ct);
        using var reader = new StringReader(content);
        return Parse(reader, devicePairId, expectedProtocol);
    }

    private static TagDataType ParseDataType(string value, int lineNumber) =>
        value.ToUpperInvariant() switch
        {
            "BOOL" => TagDataType.Bool,
            "INT16" => TagDataType.Int16,
            "UINT16" => TagDataType.UInt16,
            "INT32" => TagDataType.Int32,
            "FLOAT32_BE" => TagDataType.Float32Be,
            "FLOAT32_SWAPPED" => TagDataType.Float32Swapped,
            _ => throw new FormatException($"CSV line {lineNumber} has unsupported DataType '{value}'.")
        };

    private static List<string> SplitCsvLine(string line)
    {
        var result = new List<string>(8);
        var current = new StringBuilder();
        bool inQuotes = false;

        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (c == ',' && !inQuotes)
            {
                result.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        result.Add(current.ToString());
        return result;
    }
}
