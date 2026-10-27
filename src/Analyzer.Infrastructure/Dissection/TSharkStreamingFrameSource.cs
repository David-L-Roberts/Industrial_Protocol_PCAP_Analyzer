using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;

namespace Analyzer.Infrastructure.Dissection;

public class TSharkStreamingFrameSource : IFrameSource
{
    private readonly record struct IpTcpEndpoints(
        IPAddress SourceIp,
        int SourcePort,
        IPAddress DestIp,
        int DestPort);

    private readonly Func<string, CancellationToken, Task<Stream>>? _streamProvider;
    private readonly string _tsharkExecutablePath;

    public TSharkStreamingFrameSource(
        Func<string, CancellationToken, Task<Stream>>? streamProvider = null,
        string tsharkExecutablePath = "tshark")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tsharkExecutablePath);
        _streamProvider = streamProvider;
        _tsharkExecutablePath = tsharkExecutablePath;
    }

    public static ProcessStartInfo CreateTSharkStartInfo(
        string pcapFilePath,
        string tsharkExecutablePath = "tshark")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pcapFilePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(tsharkExecutablePath);

        var startInfo = new ProcessStartInfo
        {
            FileName = tsharkExecutablePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        startInfo.ArgumentList.Add("-r");
        startInfo.ArgumentList.Add(pcapFilePath);
        startInfo.ArgumentList.Add("-T");
        startInfo.ArgumentList.Add("ek");
        startInfo.ArgumentList.Add("-j");
        startInfo.ArgumentList.Add("modbus dnp3 tcp ip");
        startInfo.ArgumentList.Add("-o");
        startInfo.ArgumentList.Add("tcp.desegment_tcp_streams:TRUE");

        return startInfo;
    }

    public async IAsyncEnumerable<DissectedFrame> ReadFramesAsync(
        string pcapFilePath,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pcapFilePath);

        if (_streamProvider is not null)
        {
            await using var stream = await _streamProvider(pcapFilePath, ct);
            await foreach (var frame in ReadFramesFromNdjsonAsync(stream, ct))
            {
                yield return frame;
            }

            yield break;
        }

        var startInfo = CreateTSharkStartInfo(pcapFilePath, _tsharkExecutablePath);
        using var process = new Process { StartInfo = startInfo };

        if (!process.Start())
        {
            throw new InvalidOperationException($"Failed to start tshark process '{_tsharkExecutablePath}'.");
        }

        try
        {
            var stderrTask = process.StandardError.ReadToEndAsync(ct);

            await foreach (var frame in ReadFramesFromNdjsonAsync(process.StandardOutput.BaseStream, ct))
            {
                yield return frame;
            }

            await process.WaitForExitAsync(ct);
            var stderr = await stderrTask;
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"tshark exited with code {process.ExitCode}: {stderr}");
            }
        }
        finally
        {
            if (!process.HasExited)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // Ignore errors when cleaning up terminated process
                }
            }
        }
    }

    public async IAsyncEnumerable<DissectedFrame> ReadFramesFromNdjsonAsync(
        Stream ndjsonStream,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ndjsonStream);

        using var reader = new StreamReader(ndjsonStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 65536, leaveOpen: true);
        long packetOrdinal = 0;

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var line = await reader.ReadLineAsync(ct);
            if (line is null)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (TryParsePacketLine(line, ref packetOrdinal, out var frame))
            {
                yield return frame;
            }
        }
    }

    private static bool TryParsePacketLine(string line, ref long packetOrdinal, out DissectedFrame frame)
    {
        frame = default!;

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(line);
        }
        catch (JsonException ex)
        {
            throw new FormatException("Malformed NDJSON line encountered.", ex);
        }

        using (doc)
        {
            var root = doc.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (root.TryGetProperty("index", out _))
            {
                return false;
            }

            if (!root.TryGetProperty("layers", out var layers) || layers.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            packetOrdinal++;

            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            FlattenElement(layers, fields);

            if (!TryDetermineProtocol(layers, fields, out var protocol))
            {
                return false;
            }

            long frameNumber = TryExtractFrameNumber(fields, out var explicitFrameNumber)
                ? explicitFrameNumber
                : packetOrdinal;

            if (!TryExtractTimestampUtc(root, fields, out var timestampUtc))
            {
                return false;
            }

            if (!TryExtractEndpoints(fields, out var endpoints))
            {
                return false;
            }

            var rawPayload = ExtractRawApplicationPayload(fields);

            frame = new DissectedFrame(
                FrameNumber: frameNumber,
                TimestampUtc: timestampUtc,
                SourceIp: endpoints.SourceIp,
                SourcePort: endpoints.SourcePort,
                DestIp: endpoints.DestIp,
                DestPort: endpoints.DestPort,
                ProtocolName: protocol,
                RawApplicationPayload: rawPayload,
                DissectedFields: fields);

            return true;
        }
    }

    private static void FlattenElement(JsonElement element, Dictionary<string, string> fields)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.Object)
                    {
                        FlattenElement(prop.Value, fields);
                    }
                    else
                    {
                        StoreField(prop.Name, prop.Value, fields);
                    }
                }
                break;

            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object)
                    {
                        FlattenElement(item, fields);
                    }
                }
                break;
        }
    }

    private static void StoreField(string rawKey, JsonElement valueElement, Dictionary<string, string> fields)
    {
        string? strValue = ExtractScalarString(valueElement);
        if (strValue is null)
        {
            return;
        }

        fields[rawKey] = strValue;

        var normalizedKey = NormalizeEkFieldName(rawKey);
        if (!string.Equals(normalizedKey, rawKey, StringComparison.OrdinalIgnoreCase))
        {
            fields[normalizedKey] = strValue;
        }
    }

    private static string? ExtractScalarString(JsonElement element) =>
        element.ValueKind switch
        {
            JsonValueKind.String => element.GetString(),
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Array => ExtractFirstArrayScalar(element),
            _ => null
        };

    private static string? ExtractFirstArrayScalar(JsonElement arrayElement)
    {
        foreach (var item in arrayElement.EnumerateArray())
        {
            var scalar = ExtractScalarString(item);
            if (scalar is not null)
            {
                return scalar;
            }
        }

        return null;
    }

    private static string NormalizeEkFieldName(string rawKey)
    {
        int firstUnderscore = rawKey.IndexOf('_');
        if (firstUnderscore > 0)
        {
            var protoPrefix = rawKey[..firstUnderscore];
            var duplicatedPrefix = $"{protoPrefix}_{protoPrefix}_";
            if (rawKey.StartsWith(duplicatedPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return $"{protoPrefix}.{rawKey[duplicatedPrefix.Length..]}";
            }
        }

        return rawKey;
    }

    private static bool TryDetermineProtocol(
        JsonElement layers,
        Dictionary<string, string> fields,
        out ProtocolType protocol)
    {
        if (layers.TryGetProperty("dnp3", out _))
        {
            protocol = ProtocolType.Dnp3;
            return true;
        }

        if (layers.TryGetProperty("modbus", out _) || layers.TryGetProperty("mbtcp", out _))
        {
            protocol = ProtocolType.ModbusTcp;
            return true;
        }

        if (TryGetFirst(fields, ["frame.protocols", "frame_frame_protocols"], out var protocols))
        {
            if (protocols.Contains("dnp3", StringComparison.OrdinalIgnoreCase))
            {
                protocol = ProtocolType.Dnp3;
                return true;
            }

            if (protocols.Contains("modbus", StringComparison.OrdinalIgnoreCase) ||
                protocols.Contains("mbtcp", StringComparison.OrdinalIgnoreCase))
            {
                protocol = ProtocolType.ModbusTcp;
                return true;
            }
        }

        protocol = default;
        return false;
    }

    private static bool TryExtractFrameNumber(Dictionary<string, string> fields, out long frameNumber)
    {
        if (TryGetFirst(fields, ["frame.number", "frame_frame_number", "frame_number"], out var raw) &&
            long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out frameNumber))
        {
            return true;
        }

        frameNumber = default;
        return false;
    }

    private static bool TryExtractTimestampUtc(
        JsonElement root,
        Dictionary<string, string> fields,
        out DateTime timestampUtc)
    {
        if (TryGetFirst(fields, ["frame.time_epoch", "frame_frame_time_epoch"], out var epochSecondsRaw) &&
            double.TryParse(epochSecondsRaw, NumberStyles.Float, CultureInfo.InvariantCulture, out var epochSeconds))
        {
            long ticks = (long)Math.Round(epochSeconds * TimeSpan.TicksPerSecond);
            timestampUtc = DateTime.UnixEpoch.AddTicks(ticks);
            return true;
        }

        if (root.TryGetProperty("timestamp", out var tsProp))
        {
            var rawTs = ExtractScalarString(tsProp);
            if (!string.IsNullOrWhiteSpace(rawTs))
            {
                if (long.TryParse(rawTs, NumberStyles.Integer, CultureInfo.InvariantCulture, out var epochMs))
                {
                    timestampUtc = DateTimeOffset.FromUnixTimeMilliseconds(epochMs).UtcDateTime;
                    return true;
                }

                if (DateTimeOffset.TryParse(rawTs, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto))
                {
                    timestampUtc = dto.UtcDateTime;
                    return true;
                }
            }
        }

        timestampUtc = default;
        return false;
    }

    private static bool TryExtractEndpoints(
        Dictionary<string, string> fields,
        out IpTcpEndpoints endpoints)
    {
        endpoints = default;

        if (!TryGetFirst(fields, ["ip.src", "ip_ip_src"], out var rawSrcIp) ||
            !IPAddress.TryParse(rawSrcIp, out var srcIp))
        {
            return false;
        }

        if (!TryGetFirst(fields, ["ip.dst", "ip_ip_dst"], out var rawDstIp) ||
            !IPAddress.TryParse(rawDstIp, out var dstIp))
        {
            return false;
        }

        int srcPort = 0;
        if (TryGetFirst(fields, ["tcp.srcport", "tcp_tcp_srcport"], out var rawSrcPort) &&
            int.TryParse(rawSrcPort, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedSrcPort))
        {
            srcPort = parsedSrcPort;
        }

        int dstPort = 0;
        if (TryGetFirst(fields, ["tcp.dstport", "tcp_tcp_dstport"], out var rawDstPort) &&
            int.TryParse(rawDstPort, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedDstPort))
        {
            dstPort = parsedDstPort;
        }

        endpoints = new IpTcpEndpoints(srcIp, srcPort, dstIp, dstPort);
        return true;
    }

    private static byte[] ExtractRawApplicationPayload(Dictionary<string, string> fields)
    {
        if (TryGetFirst(
            fields,
            [
                "mbtcp.payload",
                "modbus.payload",
                "dnp3.payload",
                "tcp.reassembled.data",
                "tcp_tcp_reassembled_data",
                "tcp_reassembled_data",
                "tcp.payload",
                "tcp_tcp_payload",
                "data.data",
                "data_data_data"
            ],
            out var hex))
        {
            return DecodeHexPayload(hex);
        }

        return [];
    }

    internal static byte[] DecodeHexPayload(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
        {
            return [];
        }

        Span<char> cleanChars = hex.Length <= 2048
            ? stackalloc char[hex.Length]
            : new char[hex.Length];

        int count = 0;
        foreach (char c in hex)
        {
            if (Uri.IsHexDigit(c))
            {
                cleanChars[count++] = c;
            }
            else if (c is ':' or '-' or ' ')
            {
                continue;
            }
            else
            {
                throw new FormatException($"Invalid hex character '{c}' in payload '{hex}'.");
            }
        }

        if (count % 2 != 0)
        {
            throw new FormatException($"Hex payload must have an even number of hex digits, found {count}.");
        }

        return Convert.FromHexString(cleanChars[..count]);
    }

    private static bool TryGetFirst(
        Dictionary<string, string> fields,
        ReadOnlySpan<string> keys,
        out string value)
    {
        foreach (var key in keys)
        {
            if (fields.TryGetValue(key, out var found) && !string.IsNullOrWhiteSpace(found))
            {
                value = found;
                return true;
            }
        }

        value = string.Empty;
        return false;
    }
}
