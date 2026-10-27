using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Analyzer.Core.Domain;

namespace Analyzer.Infrastructure.Mapping;

public record ParsedDevicePairConfig(
    DeviceEndpointPair DevicePair,
    string? TagMappingCsvPath
);

public record ParsedSessionManifest(
    TestSession Session,
    IReadOnlyList<ParsedDevicePairConfig> DevicePairs
);

public class ManifestParser
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public ParsedSessionManifest Parse(string json, Guid? sessionId = null)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new FormatException("Manifest JSON cannot be empty.");
        }

        SessionManifestDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<SessionManifestDto>(json, SerializerOptions);
        }
        catch (JsonException ex)
        {
            throw new FormatException("Manifest JSON is not valid JSON.", ex);
        }

        if (dto is null)
        {
            throw new FormatException("Manifest JSON cannot be null.");
        }

        if (string.IsNullOrWhiteSpace(dto.SessionName))
        {
            throw new FormatException("Manifest 'session_name' is required.");
        }

        if (string.IsNullOrWhiteSpace(dto.PcapFile))
        {
            throw new FormatException("Manifest 'pcap_file' is required.");
        }

        int timeoutThresholdMs = dto.TimeoutThresholdMs ?? 2000;
        if (timeoutThresholdMs <= 0)
        {
            throw new FormatException("Manifest 'timeout_threshold_ms' must be greater than zero.");
        }

        var resolvedSessionId = sessionId ?? Guid.NewGuid();
        var session = new TestSession(
            Id: resolvedSessionId,
            Name: dto.SessionName.Trim(),
            PcapFileName: dto.PcapFile.Trim(),
            S3ObjectKey: null,
            TimeoutThresholdMs: timeoutThresholdMs,
            StoreUnmappedRegisters: dto.StoreUnmappedRegisters ?? false);

        var pairs = new List<ParsedDevicePairConfig>();
        if (dto.DevicePairs is not null)
        {
            foreach (var pairDto in dto.DevicePairs)
            {
                if (string.IsNullOrWhiteSpace(pairDto.Name))
                {
                    throw new FormatException("Device pair 'name' is required.");
                }

                var protocol = ProtocolTypeParser.Parse(pairDto.Protocol);

                if (string.IsNullOrWhiteSpace(pairDto.ClientIp) || !IPAddress.TryParse(pairDto.ClientIp.Trim(), out var clientIp))
                {
                    throw new FormatException($"Invalid 'client_ip' value '{pairDto.ClientIp}' for device pair '{pairDto.Name}'.");
                }

                if (string.IsNullOrWhiteSpace(pairDto.ServerIp) || !IPAddress.TryParse(pairDto.ServerIp.Trim(), out var serverIp))
                {
                    throw new FormatException($"Invalid 'server_ip' value '{pairDto.ServerIp}' for device pair '{pairDto.Name}'.");
                }

                var devicePair = new DeviceEndpointPair(
                    Id: Guid.NewGuid(),
                    SessionId: resolvedSessionId,
                    Name: pairDto.Name.Trim(),
                    Protocol: protocol,
                    ClientIp: clientIp,
                    ServerIp: serverIp,
                    ClientProtocolAddressId: pairDto.ClientProtocolAddressId,
                    ServerProtocolAddressId: pairDto.ServerProtocolAddressId);

                pairs.Add(new ParsedDevicePairConfig(devicePair, pairDto.TagMappingCsv));
            }
        }

        return new ParsedSessionManifest(session, pairs);
    }

    public async Task<ParsedSessionManifest> ParseFileAsync(string manifestFilePath, CancellationToken ct = default)
    {
        var json = await File.ReadAllTextAsync(manifestFilePath, ct);
        return Parse(json);
    }

    private sealed class SessionManifestDto
    {
        [JsonPropertyName("session_name")]
        public string? SessionName { get; set; }

        [JsonPropertyName("pcap_file")]
        public string? PcapFile { get; set; }

        [JsonPropertyName("timeout_threshold_ms")]
        public int? TimeoutThresholdMs { get; set; }

        [JsonPropertyName("store_unmapped_registers")]
        public bool? StoreUnmappedRegisters { get; set; }

        [JsonPropertyName("device_pairs")]
        public List<DevicePairDto>? DevicePairs { get; set; }
    }

    private sealed class DevicePairDto
    {
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("protocol")]
        public string? Protocol { get; set; }

        [JsonPropertyName("client_ip")]
        public string? ClientIp { get; set; }

        [JsonPropertyName("server_ip")]
        public string? ServerIp { get; set; }

        [JsonPropertyName("client_protocol_address_id")]
        public int? ClientProtocolAddressId { get; set; }

        [JsonPropertyName("server_protocol_address_id")]
        public int? ServerProtocolAddressId { get; set; }

        [JsonPropertyName("tag_mapping_csv")]
        public string? TagMappingCsv { get; set; }
    }
}

