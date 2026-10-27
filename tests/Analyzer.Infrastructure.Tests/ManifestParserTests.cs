using System.Net;
using Analyzer.Core.Domain;
using Analyzer.Infrastructure.Mapping;

namespace Analyzer.Infrastructure.Tests;

public class ManifestParserTests
{
    [Fact]
    public void Parse_ValidManifestJson_ReturnsSessionAndDevicePairs()
    {
        const string json = """
        {
          "session_name": "SAT_Substation_Feeder1",
          "pcap_file": "feeder1_capture.pcap",
          "timeout_threshold_ms": 1500,
          "store_unmapped_registers": true,
          "device_pairs": [
            {
              "name": "RTAC_Client_to_Relay_Server",
              "protocol": "ModbusTCP",
              "client_ip": "10.0.1.10",
              "server_ip": "10.0.1.20",
              "client_protocol_address_id": null,
              "server_protocol_address_id": 1,
              "tag_mapping_csv": "relay_modbus_tags.csv"
            },
            {
              "name": "SCADA_Master_to_RTAC_Outstation",
              "protocol": "DNP3",
              "client_ip": "10.0.1.5",
              "server_ip": "10.0.1.10",
              "client_protocol_address_id": 1,
              "server_protocol_address_id": 100,
              "tag_mapping_csv": "rtac_dnp3_tags.csv"
            }
          ]
        }
        """;

        var sessionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var parser = new ManifestParser();

        var result = parser.Parse(json, sessionId);

        Assert.Equal(sessionId, result.Session.Id);
        Assert.Equal("SAT_Substation_Feeder1", result.Session.Name);
        Assert.Equal("feeder1_capture.pcap", result.Session.PcapFileName);
        Assert.Equal(1500, result.Session.TimeoutThresholdMs);
        Assert.True(result.Session.StoreUnmappedRegisters);

        Assert.Equal(2, result.DevicePairs.Count);

        var first = result.DevicePairs[0];
        Assert.NotEqual(Guid.Empty, first.DevicePair.Id);
        Assert.Equal(sessionId, first.DevicePair.SessionId);
        Assert.Equal("RTAC_Client_to_Relay_Server", first.DevicePair.Name);
        Assert.Equal(ProtocolType.ModbusTcp, first.DevicePair.Protocol);
        Assert.Equal(IPAddress.Parse("10.0.1.10"), first.DevicePair.ClientIp);
        Assert.Equal(IPAddress.Parse("10.0.1.20"), first.DevicePair.ServerIp);
        Assert.Null(first.DevicePair.ClientProtocolAddressId);
        Assert.Equal(1, first.DevicePair.ServerProtocolAddressId);
        Assert.Equal("relay_modbus_tags.csv", first.TagMappingCsvPath);

        var second = result.DevicePairs[1];
        Assert.NotEqual(Guid.Empty, second.DevicePair.Id);
        Assert.Equal(sessionId, second.DevicePair.SessionId);
        Assert.Equal("SCADA_Master_to_RTAC_Outstation", second.DevicePair.Name);
        Assert.Equal(ProtocolType.Dnp3, second.DevicePair.Protocol);
        Assert.Equal(IPAddress.Parse("10.0.1.5"), second.DevicePair.ClientIp);
        Assert.Equal(IPAddress.Parse("10.0.1.10"), second.DevicePair.ServerIp);
        Assert.Equal(1, second.DevicePair.ClientProtocolAddressId);
        Assert.Equal(100, second.DevicePair.ServerProtocolAddressId);
        Assert.Equal("rtac_dnp3_tags.csv", second.TagMappingCsvPath);
    }

    [Fact]
    public void Parse_OmittedOptionalFields_AppliesDefaultsAndGeneratesSessionId()
    {
        const string json = """
        {
          "session_name": "Default_Session",
          "pcap_file": "capture.pcapng",
          "device_pairs": []
        }
        """;

        var parser = new ManifestParser();
        var result = parser.Parse(json);

        Assert.NotEqual(Guid.Empty, result.Session.Id);
        Assert.Equal(2000, result.Session.TimeoutThresholdMs);
        Assert.False(result.Session.StoreUnmappedRegisters);
        Assert.Empty(result.DevicePairs);
    }

    [Theory]
    [InlineData("""{"pcap_file": "a.pcap", "device_pairs": []}""")]
    [InlineData("""{"session_name": "S1", "device_pairs": []}""")]
    [InlineData("""{"session_name": "S1", "pcap_file": "a.pcap", "timeout_threshold_ms": 0, "device_pairs": []}""")]
    [InlineData("""{"session_name": "S1", "pcap_file": "a.pcap", "device_pairs": [{"name": "P1", "protocol": "UnknownProto", "client_ip": "10.0.0.1", "server_ip": "10.0.0.2"}]}""")]
    [InlineData("""{"session_name": "S1", "pcap_file": "a.pcap", "device_pairs": [{"name": "P1", "protocol": "ModbusTCP", "client_ip": "not-an-ip", "server_ip": "10.0.0.2"}]}""")]
    [InlineData("""{"session_name": "S1", "pcap_file": "a.pcap", "device_pairs": [{"name": "", "protocol": "ModbusTCP", "client_ip": "10.0.0.1", "server_ip": "10.0.0.2"}]}""")]
    public void Parse_MissingOrInvalidFields_ThrowsFormatException(string invalidJson)
    {
        var parser = new ManifestParser();

        Assert.Throws<FormatException>(() => parser.Parse(invalidJson));
    }
}
