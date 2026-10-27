using System.Net;
using System.Text;
using Analyzer.Core.Domain;
using Analyzer.Infrastructure.Dissection;

namespace Analyzer.Infrastructure.Tests;

public class TSharkStreamingFrameSourceTests
{
    [Fact]
    public void CreateTSharkStartInfo_ConfiguresExpectedArgumentsAndRedirection()
    {
        var startInfo = TSharkStreamingFrameSource.CreateTSharkStartInfo("captures/feeder1.pcap", "/usr/bin/tshark");

        Assert.Equal("/usr/bin/tshark", startInfo.FileName);
        Assert.True(startInfo.RedirectStandardOutput);
        Assert.True(startInfo.RedirectStandardError);
        Assert.False(startInfo.UseShellExecute);
        Assert.True(startInfo.CreateNoWindow);

        var expectedArgs = new[]
        {
            "-r", "captures/feeder1.pcap",
            "-T", "ek",
            "-j", "modbus dnp3 tcp ip",
            "-o", "tcp.desegment_tcp_streams:TRUE"
        };
        Assert.Equal(expectedArgs, startInfo.ArgumentList);
    }

    [Fact]
    public async Task ReadFramesAsync_WithInjectedNdjsonStream_ParsesModbusAndDnp3FramesAndSkipsIndexLines()
    {
        const string ndjson = """
        {"index":{"_index":"packets-2026-10-27","_type":"doc"}}
        {"timestamp":"1730000000125","layers":{"frame":{"frame_frame_number":"1","frame_frame_protocols":"eth:ethertype:ip:tcp:mbtcp:modbus"},"ip":{"ip_ip_src":"10.0.1.10","ip_ip_dst":"10.0.1.20"},"tcp":{"tcp_tcp_srcport":"50123","tcp_tcp_dstport":"502","tcp_tcp_payload":"00:01:00:00:00:06:01:03:00:00:00:02"},"mbtcp":{"mbtcp_mbtcp_trans_id":"1","mbtcp_mbtcp_unit_id":"1"},"modbus":{"modbus_modbus_func_code":"3"}}}
        {"index":{"_index":"packets-2026-10-27","_type":"doc"}}
        {"timestamp":"1730000000375","layers":{"frame":{"frame_frame_number":"2","frame_frame_protocols":"eth:ethertype:ip:tcp:dnp3"},"ip":{"ip_ip_src":"10.0.1.5","ip_ip_dst":"10.0.1.10"},"tcp":{"tcp_tcp_srcport":"20000","tcp_tcp_dstport":"54321","tcp_tcp_payload":"056405c001006400"},"dnp3":{"dnp3_dnp3_src":"1","dnp3_dnp3_dst":"100","dnp3_dnp3_al_func":"1"}}}
        """;

        var source = new TSharkStreamingFrameSource(
            streamProvider: (_, _) => Task.FromResult<Stream>(new MemoryStream(Encoding.UTF8.GetBytes(ndjson))));

        var frames = new List<DissectedFrame>();
        await foreach (var frame in source.ReadFramesAsync("dummy.pcap"))
        {
            frames.Add(frame);
        }

        Assert.Equal(2, frames.Count);

        var modbusFrame = frames[0];
        Assert.Equal(1L, modbusFrame.FrameNumber);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1730000000125).UtcDateTime, modbusFrame.TimestampUtc);
        Assert.Equal(DateTimeKind.Utc, modbusFrame.TimestampUtc.Kind);
        Assert.Equal(IPAddress.Parse("10.0.1.10"), modbusFrame.SourceIp);
        Assert.Equal(50123, modbusFrame.SourcePort);
        Assert.Equal(IPAddress.Parse("10.0.1.20"), modbusFrame.DestIp);
        Assert.Equal(502, modbusFrame.DestPort);
        Assert.Equal(ProtocolType.ModbusTcp, modbusFrame.ProtocolName);
        Assert.Equal(new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02 }, modbusFrame.RawApplicationPayload);
        Assert.NotNull(modbusFrame.DissectedFields);
        Assert.Equal("1", modbusFrame.DissectedFields!["mbtcp.unit_id"]);
        Assert.Equal("3", modbusFrame.DissectedFields["modbus.func_code"]);

        var dnp3Frame = frames[1];
        Assert.Equal(2L, dnp3Frame.FrameNumber);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1730000000375).UtcDateTime, dnp3Frame.TimestampUtc);
        Assert.Equal(IPAddress.Parse("10.0.1.5"), dnp3Frame.SourceIp);
        Assert.Equal(20000, dnp3Frame.SourcePort);
        Assert.Equal(IPAddress.Parse("10.0.1.10"), dnp3Frame.DestIp);
        Assert.Equal(54321, dnp3Frame.DestPort);
        Assert.Equal(ProtocolType.Dnp3, dnp3Frame.ProtocolName);
        Assert.Equal(new byte[] { 0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x64, 0x00 }, dnp3Frame.RawApplicationPayload);
        Assert.NotNull(dnp3Frame.DissectedFields);
        Assert.Equal("1", dnp3Frame.DissectedFields!["dnp3.src"]);
        Assert.Equal("100", dnp3Frame.DissectedFields["dnp3.dst"]);
    }

    [Fact]
    public async Task ReadFramesFromNdjsonAsync_SkipsNonIndustrialTcpFramesAndSupportsEpochSecondsAndArrayFields()
    {
        const string ndjson = """
        {"index":{"_index":"packets-2026-10-27","_type":"doc"}}
        {"timestamp":"1730000000000","layers":{"frame":{"frame_frame_number":["10"],"frame_frame_protocols":["eth:ethertype:ip:tcp"]},"ip":{"ip_ip_src":["10.0.1.10"],"ip_ip_dst":["10.0.1.20"]},"tcp":{"tcp_tcp_srcport":["50123"],"tcp_tcp_dstport":["502"]}}}
        {"index":{"_index":"packets-2026-10-27","_type":"doc"}}
        {"layers":{"frame":{"frame_frame_number":["11"],"frame_frame_time_epoch":["1730000001.500000000"],"frame_frame_protocols":["eth:ethertype:ip:tcp:mbtcp:modbus"]},"ip":{"ip_ip_src":["10.0.1.20"],"ip_ip_dst":["10.0.1.10"]},"tcp":{"tcp_tcp_srcport":["502"],"tcp_tcp_dstport":["50123"],"tcp_tcp_payload":["00:01:00:00:00:05:01:03:02:12:34"]}}}
        """;

        var source = new TSharkStreamingFrameSource();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(ndjson));

        var frames = new List<DissectedFrame>();
        await foreach (var frame in source.ReadFramesFromNdjsonAsync(stream))
        {
            frames.Add(frame);
        }

        var single = Assert.Single(frames);
        Assert.Equal(11L, single.FrameNumber);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1730000001500).UtcDateTime, single.TimestampUtc);
        Assert.Equal(ProtocolType.ModbusTcp, single.ProtocolName);
        Assert.Equal(new byte[] { 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x12, 0x34 }, single.RawApplicationPayload);
    }

    [Fact]
    public async Task ReadFramesFromNdjsonAsync_PrefersReassembledTcpPayloadAndAssignsOrdinalFrameNumberWhenFrameLayerFiltered()
    {
        const string ndjson = """
        {"index":{"_index":"packets-2026-10-27","_type":"doc"}}
        {"timestamp":"1730000002000","layers":{"ip":{"ip_ip_src":"10.0.1.20","ip_ip_dst":"10.0.1.10"},"tcp":{"tcp_tcp_srcport":"20000","tcp_tcp_dstport":"50000","tcp_tcp_payload":"AABB","tcp_tcp_reassembled_data":"05:64:0A:44:01:00:64:00:12:34"},"dnp3":{"dnp3_dnp3_src":"100","dnp3_dnp3_dst":"1"}}}
        """;

        var source = new TSharkStreamingFrameSource();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(ndjson));

        var frames = new List<DissectedFrame>();
        await foreach (var frame in source.ReadFramesFromNdjsonAsync(stream))
        {
            frames.Add(frame);
        }

        var single = Assert.Single(frames);
        Assert.Equal(1L, single.FrameNumber);
        Assert.Equal(ProtocolType.Dnp3, single.ProtocolName);
        Assert.Equal(new byte[] { 0x05, 0x64, 0x0A, 0x44, 0x01, 0x00, 0x64, 0x00, 0x12, 0x34 }, single.RawApplicationPayload);
    }

    [Theory]
    [InlineData("not-json-at-all")]
    [InlineData("""{"timestamp":"1730000000125","layers":{"frame":{"frame_frame_number":"1","frame_frame_protocols":"eth:ethertype:ip:tcp:modbus"},"ip":{"ip_ip_src":"10.0.1.10","ip_ip_dst":"10.0.1.20"},"tcp":{"tcp_tcp_srcport":"50123","tcp_tcp_dstport":"502","tcp_tcp_payload":"00:ZZ"}}}""")]
    public async Task ReadFramesFromNdjsonAsync_MalformedJsonOrHex_ThrowsFormatException(string badLine)
    {
        var source = new TSharkStreamingFrameSource();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(badLine));

        await Assert.ThrowsAsync<FormatException>(async () =>
        {
            await foreach (var _ in source.ReadFramesFromNdjsonAsync(stream))
            {
            }
        });
    }
}
