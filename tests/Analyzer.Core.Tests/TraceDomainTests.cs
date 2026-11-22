using System.Net;
using Analyzer.Core.Domain;
using Analyzer.Core.Services;

namespace Analyzer.Core.Tests;

public class TraceDomainTests
{
    [Fact]
    public void TraceId_ValidHex_NormalizesToLowercaseAndPreservesValueEquality()
    {
        const string upperWithWhitespace = "  0123456789ABCDEF0123456789ABCDEF  ";
        const string expectedLower = "0123456789abcdef0123456789abcdef";

        Assert.True(TraceId.TryParse(upperWithWhitespace, out var parsedFromTry));
        var parsed = TraceId.Parse(upperWithWhitespace);
        var fromLower = new TraceId(expectedLower);
        var different = TraceId.Parse("fedcba9876543210fedcba9876543210");

        Assert.Equal(expectedLower, parsedFromTry.Value);
        Assert.Equal(expectedLower, parsed.Value);
        Assert.Equal(expectedLower, parsed.ToString());
        Assert.Equal(parsed, fromLower);
        Assert.True(parsed == fromLower);
        Assert.False(parsed != fromLower);
        Assert.True(parsed != different);
        Assert.Equal(parsed.GetHashCode(), fromLower.GetHashCode());
        Assert.Equal(string.Empty, default(TraceId).ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("0123456789abcdef")]
    [InlineData("0123456789abcdef0123456789abcde")]
    [InlineData("0123456789abcdef0123456789abcdef0")]
    [InlineData("0123456789abcdef0123456789abcdeg")]
    [InlineData("00000000000000000000000000000000")]
    public void TraceId_InvalidFormatOrAllZero_RejectsParseAndTryParse(string? invalid)
    {
        Assert.False(TraceId.TryParse(invalid, out _));
        Assert.Throws<ArgumentException>(() => TraceId.Parse(invalid!));
        Assert.Throws<ArgumentException>(() => new TraceId(invalid!));
    }

    [Fact]
    public void SpanId_ValidHex_NormalizesToLowercaseAndPreservesValueEquality()
    {
        const string upperWithWhitespace = "  0123456789ABCDEF  ";
        const string expectedLower = "0123456789abcdef";

        Assert.True(SpanId.TryParse(upperWithWhitespace, out var parsedFromTry));
        var parsed = SpanId.Parse(upperWithWhitespace);
        var fromLower = new SpanId(expectedLower);
        var different = SpanId.Parse("fedcba9876543210");

        Assert.Equal(expectedLower, parsedFromTry.Value);
        Assert.Equal(expectedLower, parsed.Value);
        Assert.Equal(expectedLower, parsed.ToString());
        Assert.Equal(parsed, fromLower);
        Assert.True(parsed == fromLower);
        Assert.False(parsed != fromLower);
        Assert.True(parsed != different);
        Assert.Equal(parsed.GetHashCode(), fromLower.GetHashCode());
        Assert.Equal(string.Empty, default(SpanId).ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("01234567")]
    [InlineData("0123456789abcde")]
    [InlineData("0123456789abcdef0")]
    [InlineData("0123456789abcdef0123456789abcdef")]
    [InlineData("0123456789abcdez")]
    [InlineData("0000000000000000")]
    public void SpanId_InvalidFormatOrAllZero_RejectsParseAndTryParse(string? invalid)
    {
        Assert.False(SpanId.TryParse(invalid, out _));
        Assert.Throws<ArgumentException>(() => SpanId.Parse(invalid!));
        Assert.Throws<ArgumentException>(() => new SpanId(invalid!));
    }

    [Fact]
    public void DeterministicTraceIdGenerator_ProducesRepeatableValidW3cHexAndSeparatesDistinctInputs()
    {
        var sessionA = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var sessionB = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var pairA = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var pairB = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

        var trace1 = DeterministicTraceIdGenerator.CreateTraceId(sessionA, pairA, 42, SpanCorrelationRole.Transaction);
        var trace1Repeat = DeterministicTraceIdGenerator.CreateTraceId(sessionA, pairA, 42, SpanCorrelationRole.Transaction);
        var traceDiffSession = DeterministicTraceIdGenerator.CreateTraceId(sessionB, pairA, 42, SpanCorrelationRole.Transaction);
        var traceDiffPair = DeterministicTraceIdGenerator.CreateTraceId(sessionA, pairB, 42, SpanCorrelationRole.Transaction);
        var traceDiffFrame = DeterministicTraceIdGenerator.CreateTraceId(sessionA, pairA, 43, SpanCorrelationRole.Transaction);
        var traceDiffRole = DeterministicTraceIdGenerator.CreateTraceId(sessionA, pairA, 42, SpanCorrelationRole.SboSelect);

        Assert.Equal(trace1, trace1Repeat);
        Assert.Equal(32, trace1.Value.Length);
        Assert.All(trace1.Value, c => Assert.True((c is >= '0' and <= '9') || (c is >= 'a' and <= 'f')));
        Assert.NotEqual(new string('0', 32), trace1.Value);

        Assert.NotEqual(trace1, traceDiffSession);
        Assert.NotEqual(trace1, traceDiffPair);
        Assert.NotEqual(trace1, traceDiffFrame);
        Assert.NotEqual(trace1, traceDiffRole);

        var span1 = DeterministicTraceIdGenerator.CreateSpanId(sessionA, pairA, 42, SpanCorrelationRole.Transaction);
        var span1Repeat = DeterministicTraceIdGenerator.CreateSpanId(sessionA, pairA, 42, SpanCorrelationRole.Transaction, disambiguator: 0);
        var spanDiffDisambig = DeterministicTraceIdGenerator.CreateSpanId(sessionA, pairA, 42, SpanCorrelationRole.Transaction, disambiguator: 1);
        var spanDiffSession = DeterministicTraceIdGenerator.CreateSpanId(sessionB, pairA, 42, SpanCorrelationRole.Transaction);
        var spanDiffPair = DeterministicTraceIdGenerator.CreateSpanId(sessionA, pairB, 42, SpanCorrelationRole.Transaction);
        var spanDiffFrame = DeterministicTraceIdGenerator.CreateSpanId(sessionA, pairA, 43, SpanCorrelationRole.Transaction);
        var spanDiffRole = DeterministicTraceIdGenerator.CreateSpanId(sessionA, pairA, 42, SpanCorrelationRole.Confirm);

        Assert.Equal(span1, span1Repeat);
        Assert.Equal(16, span1.Value.Length);
        Assert.All(span1.Value, c => Assert.True((c is >= '0' and <= '9') || (c is >= 'a' and <= 'f')));
        Assert.NotEqual(new string('0', 16), span1.Value);

        Assert.NotEqual(span1, spanDiffDisambig);
        Assert.NotEqual(span1, spanDiffSession);
        Assert.NotEqual(span1, spanDiffPair);
        Assert.NotEqual(span1, spanDiffFrame);
        Assert.NotEqual(span1, spanDiffRole);
    }

    [Fact]
    public void DeviceEndpointPair_ResolveEndpoints_AppliesNameThenIpWithProtocolAddressThenIpFallback()
    {
        var sessionId = Guid.NewGuid();
        var clientIp = IPAddress.Parse("10.0.1.10");
        var serverIp = IPAddress.Parse("10.0.1.20");

        var namedPair = new DeviceEndpointPair(
            Id: Guid.NewGuid(),
            SessionId: sessionId,
            Name: "NamedPair",
            Protocol: ProtocolType.Dnp3,
            ClientIp: clientIp,
            ServerIp: serverIp,
            ClientProtocolAddressId: 1,
            ServerProtocolAddressId: 100,
            ClientName: "  SEL_RTAC  ",
            ServerName: "  Feeder1_Relay  ");

        Assert.Equal("SEL_RTAC", namedPair.ResolveClientEndpoint());
        Assert.Equal("Feeder1_Relay", namedPair.ResolveServerEndpoint());

        var blankNamesWithProtocolAddr = namedPair with
        {
            ClientName = "   ",
            ServerName = null
        };

        Assert.Equal("10.0.1.10:1", blankNamesWithProtocolAddr.ResolveClientEndpoint());
        Assert.Equal("10.0.1.20:100", blankNamesWithProtocolAddr.ResolveServerEndpoint());

        var ipOnlyFallback = blankNamesWithProtocolAddr with
        {
            ClientProtocolAddressId = null,
            ServerProtocolAddressId = null
        };

        Assert.Equal("10.0.1.10", ipOnlyFallback.ResolveClientEndpoint());
        Assert.Equal("10.0.1.20", ipOnlyFallback.ResolveServerEndpoint());
    }
}
