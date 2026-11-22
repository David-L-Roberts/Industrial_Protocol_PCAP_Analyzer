using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Analyzer.Core.Domain;

namespace Analyzer.Core.Services;

/// <summary>
/// Derives repeatable W3C-compatible <see cref="TraceId"/> and <see cref="SpanId"/> values
/// deterministically from session, pair, frame, and correlation metadata using SHA-256.
/// </summary>
public static class DeterministicTraceIdGenerator
{
    public static TraceId CreateTraceId(
        Guid sessionId,
        Guid devicePairId,
        long anchorFrameNumber,
        SpanCorrelationRole role)
    {
        string input = string.Create(
            CultureInfo.InvariantCulture,
            $"trace:{sessionId:D}:{devicePairId:D}:{anchorFrameNumber}:{role}");

        return new TraceId(ComputeNonZeroHex(input, byteCount: 16));
    }

    public static SpanId CreateSpanId(
        Guid sessionId,
        Guid devicePairId,
        long frameNumber,
        SpanCorrelationRole role,
        int disambiguator = 0)
    {
        string input = string.Create(
            CultureInfo.InvariantCulture,
            $"span:{sessionId:D}:{devicePairId:D}:{frameNumber}:{role}:{disambiguator}");

        return new SpanId(ComputeNonZeroHex(input, byteCount: 8));
    }

    private static string ComputeNonZeroHex(string canonicalInput, int byteCount)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalInput));
        Span<byte> idBytes = hash.AsSpan(0, byteCount);
        EnsureNonZero(idBytes);
        return Convert.ToHexString(idBytes).ToLowerInvariant();
    }

    private static void EnsureNonZero(Span<byte> bytes)
    {
        foreach (byte b in bytes)
        {
            if (b != 0)
            {
                return;
            }
        }

        bytes[^1] = 0x01;
    }
}
