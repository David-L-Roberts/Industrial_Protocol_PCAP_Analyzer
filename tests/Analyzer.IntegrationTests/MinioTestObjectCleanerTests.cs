using Analyzer.IntegrationTests.Storage;
using Minio;

namespace Analyzer.IntegrationTests;

public class MinioTestObjectCleanerTests
{
    [Fact]
    public async Task CleanupObjectsIfEnabledAsync_WhenKeepTestDataIsTrue_DoesNotContactMinioServer()
    {
        using var client = CreateUnreachableClient();

        await MinioTestObjectCleaner.CleanupObjectsIfEnabledAsync(
            client,
            "pcap-captures",
            ["captures/11111111-1111-1111-1111-111111111111/sample.pcap"],
            keepTestData: true);
    }

    [Fact]
    public async Task CleanupObjectsIfEnabledAsync_WhenObjectKeysAreEmpty_DoesNotContactMinioServer()
    {
        using var client = CreateUnreachableClient();

        await MinioTestObjectCleaner.CleanupObjectsIfEnabledAsync(
            client,
            "pcap-captures",
            ["", "   "],
            keepTestData: false);
    }

    private static IMinioClient CreateUnreachableClient() =>
        new MinioClient()
            .WithEndpoint("127.0.0.1:1")
            .WithCredentials("unused", "unused")
            .Build();
}
