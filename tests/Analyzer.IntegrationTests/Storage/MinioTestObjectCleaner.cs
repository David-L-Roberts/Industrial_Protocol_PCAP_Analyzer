using Minio;
using Minio.DataModel.Args;

namespace Analyzer.IntegrationTests.Storage;

/// <summary>
/// Removes uploaded test capture objects from MinIO during test teardown unless <c>KEEP_TEST_DATA</c> is enabled.
/// </summary>
public static class MinioTestObjectCleaner
{
    public static async Task CleanupObjectsIfEnabledAsync(
        IMinioClient client,
        string bucketName,
        IEnumerable<string> objectKeys,
        bool keepTestData,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(bucketName);
        ArgumentNullException.ThrowIfNull(objectKeys);

        if (keepTestData)
        {
            return;
        }

        var keys = objectKeys
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (keys.Length == 0)
        {
            return;
        }

        foreach (var key in keys)
        {
            await DeleteObjectAsync(client, bucketName, key, ct);
        }
    }

    public static async Task DeleteObjectAsync(
        IMinioClient client,
        string bucketName,
        string objectKey,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(bucketName);
        if (string.IsNullOrWhiteSpace(objectKey))
        {
            return;
        }

        await client.RemoveObjectAsync(
            new RemoveObjectArgs()
                .WithBucket(bucketName)
                .WithObject(objectKey),
            ct);
    }
}
