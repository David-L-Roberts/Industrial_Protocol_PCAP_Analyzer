using Analyzer.Core.Interfaces;
using Minio;
using Minio.DataModel.Args;

namespace Analyzer.Infrastructure.Storage;

/// <summary>
/// Minimal operations on MinIO/S3 needed to archive capture files.
/// </summary>
public interface IMinioClientAdapter
{
    Task<bool> BucketExistsAsync(string bucketName, CancellationToken ct);
    Task MakeBucketAsync(string bucketName, CancellationToken ct);
    Task PutObjectAsync(string bucketName, string objectKey, Stream stream, long size, string contentType, CancellationToken ct);
}

/// <summary>
/// Production adapter delegating to official MinIO SDK <see cref="IMinioClient"/>.
/// </summary>
public sealed class MinioSdkClientAdapter : IMinioClientAdapter
{
    private readonly IMinioClient _client;

    public MinioSdkClientAdapter(IMinioClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    public Task<bool> BucketExistsAsync(string bucketName, CancellationToken ct) =>
        _client.BucketExistsAsync(new BucketExistsArgs().WithBucket(bucketName), ct);

    public Task MakeBucketAsync(string bucketName, CancellationToken ct) =>
        _client.MakeBucketAsync(new MakeBucketArgs().WithBucket(bucketName), ct);

    public Task PutObjectAsync(string bucketName, string objectKey, Stream stream, long size, string contentType, CancellationToken ct) =>
        _client.PutObjectAsync(
            new PutObjectArgs()
                .WithBucket(bucketName)
                .WithObject(objectKey)
                .WithStreamData(stream)
                .WithObjectSize(size)
                .WithContentType(contentType),
            ct);
}

public sealed class MinioPcapStorageService : IPcapArchiveStorage
{
    private readonly IMinioClientAdapter _client;
    private readonly string _bucketName;

    public MinioPcapStorageService(IMinioClientAdapter client, string bucketName = "pcap-captures")
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentException.ThrowIfNullOrWhiteSpace(bucketName);
        _client = client;
        _bucketName = bucketName;
    }

    public MinioPcapStorageService(IMinioClient client, string bucketName = "pcap-captures")
        : this(new MinioSdkClientAdapter(client), bucketName)
    {
    }

    public MinioPcapStorageService(MinioStorageOptions options)
        : this(BuildMinioClient(options), options.BucketName)
    {
    }

    public static (string Endpoint, bool WithSsl) NormalizeEndpoint(string rawEndpoint, bool configuredSsl = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawEndpoint);
        var trimmed = rawEndpoint.Trim();

        if (trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            var uri = new Uri(trimmed);
            return (uri.Authority, true);
        }

        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            var uri = new Uri(trimmed);
            return (uri.Authority, configuredSsl);
        }

        var slashIndex = trimmed.IndexOf('/');
        var hostPort = slashIndex >= 0 ? trimmed[..slashIndex] : trimmed;
        return (hostPort, configuredSsl);
    }

    public static IMinioClient BuildMinioClient(MinioStorageOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Endpoint);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.BucketName);

        var (normalizedEndpoint, withSsl) = NormalizeEndpoint(options.Endpoint, options.WithSsl);

        var builder = new MinioClient()
            .WithEndpoint(normalizedEndpoint)
            .WithCredentials(options.AccessKey, options.SecretKey);

        if (withSsl)
        {
            builder = builder.WithSSL();
        }

        return builder.Build();
    }

    public static string GenerateObjectKey(Guid sessionId, string pcapFilePath)
    {
        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException("Session ID cannot be empty.", nameof(sessionId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(pcapFilePath);

        var fileName = Path.GetFileName(pcapFilePath);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            throw new ArgumentException("PCAP file path does not contain a valid file name.", nameof(pcapFilePath));
        }

        return $"captures/{sessionId:D}/{fileName}";
    }

    public async Task<string> ArchivePcapAsync(Guid sessionId, string pcapFilePath, CancellationToken ct)
    {
        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException("Session ID cannot be empty.", nameof(sessionId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(pcapFilePath);

        if (!File.Exists(pcapFilePath))
        {
            throw new FileNotFoundException($"PCAP file not found at '{pcapFilePath}'.", pcapFilePath);
        }

        var objectKey = GenerateObjectKey(sessionId, pcapFilePath);

        bool exists = await _client.BucketExistsAsync(_bucketName, ct);
        if (!exists)
        {
            await _client.MakeBucketAsync(_bucketName, ct);
        }

        var fileInfo = new FileInfo(pcapFilePath);
        await using var stream = File.OpenRead(pcapFilePath);

        var contentType = GetContentType(pcapFilePath);

        await _client.PutObjectAsync(
            _bucketName,
            objectKey,
            stream,
            fileInfo.Length,
            contentType,
            ct);

        return objectKey;
    }

    private static string GetContentType(string filePath) =>
        Path.GetExtension(filePath).ToLowerInvariant() switch
        {
            ".pcap" => "application/vnd.tcpdump.pcap",
            ".pcapng" => "application/x-pcapng",
            _ => "application/octet-stream"
        };
}
