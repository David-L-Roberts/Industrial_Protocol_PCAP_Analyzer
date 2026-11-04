using Analyzer.Infrastructure.Storage;
using Analyzer.IntegrationTests.Attributes;
using Analyzer.IntegrationTests.Configuration;
using Analyzer.IntegrationTests.Storage;
using Minio;
using Minio.DataModel.Args;
using Minio.Exceptions;

namespace Analyzer.IntegrationTests;

[IntegrationTrait]
public class LiveMinioPcapStorageServiceTests : IAsyncLifetime
{
    private readonly IntegrationTestConfig _config = IntegrationTestConfig.Load();
    private readonly List<string> _trackedObjectKeys = [];
    private IMinioClient _minioClient = default!;

    public Task InitializeAsync()
    {
        _minioClient = MinioPcapStorageService.BuildMinioClient(_config.MinioOptions);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        try
        {
            await MinioTestObjectCleaner.CleanupObjectsIfEnabledAsync(
                _minioClient,
                _config.MinioOptions.BucketName,
                _trackedObjectKeys,
                _config.KeepTestData);
        }
        finally
        {
            _minioClient.Dispose();
        }
    }

    [IntegrationTheory]
    [InlineData("Dnp3SampleCapture.pcap", "application/vnd.tcpdump.pcap")]
    [InlineData("ModbusSampleCapture.pcapng", "application/x-pcapng")]
    public async Task ArchivePcapAsync_UploadsRealCaptureFileAndVerifiesRemoteObjectMetadata(
        string sampleFileName,
        string expectedContentType)
    {
        var (pcapPath, sessionId, objectKey) = await ArchiveSampleCaptureAsync(sampleFileName);
        var expectedFileLength = new FileInfo(pcapPath).Length;

        Assert.Equal($"captures/{sessionId:D}/{sampleFileName}", objectKey);

        bool bucketExists = await _minioClient.BucketExistsAsync(
            new BucketExistsArgs().WithBucket(_config.MinioOptions.BucketName));
        Assert.True(bucketExists, $"Expected bucket '{_config.MinioOptions.BucketName}' to exist in MinIO.");

        var stat = await StatObjectAsync(objectKey);

        Assert.Equal(objectKey, stat.ObjectName);
        Assert.Equal(expectedFileLength, stat.Size);
        Assert.Equal(expectedContentType, stat.ContentType);
    }

    [IntegrationFact]
    public async Task CleanupObjectsIfEnabledAsync_PreservesObjectWhenKeepTestDataIsTrueAndDeletesWhenFalse()
    {
        var (pcapPath, _, objectKey) = await ArchiveSampleCaptureAsync("Dnp3SampleCapture.pcap");

        // 1. When keepTestData is true, object remains in MinIO
        await MinioTestObjectCleaner.CleanupObjectsIfEnabledAsync(
            _minioClient,
            _config.MinioOptions.BucketName,
            [objectKey],
            keepTestData: true);

        var statAfterKeep = await StatObjectAsync(objectKey);
        Assert.Equal(new FileInfo(pcapPath).Length, statAfterKeep.Size);

        // 2. When keepTestData is false, object is deleted from MinIO
        await MinioTestObjectCleaner.CleanupObjectsIfEnabledAsync(
            _minioClient,
            _config.MinioOptions.BucketName,
            [objectKey],
            keepTestData: false);

        await Assert.ThrowsAsync<ObjectNotFoundException>(() => StatObjectAsync(objectKey));
    }

    private async Task<(string PcapPath, Guid SessionId, string ObjectKey)> ArchiveSampleCaptureAsync(string sampleFileName)
    {
        var repoRoot = IntegrationTestConfig.FindRepoRoot(AppContext.BaseDirectory)
            ?? throw new InvalidOperationException("Could not locate repository root.");
        var pcapPath = Path.Combine(repoRoot, "docs", "inputs", sampleFileName);
        Assert.True(File.Exists(pcapPath), $"Expected sample capture file at '{pcapPath}'.");

        var sessionId = Guid.NewGuid();
        var service = new MinioPcapStorageService(_minioClient, _config.MinioOptions.BucketName);
        var objectKey = await service.ArchivePcapAsync(sessionId, pcapPath, CancellationToken.None);
        _trackedObjectKeys.Add(objectKey);

        return (pcapPath, sessionId, objectKey);
    }

    private Task<Minio.DataModel.ObjectStat> StatObjectAsync(string objectKey) =>
        _minioClient.StatObjectAsync(
            new StatObjectArgs()
                .WithBucket(_config.MinioOptions.BucketName)
                .WithObject(objectKey));
}
