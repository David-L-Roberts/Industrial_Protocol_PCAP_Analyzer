using Analyzer.Infrastructure.Storage;

namespace Analyzer.Infrastructure.Tests.Storage;

public class MinioPcapStorageServiceTests
{
    private static readonly Guid SessionId = Guid.Parse("12345678-1234-1234-1234-123456789abc");

    [Theory]
    [InlineData("feeder1.pcap", "captures/12345678-1234-1234-1234-123456789abc/feeder1.pcap")]
    [InlineData(@"C:\captures\substation\relay.pcapng", "captures/12345678-1234-1234-1234-123456789abc/relay.pcapng")]
    [InlineData("/var/log/pcaps/capture_001.pcap", "captures/12345678-1234-1234-1234-123456789abc/capture_001.pcap")]
    [InlineData("dir/with/spaces/test session.pcap", "captures/12345678-1234-1234-1234-123456789abc/test session.pcap")]
    public void GenerateObjectKey_ReturnsSanitizedDeterministicKey(string inputPath, string expectedKey)
    {
        var key = MinioPcapStorageService.GenerateObjectKey(SessionId, inputPath);

        Assert.Equal(expectedKey, key);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void GenerateObjectKey_ThrowsOnInvalidPath(string invalidPath)
    {
        Assert.Throws<ArgumentException>(() => MinioPcapStorageService.GenerateObjectKey(SessionId, invalidPath));
    }

    [Fact]
    public void GenerateObjectKey_ThrowsOnEmptyGuid()
    {
        Assert.Throws<ArgumentException>(() => MinioPcapStorageService.GenerateObjectKey(Guid.Empty, "capture.pcap"));
    }

    [Fact]
    public async Task ArchivePcapAsync_CreatesBucketIfMissingAndUploadsFile()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.pcap");
        try
        {
            await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04]);

            var fakeClient = new RecordingMinioAdapter { BucketExists = false };
            var service = new MinioPcapStorageService(fakeClient, "test-bucket");

            var key = await service.ArchivePcapAsync(SessionId, tempFile, CancellationToken.None);

            Assert.Equal($"captures/{SessionId:D}/{Path.GetFileName(tempFile)}", key);
            Assert.Contains("test-bucket", fakeClient.CreatedBuckets);
            var uploaded = Assert.Single(fakeClient.UploadedObjects);
            Assert.Equal("test-bucket", uploaded.Bucket);
            Assert.Equal(key, uploaded.Key);
            Assert.Equal(4, uploaded.Length);
            Assert.Equal("application/vnd.tcpdump.pcap", uploaded.ContentType);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, uploaded.Bytes);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public async Task ArchivePcapAsync_SetsAppropriateContentTypeForPcapng()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.pcapng");
        try
        {
            await File.WriteAllBytesAsync(tempFile, [0x0A, 0x0D, 0x0D, 0x0A]);

            var fakeClient = new RecordingMinioAdapter { BucketExists = true };
            var service = new MinioPcapStorageService(fakeClient, "captures");

            var key = await service.ArchivePcapAsync(SessionId, tempFile, CancellationToken.None);

            var uploaded = Assert.Single(fakeClient.UploadedObjects);
            Assert.Equal("application/x-pcapng", uploaded.ContentType);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public async Task ArchivePcapAsync_SkipsMakeBucketWhenBucketAlreadyExists()
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempFile, [0xFF]);

            var fakeClient = new RecordingMinioAdapter { BucketExists = true };
            var service = new MinioPcapStorageService(fakeClient, "existing-bucket");

            var key = await service.ArchivePcapAsync(SessionId, tempFile, CancellationToken.None);

            Assert.Empty(fakeClient.CreatedBuckets);
            Assert.Single(fakeClient.UploadedObjects);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public async Task ArchivePcapAsync_ThrowsFileNotFoundExceptionWhenFileDoesNotExist()
    {
        var fakeClient = new RecordingMinioAdapter();
        var service = new MinioPcapStorageService(fakeClient);

        await Assert.ThrowsAsync<FileNotFoundException>(
            () => service.ArchivePcapAsync(SessionId, "non_existent_file.pcap", CancellationToken.None));
    }

    private sealed class RecordingMinioAdapter : IMinioClientAdapter
    {
        public bool BucketExists { get; set; } = true;
        public List<string> CreatedBuckets { get; } = new();
        public List<UploadedObject> UploadedObjects { get; } = new();

        public Task<bool> BucketExistsAsync(string bucketName, CancellationToken ct) =>
            Task.FromResult(BucketExists);

        public Task MakeBucketAsync(string bucketName, CancellationToken ct)
        {
            CreatedBuckets.Add(bucketName);
            BucketExists = true;
            return Task.CompletedTask;
        }

        public async Task PutObjectAsync(string bucketName, string objectKey, Stream stream, long size, string contentType, CancellationToken ct)
        {
            using var ms = new MemoryStream();
            await stream.CopyToAsync(ms, ct);
            UploadedObjects.Add(new UploadedObject(bucketName, objectKey, size, contentType, ms.ToArray()));
        }
    }

    private sealed record UploadedObject(string Bucket, string Key, long Length, string ContentType, byte[] Bytes);
}
