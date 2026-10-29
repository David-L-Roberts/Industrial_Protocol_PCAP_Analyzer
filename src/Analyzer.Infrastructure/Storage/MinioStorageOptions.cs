namespace Analyzer.Infrastructure.Storage;

public sealed record MinioStorageOptions(
    string Endpoint,
    string AccessKey,
    string SecretKey,
    string BucketName = "pcap-captures",
    bool WithSsl = false
);

