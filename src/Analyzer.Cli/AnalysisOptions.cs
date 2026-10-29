namespace Analyzer.Cli;

public record AnalysisOptions(
    string ManifestPath,
    string DbConnectionString,
    string? S3Endpoint = null,
    string? S3Bucket = "pcap-captures",
    string? S3AccessKey = null,
    string? S3SecretKey = null,
    bool S3WithSsl = false,
    string? NdjsonInputPath = null,
    string TSharkPath = "tshark",
    int BatchSize = 5000
);

