using Analyzer.Core.Interfaces;
using Analyzer.Infrastructure.Dissection;
using Analyzer.Infrastructure.Persistence;
using Analyzer.Infrastructure.Storage;

namespace Analyzer.Cli;

public sealed class DefaultAnalysisInfrastructureFactory : IAnalysisInfrastructureFactory
{
    public IDataSink CreateDataSink(string connectionString, int batchSize)
    {
        var writer = new NpgsqlPostgresWriter(connectionString);
        return new TimescaleDbBatchSink(writer, batchSize);
    }

    public IFrameSource CreateFrameSource(AnalysisOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!string.IsNullOrWhiteSpace(options.NdjsonInputPath))
        {
            return new TSharkStreamingFrameSource(
                streamProvider: (path, ct) => Task.FromResult<Stream>(File.OpenRead(options.NdjsonInputPath)));
        }

        var tsharkPath = ResolveTSharkPath(options.TSharkPath);
        return new TSharkStreamingFrameSource(tsharkExecutablePath: tsharkPath);
    }

    private static string ResolveTSharkPath(string configured)
    {
        if (string.IsNullOrWhiteSpace(configured) || string.Equals(configured, "tshark", StringComparison.OrdinalIgnoreCase))
        {
            var envTshark = Environment.GetEnvironmentVariable("TSHARK_PATH");
            if (!string.IsNullOrWhiteSpace(envTshark) && File.Exists(envTshark))
            {
                return envTshark;
            }

            if (OperatingSystem.IsWindows())
            {
                const string defaultWindowsWiresharkPath = @"C:\Program Files\Wireshark\tshark.exe";
                if (File.Exists(defaultWindowsWiresharkPath))
                {
                    return defaultWindowsWiresharkPath;
                }
            }
        }

        return configured;
    }

    public IPcapArchiveStorage? CreateArchiver(AnalysisOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.S3Endpoint))
        {
            return null;
        }

        var minioOptions = new MinioStorageOptions(
            Endpoint: options.S3Endpoint,
            AccessKey: options.S3AccessKey ?? "minioadmin",
            SecretKey: options.S3SecretKey ?? "minioadmin",
            BucketName: options.S3Bucket ?? "pcap-captures",
            WithSsl: options.S3WithSsl);

        return new MinioPcapStorageService(minioOptions);
    }
}

