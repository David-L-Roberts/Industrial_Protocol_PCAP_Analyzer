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

        return new TSharkStreamingFrameSource(tsharkExecutablePath: options.TSharkPath);
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

