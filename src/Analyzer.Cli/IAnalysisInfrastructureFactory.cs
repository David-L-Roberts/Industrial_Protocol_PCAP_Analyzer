using Analyzer.Core.Interfaces;

namespace Analyzer.Cli;

public interface IAnalysisInfrastructureFactory
{
    IDataSink CreateDataSink(string connectionString, int batchSize);
    IFrameSource CreateFrameSource(AnalysisOptions options);
    IPcapArchiveStorage? CreateArchiver(AnalysisOptions options);
}

