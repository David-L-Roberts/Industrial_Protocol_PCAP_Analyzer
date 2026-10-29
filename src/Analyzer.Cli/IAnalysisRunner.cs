using Analyzer.Core.Domain;

namespace Analyzer.Cli;

public interface IAnalysisRunner
{
    Task<PipelineExecutionSummary> RunAnalysisAsync(
        AnalysisOptions options,
        TextWriter? progressOutput = null,
        CancellationToken ct = default);
}

