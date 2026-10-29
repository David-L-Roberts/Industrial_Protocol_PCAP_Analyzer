using Analyzer.Core.Domain;
using Analyzer.Cli;
using Xunit;

namespace Analyzer.Cli.Tests;

public class AnalyzerCliAppTests
{
    [Fact]
    public async Task RunAsync_WithValidAnalyzeArguments_CallsRunnerAndReturnsZeroExitCode()
    {
        var fakeRunner = new FakeAnalysisRunner();
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        string[] args =
        [
            "analyze",
            "--manifest", "test_manifest.json",
            "--db", "Host=localhost;Database=testdb",
            "--s3-endpoint", "http://127.0.0.1:9000",
            "--s3-bucket", "custom-bucket",
            "--ndjson-input", "preparsed.ndjson"
        ];

        int exitCode = await AnalyzerCliApp.RunAsync(args, fakeRunner, stdout, stderr);

        Assert.Equal(0, exitCode);
        Assert.NotNull(fakeRunner.LastOptions);
        Assert.Equal("test_manifest.json", fakeRunner.LastOptions.ManifestPath);
        Assert.Equal("Host=localhost;Database=testdb", fakeRunner.LastOptions.DbConnectionString);
        Assert.Equal("http://127.0.0.1:9000", fakeRunner.LastOptions.S3Endpoint);
        Assert.Equal("custom-bucket", fakeRunner.LastOptions.S3Bucket);
        Assert.Equal("preparsed.ndjson", fakeRunner.LastOptions.NdjsonInputPath);
    }

    [Fact]
    public async Task RunAsync_WithMissingRequiredArguments_ReturnsNonZeroExitCode()
    {
        var fakeRunner = new FakeAnalysisRunner();
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        string[] args = ["analyze"]; // Missing --manifest and --db

        int exitCode = await AnalyzerCliApp.RunAsync(args, fakeRunner, stdout, stderr);

        Assert.NotEqual(0, exitCode);
        Assert.Null(fakeRunner.LastOptions);
    }

    [Fact]
    public async Task RunAsync_WhenRunnerThrows_ReturnsNonZeroExitCodeAndOutputsError()
    {
        var fakeRunner = new FakeAnalysisRunner
        {
            ThrowException = new InvalidOperationException("Fatal database failure")
        };
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        string[] args =
        [
            "analyze",
            "--manifest", "manifest.json",
            "--db", "Host=localhost;Database=testdb"
        ];

        int exitCode = await AnalyzerCliApp.RunAsync(args, fakeRunner, stdout, stderr);

        Assert.Equal(1, exitCode);
        string errOutput = stderr.ToString();
        Assert.Contains("Fatal database failure", errOutput);
    }

    private sealed class FakeAnalysisRunner : IAnalysisRunner
    {
        public AnalysisOptions? LastOptions { get; private set; }
        public Exception? ThrowException { get; set; }

        public Task<PipelineExecutionSummary> RunAnalysisAsync(
            AnalysisOptions options,
            TextWriter? progressOutput = null,
            CancellationToken ct = default)
        {
            LastOptions = options;
            if (ThrowException != null)
            {
                throw ThrowException;
            }

            return Task.FromResult(new PipelineExecutionSummary(10, 10, 5, 5, 0, 0, 0, 20, 2, 0));
        }
    }
}

