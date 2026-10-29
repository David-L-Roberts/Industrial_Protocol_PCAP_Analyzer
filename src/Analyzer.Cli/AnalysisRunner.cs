using System.Diagnostics;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Pipeline;
using Analyzer.Core.Services;
using Analyzer.Decoders.Dnp3;
using Analyzer.Decoders.Dnp3.Handlers;
using Analyzer.Decoders.Dnp3.Registry;
using Analyzer.Decoders.Modbus;
using Analyzer.Infrastructure.Mapping;
using Microsoft.Extensions.DependencyInjection;

namespace Analyzer.Cli;

public class AnalysisRunner : IAnalysisRunner
{
    private readonly ManifestParser _manifestParser;
    private readonly CsvTagMappingLoader _csvLoader;
    private readonly IAnalysisInfrastructureFactory _infraFactory;

    public AnalysisRunner(
        ManifestParser manifestParser,
        CsvTagMappingLoader csvLoader,
        IAnalysisInfrastructureFactory infraFactory)
    {
        ArgumentNullException.ThrowIfNull(manifestParser);
        ArgumentNullException.ThrowIfNull(csvLoader);
        ArgumentNullException.ThrowIfNull(infraFactory);

        _manifestParser = manifestParser;
        _csvLoader = csvLoader;
        _infraFactory = infraFactory;
    }

    public async Task<PipelineExecutionSummary> RunAnalysisAsync(
        AnalysisOptions options,
        TextWriter? progressOutput = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ManifestPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DbConnectionString);

        if (!File.Exists(options.ManifestPath))
        {
            throw new FileNotFoundException($"Manifest file not found: '{options.ManifestPath}'", options.ManifestPath);
        }

        var manifestFullPath = Path.GetFullPath(options.ManifestPath);
        var manifestDir = Path.GetDirectoryName(manifestFullPath) ?? Directory.GetCurrentDirectory();

        progressOutput?.WriteLine($"Parsing session manifest '{manifestFullPath}'...");
        var parsedManifest = await _manifestParser.ParseFileAsync(manifestFullPath, ct);
        var session = parsedManifest.Session;
        var devicePairs = parsedManifest.DevicePairs.Select(p => p.DevicePair).ToList();

        var allTags = new List<TagDefinition>();
        foreach (var pairConfig in parsedManifest.DevicePairs)
        {
            if (string.IsNullOrWhiteSpace(pairConfig.TagMappingCsvPath))
            {
                continue;
            }

            var csvPath = Path.IsPathRooted(pairConfig.TagMappingCsvPath)
                ? pairConfig.TagMappingCsvPath
                : Path.Combine(manifestDir, pairConfig.TagMappingCsvPath);

            if (!File.Exists(csvPath))
            {
                throw new FileNotFoundException(
                    $"Tag mapping CSV file not found: '{csvPath}' for pair '{pairConfig.DevicePair.Name}'",
                    csvPath);
            }

            progressOutput?.WriteLine($"Loading tag mappings for pair '{pairConfig.DevicePair.Name}' from '{csvPath}'...");
            var tags = await _csvLoader.LoadFileAsync(csvPath, pairConfig.DevicePair.Id, pairConfig.DevicePair.Protocol, ct);
            allTags.AddRange(tags);
        }

        var resolvedPcapPath = Path.IsPathRooted(session.PcapFileName)
            ? session.PcapFileName
            : Path.Combine(manifestDir, session.PcapFileName);

        if (string.IsNullOrWhiteSpace(options.NdjsonInputPath) && !File.Exists(resolvedPcapPath))
        {
            throw new FileNotFoundException($"PCAP file not found: '{resolvedPcapPath}'", resolvedPcapPath);
        }

        var archiver = _infraFactory.CreateArchiver(options);
        if (archiver != null)
        {
            progressOutput?.WriteLine($"Archiving capture '{resolvedPcapPath}' to MinIO/S3 endpoint '{options.S3Endpoint}'...");
            var s3Key = await archiver.ArchivePcapAsync(session.Id, resolvedPcapPath, ct);
            session = session with { S3ObjectKey = s3Key };
            progressOutput?.WriteLine($"Capture archived with key: {s3Key}");
        }

        var frameSource = _infraFactory.CreateFrameSource(options);
        var dataSink = _infraFactory.CreateDataSink(options.DbConnectionString, options.BatchSize);

        var redEngine = new VirtualClockRedEngine(session.TimeoutThresholdMs);
        var tagEngine = new TagResolutionEngine(allTags);

        var sessionServices = new ServiceCollection();
        sessionServices.AddAnalyzerCoreServices();
        sessionServices.AddSingleton(_infraFactory);
        sessionServices.AddSingleton(options);
        sessionServices.AddSingleton(session);
        sessionServices.AddSingleton(redEngine);
        sessionServices.AddSingleton(tagEngine);
        sessionServices.AddSingleton(frameSource);
        sessionServices.AddSingleton(dataSink);

        var sessionSp = sessionServices.BuildServiceProvider();
        var orchestrator = sessionSp.GetRequiredService<IngestionPipelineOrchestrator>();

        progressOutput?.WriteLine($"Starting analysis session '{session.Name}' (ID: {session.Id})...");
        var stopwatch = Stopwatch.StartNew();

        var inputPath = !string.IsNullOrWhiteSpace(options.NdjsonInputPath) ? options.NdjsonInputPath : resolvedPcapPath;

        try
        {
            var summary = await orchestrator.RunAsync(
                session,
                devicePairs,
                allTags,
                inputPath,
                ct);

            stopwatch.Stop();

            if (progressOutput != null)
            {
                progressOutput.WriteLine("=================================================");
                progressOutput.WriteLine($"Session Completed: {session.Name} (ID: {session.Id}) in {stopwatch.Elapsed.TotalSeconds:F2}s");
                progressOutput.WriteLine($"Total frames processed: {summary.TotalFramesProcessed}");
                progressOutput.WriteLine($"Matched frames processed: {summary.MatchedFramesProcessed}");
                progressOutput.WriteLine($"Transactions: {summary.TotalTransactions} (Success: {summary.SuccessTransactions}, Errors: {summary.ErrorTransactions}, Timeouts: {summary.TimeoutTransactions}, Exceptions: {summary.ExceptionTransactions})");
                progressOutput.WriteLine($"Data points persisted: {summary.DataPointsPersisted}");
                progressOutput.WriteLine($"Command events persisted: {summary.CommandEventsPersisted}");
                if (session.StoreUnmappedRegisters)
                {
                    progressOutput.WriteLine($"Unmapped registers persisted: {summary.UnmappedRegistersPersisted}");
                }
                progressOutput.WriteLine("=================================================");
            }

            return summary;
        }
        catch
        {
            try
            {
                await dataSink.CompleteSessionAsync(session.Id, SessionStatus.Failed, CancellationToken.None);
            }
            catch
            {
                // Suppress secondary exception
            }

            throw;
        }
    }
}
