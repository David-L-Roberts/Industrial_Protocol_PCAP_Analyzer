using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.IO;
using System.CommandLine.Parsing;
using Microsoft.Extensions.DependencyInjection;

namespace Analyzer.Cli;

public static class AnalyzerCliApp
{
    public static RootCommand BuildRootCommand(
        IAnalysisRunner runner,
        TextWriter? stdout = null,
        TextWriter? stderr = null)
    {
        ArgumentNullException.ThrowIfNull(runner);

        var rootCommand = new RootCommand("Industrial Protocol PCAP Analyzer (FAT/SAT)");

        var manifestOption = new Option<string>(
            aliases: ["--manifest", "-m"],
            description: "Path to session manifest JSON file")
        {
            IsRequired = true
        };

        var dbOption = new Option<string>(
            aliases: ["--db", "-d"],
            description: "TimescaleDB / PostgreSQL connection string")
        {
            IsRequired = true
        };

        var s3EndpointOption = new Option<string?>(
            aliases: ["--s3-endpoint"],
            description: "Optional MinIO/S3 endpoint URL (e.g. http://localhost:9000)");

        var s3BucketOption = new Option<string>(
            aliases: ["--s3-bucket"],
            getDefaultValue: () => "pcap-captures",
            description: "MinIO/S3 bucket name for PCAP archive");

        var s3AccessKeyOption = new Option<string?>(
            aliases: ["--s3-access-key"],
            description: "MinIO/S3 access key");

        var s3SecretKeyOption = new Option<string?>(
            aliases: ["--s3-secret-key"],
            description: "MinIO/S3 secret key");

        var s3SslOption = new Option<bool>(
            aliases: ["--s3-ssl"],
            getDefaultValue: () => false,
            description: "MinIO/S3 enable SSL");

        var ndjsonInputOption = new Option<string?>(
            aliases: ["--ndjson-input"],
            description: "Optional pre-dissected tshark NDJSON file path (skips running tshark)");

        var tsharkPathOption = new Option<string>(
            aliases: ["--tshark"],
            getDefaultValue: () => "tshark",
            description: "Path to tshark executable");

        var batchSizeOption = new Option<int>(
            aliases: ["--batch-size"],
            getDefaultValue: () => 5000,
            description: "Batch size for database bulk copy");

        var analyzeCommand = new Command("analyze", "Execute a full FAT/SAT PCAP analysis session.");
        analyzeCommand.AddOption(manifestOption);
        analyzeCommand.AddOption(dbOption);
        analyzeCommand.AddOption(s3EndpointOption);
        analyzeCommand.AddOption(s3BucketOption);
        analyzeCommand.AddOption(s3AccessKeyOption);
        analyzeCommand.AddOption(s3SecretKeyOption);
        analyzeCommand.AddOption(s3SslOption);
        analyzeCommand.AddOption(ndjsonInputOption);
        analyzeCommand.AddOption(tsharkPathOption);
        analyzeCommand.AddOption(batchSizeOption);

        analyzeCommand.SetHandler(async (context) =>
        {
            var manifest = context.ParseResult.GetValueForOption(manifestOption)!;
            var db = context.ParseResult.GetValueForOption(dbOption)!;
            var s3Endpoint = context.ParseResult.GetValueForOption(s3EndpointOption);
            var s3Bucket = context.ParseResult.GetValueForOption(s3BucketOption) ?? "pcap-captures";
            var s3Access = context.ParseResult.GetValueForOption(s3AccessKeyOption);
            var s3Secret = context.ParseResult.GetValueForOption(s3SecretKeyOption);
            var s3Ssl = context.ParseResult.GetValueForOption(s3SslOption);
            var ndjson = context.ParseResult.GetValueForOption(ndjsonInputOption);
            var tshark = context.ParseResult.GetValueForOption(tsharkPathOption) ?? "tshark";
            var batchSize = context.ParseResult.GetValueForOption(batchSizeOption);

            var options = new AnalysisOptions(
                ManifestPath: manifest,
                DbConnectionString: db,
                S3Endpoint: s3Endpoint,
                S3Bucket: s3Bucket,
                S3AccessKey: s3Access,
                S3SecretKey: s3Secret,
                S3WithSsl: s3Ssl,
                NdjsonInputPath: ndjson,
                TSharkPath: tshark,
                BatchSize: batchSize);

            try
            {
                var summary = await runner.RunAnalysisAsync(options, stdout, context.GetCancellationToken());
                context.ExitCode = 0;
            }
            catch (Exception ex)
            {
                stderr?.WriteLine($"Error: {ex.Message}");
                context.ExitCode = 1;
            }
        });

        rootCommand.AddCommand(analyzeCommand);
        return rootCommand;
    }

    public static async Task<int> RunAsync(
        string[] args,
        IAnalysisRunner? runner = null,
        TextWriter? stdout = null,
        TextWriter? stderr = null)
    {
        stdout ??= Console.Out;
        stderr ??= Console.Error;

        if (runner == null)
        {
            var services = new ServiceCollection();
            services.AddAnalyzerCoreServices();
            var sp = services.BuildServiceProvider();
            runner = sp.GetRequiredService<IAnalysisRunner>();
        }

        var rootCommand = BuildRootCommand(runner, stdout, stderr);
        var parser = new CommandLineBuilder(rootCommand)
            .UseDefaults()
            .Build();

        var console = new TextWriterConsole(stdout, stderr);
        return await parser.InvokeAsync(args, console);
    }

    private sealed class TextWriterConsole(TextWriter stdout, TextWriter stderr) : IConsole
    {
        public IStandardStreamWriter Out { get; } = StandardStreamWriter.Create(stdout);
        public bool IsOutputRedirected => true;
        public IStandardStreamWriter Error { get; } = StandardStreamWriter.Create(stderr);
        public bool IsErrorRedirected => true;
        public bool IsInputRedirected => true;
    }
}

