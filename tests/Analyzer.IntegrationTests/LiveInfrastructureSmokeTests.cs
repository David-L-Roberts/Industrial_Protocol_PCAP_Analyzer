using System.Diagnostics;
using Analyzer.Infrastructure.Dissection;
using Analyzer.Infrastructure.Storage;
using Analyzer.IntegrationTests.Attributes;
using Analyzer.IntegrationTests.Configuration;
using Minio;
using Minio.DataModel.Args;
using Npgsql;

namespace Analyzer.IntegrationTests;

[IntegrationTrait]
public class LiveInfrastructureSmokeTests
{
    private readonly IntegrationTestConfig _config = IntegrationTestConfig.Load();

    [IntegrationFact]
    public async Task TimescaleDb_CanConnectAndVerifyRequiredSchemaAndExtension()
    {
        await using var dataSource = NpgsqlDataSource.Create(_config.TimescaleConnectionString);
        await using var conn = await dataSource.OpenConnectionAsync();

        await using (var extCmd = new NpgsqlCommand(
            "SELECT COUNT(*) FROM pg_extension WHERE extname = 'timescaledb';",
            conn))
        {
            var extCount = Convert.ToInt64(await extCmd.ExecuteScalarAsync());
            Assert.True(extCount == 1, "Expected 'timescaledb' extension to be installed in target database.");
        }

        string[] expectedTables =
        [
            "test_sessions",
            "device_pairs",
            "tag_definitions",
            "red_transactions",
            "tag_values",
            "captured_command_events",
            "modbus_raw_unmapped"
        ];

        foreach (var table in expectedTables)
        {
            await using var tableCmd = new NpgsqlCommand(
                "SELECT to_regclass(@tableName)::text;",
                conn);
            tableCmd.Parameters.AddWithValue("tableName", $"public.{table}");
            var regClass = await tableCmd.ExecuteScalarAsync() as string;
            Assert.False(
                string.IsNullOrWhiteSpace(regClass),
                $"Expected table 'public.{table}' from 001_init_timescaledb.sql to exist in TimescaleDB.");
        }
    }

    [IntegrationFact]
    public async Task Minio_CanConnectAndQueryBucketStatus()
    {
        using var client = MinioPcapStorageService.BuildMinioClient(_config.MinioOptions);

        // ListBucketsAsync performs an authenticated S3 GET / request against the MinIO server
        // and throws if the endpoint is unreachable or credentials are invalid.
        var listResult = await client.ListBucketsAsync(CancellationToken.None);
        Assert.NotNull(listResult);
    }

    [IntegrationFact]
    public async Task TShark_CanLocateAndExecuteVersionCheck()
    {
        var tsharkPath = _config.TSharkExecutablePath;
        Assert.False(string.IsNullOrWhiteSpace(tsharkPath), "TSHARK_PATH must not be empty.");

        // If TSHARK_PATH contains directory separators or is rooted, verify the file exists on disk first.
        if (Path.IsPathRooted(tsharkPath) ||
            tsharkPath.Contains(Path.DirectorySeparatorChar) ||
            tsharkPath.Contains(Path.AltDirectorySeparatorChar))
        {
            Assert.True(
                File.Exists(tsharkPath),
                $"Configured TSHARK_PATH '{tsharkPath}' does not exist on disk.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = tsharkPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("--version");

        using var process = new Process { StartInfo = startInfo };
        Assert.True(process.Start(), $"Failed to start tshark process at '{tsharkPath}'.");

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        await process.WaitForExitAsync();
        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        Assert.True(
            process.ExitCode == 0,
            $"tshark --version exited with code {process.ExitCode}. stderr: {stderr}");
        Assert.Contains("TShark", stdout, StringComparison.OrdinalIgnoreCase);

        // Also verify CreateTSharkStartInfo preserves the configured full/custom path
        var dissectStartInfo = TSharkStreamingFrameSource.CreateTSharkStartInfo("sample.pcap", tsharkPath);
        Assert.Equal(tsharkPath, dissectStartInfo.FileName);
    }
}
