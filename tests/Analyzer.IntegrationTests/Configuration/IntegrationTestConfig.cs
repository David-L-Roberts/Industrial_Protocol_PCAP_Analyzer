using System.Collections;
using System.Globalization;
using Analyzer.Infrastructure.Storage;
using Npgsql;

namespace Analyzer.IntegrationTests.Configuration;

public sealed record IntegrationTestConfig(
    string TimescaleConnectionString,
    MinioStorageOptions MinioOptions,
    string TSharkExecutablePath,
    bool KeepTestData)
{
    public static IntegrationTestConfig Load(
        string? searchDirectory = null,
        IReadOnlyDictionary<string, string?>? environmentOverrides = null)
    {
        var rootDir = FindRepoRoot(searchDirectory ?? AppContext.BaseDirectory);
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (rootDir is not null)
        {
            var envExamplePath = Path.Combine(rootDir, ".env.example");
            if (File.Exists(envExamplePath))
            {
                LoadEnvFileInto(envExamplePath, values);
            }

            var dotEnvPath = Path.Combine(rootDir, ".env");
            if (File.Exists(dotEnvPath))
            {
                LoadEnvFileInto(dotEnvPath, values);
            }
        }

        if (environmentOverrides is not null)
        {
            foreach (var kvp in environmentOverrides)
            {
                if (!string.IsNullOrWhiteSpace(kvp.Value))
                {
                    values[kvp.Key] = kvp.Value;
                }
            }
        }
        else
        {
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            {
                if (entry.Key is string key &&
                    entry.Value is string val &&
                    !string.IsNullOrWhiteSpace(val))
                {
                    values[key] = val;
                }
            }
        }

        var connectionString = ResolveConnectionString(values);
        var minioOptions = ResolveMinioOptions(values);
        var tsharkPath = ResolveTSharkExecutablePath(values);
        var keepTestData = IsTruthy(GetValueOrDefault(values, "KEEP_TEST_DATA", "false"));

        return new IntegrationTestConfig(
            TimescaleConnectionString: connectionString,
            MinioOptions: minioOptions,
            TSharkExecutablePath: tsharkPath,
            KeepTestData: keepTestData);
    }

    public static bool IsTruthy(string? raw) =>
        string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase);

    public static string? FindRepoRoot(string startDirectory)
    {
        var dir = new DirectoryInfo(startDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, ".env.example")) ||
                File.Exists(Path.Combine(dir.FullName, ".env")) ||
                File.Exists(Path.Combine(dir.FullName, "ProtocolAnalyzer.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        return null;
    }

    private static void LoadEnvFileInto(string filePath, Dictionary<string, string> target)
    {
        foreach (var rawLine in File.ReadLines(filePath))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            int eqIndex = line.IndexOf('=');
            if (eqIndex <= 0)
            {
                continue;
            }

            var key = line[..eqIndex].Trim();
            var value = line[(eqIndex + 1)..].Trim();

            if (value.Length >= 2 &&
                ((value.StartsWith('"') && value.EndsWith('"')) ||
                 (value.StartsWith('\'') && value.EndsWith('\''))))
            {
                value = value[1..^1];
            }

            if (key.Length > 0)
            {
                target[key] = value;
            }
        }
    }

    private static string ResolveConnectionString(Dictionary<string, string> values)
    {
        if (values.TryGetValue("TIMESCALE_CONNECTION_STRING", out var explicitConnStr) &&
            !string.IsNullOrWhiteSpace(explicitConnStr))
        {
            return explicitConnStr;
        }

        var host = GetValueOrDefault(values, "POSTGRES_HOST", "localhost");
        var portRaw = GetValueOrDefault(values, "POSTGRES_PORT", "5432");
        if (!int.TryParse(portRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int port))
        {
            port = 5432;
        }

        var database = GetValueOrDefault(values, "POSTGRES_DB", "protocol_analyzer");
        var username = GetValueOrDefault(values, "POSTGRES_USER", "analyzer");
        var password = GetValueOrDefault(values, "POSTGRES_PASSWORD", "analyzer_dev_password");

        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = host,
            Port = port,
            Database = database,
            Username = username,
            Password = password
        };

        return builder.ConnectionString;
    }

    private static MinioStorageOptions ResolveMinioOptions(Dictionary<string, string> values)
    {
        var endpoint = GetValueOrDefault(values, "MINIO_ENDPOINT", "localhost:9000");
        var accessKey = GetFirstNonEmpty(values, ["MINIO_ACCESS_KEY", "MINIO_ROOT_USER"], "minioadmin");
        var secretKey = GetFirstNonEmpty(values, ["MINIO_SECRET_KEY", "MINIO_ROOT_PASSWORD"], "minioadmin_dev_password");
        var bucket = GetValueOrDefault(values, "MINIO_BUCKET", "pcap-captures");
        var useSsl = IsTruthy(GetValueOrDefault(values, "MINIO_USE_SSL", "false"));

        return new MinioStorageOptions(
            Endpoint: endpoint,
            AccessKey: accessKey,
            SecretKey: secretKey,
            BucketName: bucket,
            WithSsl: useSsl);
    }

    private static string ResolveTSharkExecutablePath(Dictionary<string, string> values)
    {
        var configured = GetValueOrDefault(values, "TSHARK_PATH", "tshark");

        // If running on non-Windows (e.g., linux-x64) and the default Windows path from .env.example
        // is present and does not exist on disk, fall back to 'tshark' on PATH.
        if (!OperatingSystem.IsWindows() &&
            configured.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            !File.Exists(configured))
        {
            return "tshark";
        }

        // Conversely, on Windows, if 'tshark' is specified without a path and standard Wireshark installation exists:
        if (OperatingSystem.IsWindows() &&
            string.Equals(configured, "tshark", StringComparison.OrdinalIgnoreCase))
        {
            const string defaultWindowsWiresharkPath = @"C:\Program Files\Wireshark\tshark.exe";
            if (File.Exists(defaultWindowsWiresharkPath))
            {
                return defaultWindowsWiresharkPath;
            }
        }

        return configured;
    }

    private static string GetValueOrDefault(Dictionary<string, string> values, string key, string defaultValue) =>
        values.TryGetValue(key, out var found) && !string.IsNullOrWhiteSpace(found)
            ? found
            : defaultValue;

    private static string GetFirstNonEmpty(Dictionary<string, string> values, ReadOnlySpan<string> keys, string defaultValue)
    {
        foreach (var key in keys)
        {
            if (values.TryGetValue(key, out var found) && !string.IsNullOrWhiteSpace(found))
            {
                return found;
            }
        }

        return defaultValue;
    }
}
