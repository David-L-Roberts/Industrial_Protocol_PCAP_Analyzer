using Analyzer.IntegrationTests.Configuration;

namespace Analyzer.IntegrationTests;

public class IntegrationTestConfigTests : IDisposable
{
    private readonly string _tempDir;

    public IntegrationTestConfigTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"AnalyzerEnvTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public void Load_WhenOnlyEnvExampleExists_ParsesDefaultSettingsAndBuildsConnectionString()
    {
        var envExamplePath = Path.Combine(_tempDir, ".env.example");
        File.WriteAllText(envExamplePath, """
            # Comment line
            POSTGRES_HOST=192.168.1.50
            POSTGRES_PORT=5433
            POSTGRES_DB=test_db
            POSTGRES_USER=test_user
            POSTGRES_PASSWORD="secret=password"
            MINIO_ENDPOINT=192.168.1.50:9000
            MINIO_ROOT_USER=minio_user
            MINIO_ROOT_PASSWORD=minio_pass
            MINIO_BUCKET=custom-bucket
            MINIO_USE_SSL=true
            TSHARK_PATH="C:\Custom\Wireshark\tshark.exe"
            KEEP_TEST_DATA=true
            """);

        var config = IntegrationTestConfig.Load(_tempDir, environmentOverrides: new Dictionary<string, string?>());

        var parsedConnStr = new Npgsql.NpgsqlConnectionStringBuilder(config.TimescaleConnectionString);
        Assert.Equal("192.168.1.50", parsedConnStr.Host);
        Assert.Equal(5433, parsedConnStr.Port);
        Assert.Equal("test_db", parsedConnStr.Database);
        Assert.Equal("test_user", parsedConnStr.Username);
        Assert.Equal("secret=password", parsedConnStr.Password);

        Assert.Equal("192.168.1.50:9000", config.MinioOptions.Endpoint);
        Assert.Equal("minio_user", config.MinioOptions.AccessKey);
        Assert.Equal("minio_pass", config.MinioOptions.SecretKey);
        Assert.Equal("custom-bucket", config.MinioOptions.BucketName);
        Assert.True(config.MinioOptions.WithSsl);

        Assert.Equal(@"C:\Custom\Wireshark\tshark.exe", config.TSharkExecutablePath);
        Assert.True(config.KeepTestData);
    }

    [Fact]
    public void Load_WhenDotEnvAndEnvOverridesExist_AppliesPrecedenceOrder()
    {
        File.WriteAllText(Path.Combine(_tempDir, ".env.example"), """
            POSTGRES_HOST=example-host
            POSTGRES_PORT=5432
            POSTGRES_DB=example_db
            POSTGRES_USER=example_user
            POSTGRES_PASSWORD=example_pass
            MINIO_ENDPOINT=example-minio:9000
            MINIO_ROOT_USER=example_minio
            MINIO_ROOT_PASSWORD=example_minio_pass
            MINIO_BUCKET=example-bucket
            TSHARK_PATH=tshark
            """);

        File.WriteAllText(Path.Combine(_tempDir, ".env"), """
            POSTGRES_HOST=dotenv-host
            MINIO_BUCKET=dotenv-bucket
            TSHARK_PATH=/usr/local/bin/tshark
            """);

        var overrides = new Dictionary<string, string?>
        {
            ["MINIO_BUCKET"] = "override-bucket",
            ["TIMESCALE_CONNECTION_STRING"] = "Host=explicit-host;Port=5432;Database=explicit;Username=u;Password=p"
        };

        var config = IntegrationTestConfig.Load(_tempDir, overrides);

        Assert.Equal("Host=explicit-host;Port=5432;Database=explicit;Username=u;Password=p", config.TimescaleConnectionString);
        Assert.Equal("override-bucket", config.MinioOptions.BucketName);
        Assert.Equal("example-minio:9000", config.MinioOptions.Endpoint);
        Assert.Equal("/usr/local/bin/tshark", config.TSharkExecutablePath);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
        {
            Directory.Delete(_tempDir, recursive: true);
        }
    }
}
