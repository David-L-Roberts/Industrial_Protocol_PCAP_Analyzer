using Analyzer.IntegrationTests.Persistence;
using Npgsql;

namespace Analyzer.IntegrationTests;

public class TimescaleTestDatabaseCleanerTests
{
    private const string UnreachableConnectionString = "Host=127.0.0.1;Port=1;Database=unused;Username=u;Password=p;Timeout=1";

    [Fact]
    public async Task CleanupSessionsIfEnabledAsync_WhenKeepTestDataIsTrue_DoesNotOpenConnection()
    {
        // Port 1 is unreachable; if CleanupSessionsIfEnabledAsync attempts to open a connection when keepTestData=true, it will throw.
        await using var dataSource = NpgsqlDataSource.Create(UnreachableConnectionString);

        await TimescaleTestDatabaseCleaner.CleanupSessionsIfEnabledAsync(
            dataSource,
            [Guid.NewGuid()],
            keepTestData: true);
    }

    [Fact]
    public async Task CleanupSessionsIfEnabledAsync_WhenSessionIdsAreEmpty_DoesNotOpenConnection()
    {
        await using var dataSource = NpgsqlDataSource.Create(UnreachableConnectionString);

        await TimescaleTestDatabaseCleaner.CleanupSessionsIfEnabledAsync(
            dataSource,
            [Guid.Empty],
            keepTestData: false);
    }
}
