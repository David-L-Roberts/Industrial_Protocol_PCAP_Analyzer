using Npgsql;

namespace Analyzer.IntegrationTests.Persistence;

/// <summary>
/// Cleans up test session data in TimescaleDB via <c>SELECT delete_test_session(@sessionId)</c>
/// unless <c>KEEP_TEST_DATA</c> is enabled.
/// </summary>
public static class TimescaleTestDatabaseCleaner
{
    public const string DeleteSessionSql = "SELECT delete_test_session(@sessionId);";

    public static async Task CleanupSessionsIfEnabledAsync(
        NpgsqlDataSource dataSource,
        IEnumerable<Guid> sessionIds,
        bool keepTestData,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        ArgumentNullException.ThrowIfNull(sessionIds);

        if (keepTestData)
        {
            return;
        }

        var ids = sessionIds.Where(id => id != Guid.Empty).Distinct().ToArray();
        if (ids.Length == 0)
        {
            return;
        }

        await using var conn = await dataSource.OpenConnectionAsync(ct);
        foreach (var sessionId in ids)
        {
            await DeleteSessionAsync(conn, sessionId, ct);
        }
    }

    public static async Task DeleteSessionAsync(
        NpgsqlConnection connection,
        Guid sessionId,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (sessionId == Guid.Empty)
        {
            return;
        }

        await using var cmd = new NpgsqlCommand(DeleteSessionSql, connection);
        cmd.Parameters.AddWithValue("sessionId", sessionId);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
