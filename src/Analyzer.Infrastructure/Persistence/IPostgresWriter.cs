using NpgsqlTypes;

namespace Analyzer.Infrastructure.Persistence;

/// <summary>
/// Port describing the minimal PostgreSQL operations <see cref="TimescaleDbBatchSink"/> needs.
/// Keeps the sink's batching, row mapping, and T0 logic testable without a live database.
/// </summary>
public interface IPostgresWriter
{
    /// <summary>
    /// Runs <paramref name="work"/> inside a single database transaction, committing on success
    /// and rolling back if the work throws.
    /// </summary>
    Task RunInTransactionAsync(Func<IPostgresTransaction, CancellationToken, Task> work, CancellationToken ct);
}

public interface IPostgresTransaction
{
    Task ExecuteAsync(string sql, IReadOnlyList<SqlParameterValue> parameters, CancellationToken ct);

    /// <summary>
    /// Streams <paramref name="rows"/> into <paramref name="target"/> using binary <c>COPY ... FROM STDIN</c>.
    /// Each row holds one value per <see cref="CopyTarget.Columns"/> entry, in order; <c>null</c> writes SQL NULL.
    /// </summary>
    Task CopyBinaryAsync(CopyTarget target, IReadOnlyList<object?[]> rows, CancellationToken ct);
}

public sealed record SqlParameterValue(string Name, object? Value, NpgsqlDbType DbType);

public sealed record CopyColumn(string Name, NpgsqlDbType DbType);

public sealed record CopyTarget(string TableName, IReadOnlyList<CopyColumn> Columns)
{
    public string ToCopyCommand() =>
        $"COPY {TableName} ({string.Join(", ", Columns.Select(c => c.Name))}) FROM STDIN (FORMAT BINARY)";
}

