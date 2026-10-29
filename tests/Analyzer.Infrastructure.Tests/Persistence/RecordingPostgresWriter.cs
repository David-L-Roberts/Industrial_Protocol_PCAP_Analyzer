using Analyzer.Infrastructure.Persistence;

namespace Analyzer.Infrastructure.Tests.Persistence;

/// <summary>
/// In-memory <see cref="IPostgresWriter"/> that records every transaction and the operations issued inside it.
/// </summary>
internal sealed class RecordingPostgresWriter : IPostgresWriter
{
    public List<RecordedTransaction> Transactions { get; } = new();

    public IEnumerable<RecordedCopy> Copies => Transactions.SelectMany(t => t.Operations.OfType<RecordedCopy>());

    public IEnumerable<RecordedStatement> Statements => Transactions.SelectMany(t => t.Operations.OfType<RecordedStatement>());

    public Func<RecordedCopy, Exception?> CopyFailure { get; set; } = _ => null;

    public async Task RunInTransactionAsync(Func<IPostgresTransaction, CancellationToken, Task> work, CancellationToken ct)
    {
        var transaction = new RecordedTransaction(this);
        Transactions.Add(transaction);
        try
        {
            await work(transaction, ct);
            transaction.Committed = true;
        }
        catch
        {
            transaction.RolledBack = true;
            throw;
        }
    }

    internal sealed class RecordedTransaction(RecordingPostgresWriter owner) : IPostgresTransaction
    {
        public List<object> Operations { get; } = new();

        public bool Committed { get; set; }

        public bool RolledBack { get; set; }

        public Task ExecuteAsync(string sql, IReadOnlyList<SqlParameterValue> parameters, CancellationToken ct)
        {
            Operations.Add(new RecordedStatement(sql, parameters));
            return Task.CompletedTask;
        }

        public Task CopyBinaryAsync(CopyTarget target, IReadOnlyList<object?[]> rows, CancellationToken ct)
        {
            var copy = new RecordedCopy(target, rows.ToArray());
            var failure = owner.CopyFailure(copy);
            if (failure is not null)
            {
                throw failure;
            }

            Operations.Add(copy);
            return Task.CompletedTask;
        }
    }
}

internal sealed record RecordedStatement(string Sql, IReadOnlyList<SqlParameterValue> Parameters)
{
    public object? this[string parameterName] =>
        Parameters.Single(p => p.Name == parameterName).Value;
}

internal sealed record RecordedCopy(CopyTarget Target, IReadOnlyList<object?[]> Rows)
{
    public string TableName => Target.TableName;

    public IReadOnlyList<string> ColumnNames => Target.Columns.Select(c => c.Name).ToArray();

    /// <summary>Returns row <paramref name="rowIndex"/> as a column-name → value map.</summary>
    public IReadOnlyDictionary<string, object?> Row(int rowIndex) =>
        Target.Columns
            .Select((column, i) => (column.Name, Value: Rows[rowIndex][i]))
            .ToDictionary(x => x.Name, x => x.Value);
}

