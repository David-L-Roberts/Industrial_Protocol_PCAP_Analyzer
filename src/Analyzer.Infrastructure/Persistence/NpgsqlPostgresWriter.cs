using Npgsql;
using NpgsqlTypes;

namespace Analyzer.Infrastructure.Persistence;

/// <summary>
/// PostgreSQL adapter executing SQL statements and high-speed binary <c>COPY</c> via <see cref="NpgsqlBinaryImporter"/>.
/// </summary>
public sealed class NpgsqlPostgresWriter : IPostgresWriter, IAsyncDisposable, IDisposable
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly bool _ownsDataSource;

    public NpgsqlPostgresWriter(NpgsqlDataSource dataSource)
    {
        ArgumentNullException.ThrowIfNull(dataSource);
        _dataSource = dataSource;
        _ownsDataSource = false;
    }

    public NpgsqlPostgresWriter(string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        _dataSource = NpgsqlDataSource.Create(connectionString);
        _ownsDataSource = true;
    }

    public async Task RunInTransactionAsync(Func<IPostgresTransaction, CancellationToken, Task> work, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(work);

        await using var connection = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(ct);

        try
        {
            var adapter = new NpgsqlTransactionAdapter(connection, tx);
            await work(adapter, ct);
            await tx.CommitAsync(ct);
        }
        catch
        {
            try
            {
                await tx.RollbackAsync(ct);
            }
            catch
            {
                // Preserve original exception
            }
            throw;
        }
    }

    public void Dispose()
    {
        if (_ownsDataSource)
        {
            _dataSource.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_ownsDataSource)
        {
            await _dataSource.DisposeAsync();
        }
    }

    private sealed class NpgsqlTransactionAdapter : IPostgresTransaction
    {
        private readonly NpgsqlConnection _connection;
        private readonly NpgsqlTransaction _transaction;

        public NpgsqlTransactionAdapter(NpgsqlConnection connection, NpgsqlTransaction transaction)
        {
            _connection = connection;
            _transaction = transaction;
        }

        public async Task ExecuteAsync(string sql, IReadOnlyList<SqlParameterValue> parameters, CancellationToken ct)
        {
            await using var cmd = new NpgsqlCommand(sql, _connection, _transaction);
            foreach (var p in parameters)
            {
                var npgsqlParam = cmd.Parameters.Add(p.Name, p.DbType);
                npgsqlParam.Value = p.Value ?? DBNull.Value;
            }

            await cmd.ExecuteNonQueryAsync(ct);
        }

        public async Task CopyBinaryAsync(CopyTarget target, IReadOnlyList<object?[]> rows, CancellationToken ct)
        {
            if (rows.Count == 0)
            {
                return;
            }

            var copySql = target.ToCopyCommand();
            await using var importer = await _connection.BeginBinaryImportAsync(copySql, ct);

            var columns = target.Columns;
            int columnCount = columns.Count;

            foreach (var row in rows)
            {
                await importer.StartRowAsync(ct);
                for (int i = 0; i < columnCount; i++)
                {
                    var val = row[i];
                    if (val is null)
                    {
                        await importer.WriteNullAsync(ct);
                    }
                    else
                    {
                        await WriteValueAsync(importer, val, columns[i].DbType, ct);
                    }
                }
            }

            await importer.CompleteAsync(ct);
        }

        private static async Task WriteValueAsync(
            NpgsqlBinaryImporter importer,
            object val,
            NpgsqlDbType dbType,
            CancellationToken ct)
        {
            // Npgsql 8.0 WriteAsync has generic overload WriteAsync<T>(T value, NpgsqlDbType, ct)
            // Pattern matching on actual types ensures type-exact dispatch without runtime boxing overhead.
            switch (val)
            {
                case string s:
                    await importer.WriteAsync(s, dbType, ct);
                    break;
                case long l:
                    await importer.WriteAsync(l, dbType, ct);
                    break;
                case int intVal:
                    await importer.WriteAsync(intVal, dbType, ct);
                    break;
                case short sh:
                    await importer.WriteAsync(sh, dbType, ct);
                    break;
                case double d:
                    await importer.WriteAsync(d, dbType, ct);
                    break;
                case bool b:
                    await importer.WriteAsync(b, dbType, ct);
                    break;
                case Guid g:
                    await importer.WriteAsync(g, dbType, ct);
                    break;
                case DateTime dt:
                    await importer.WriteAsync(dt, dbType, ct);
                    break;
                case byte[] bytes:
                    await importer.WriteAsync(bytes, dbType, ct);
                    break;
                case System.Net.IPAddress ip:
                    await importer.WriteAsync(ip, dbType, ct);
                    break;
                default:
                    await importer.WriteAsync(val, dbType, ct);
                    break;
            }
        }
    }
}

