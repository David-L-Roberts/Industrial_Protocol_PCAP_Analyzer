using NpgsqlTypes;

namespace Analyzer.Infrastructure.Persistence;

/// <summary>
/// Binds a domain record type to a target table: the ordered column list used for binary <c>COPY</c>
/// and the projection of a record into a row of column values.
/// </summary>
internal sealed class CopyTableMap<TRecord>
{
    private readonly Func<TRecord, object?>[] _projections;

    public CopyTableMap(string tableName, params (string Name, NpgsqlDbType DbType, Func<TRecord, object?> Project)[] columns)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tableName);
        if (columns.Length == 0)
        {
            throw new ArgumentException("A copy table map requires at least one column.", nameof(columns));
        }

        Target = new CopyTarget(tableName, columns.Select(c => new CopyColumn(c.Name, c.DbType)).ToArray());
        _projections = columns.Select(c => c.Project).ToArray();
    }

    public CopyTarget Target { get; }

    public object?[] ToRow(TRecord record)
    {
        var row = new object?[_projections.Length];
        for (int i = 0; i < _projections.Length; i++)
        {
            row[i] = _projections[i](record);
        }

        return row;
    }
}

