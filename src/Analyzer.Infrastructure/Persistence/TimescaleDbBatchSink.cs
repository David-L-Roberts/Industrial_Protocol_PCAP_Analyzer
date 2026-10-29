using System.Collections.Concurrent;
using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;

namespace Analyzer.Infrastructure.Persistence;

public sealed class TimescaleDbBatchSink : IDataSink
{
    public const int DefaultBatchSize = 5000;

    private readonly IPostgresWriter _writer;
    private readonly int _batchSize;
    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<Guid, TagInitialState>> _initialStatesBySession = new();

    public TimescaleDbBatchSink(IPostgresWriter writer, int batchSize = DefaultBatchSize)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(batchSize);
        _writer = writer;
        _batchSize = batchSize;
    }

    public Task InitializeSessionAsync(
        TestSession session,
        IEnumerable<DeviceEndpointPair> pairs,
        IEnumerable<TagDefinition> tags,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(pairs);
        ArgumentNullException.ThrowIfNull(tags);

        var devicePairList = pairs as IReadOnlyList<DeviceEndpointPair> ?? pairs.ToArray();
        var tagList = tags as IReadOnlyList<TagDefinition> ?? tags.ToArray();

        return _writer.RunInTransactionAsync(
            async (tx, token) =>
            {
                const string insertSessionSql = """
                    INSERT INTO test_sessions (
                        id, name, pcap_file_name, s3_object_key,
                        timeout_threshold_ms, store_unmapped_registers, status
                    ) VALUES (
                        @id, @name, @pcap_file_name, @s3_object_key,
                        @timeout_threshold_ms, @store_unmapped_registers, @status
                    )
                    """;

                var sessionParams = new SqlParameterValue[]
                {
                    new("@id", session.Id, NpgsqlTypes.NpgsqlDbType.Uuid),
                    new("@name", session.Name, NpgsqlTypes.NpgsqlDbType.Varchar),
                    new("@pcap_file_name", session.PcapFileName, NpgsqlTypes.NpgsqlDbType.Varchar),
                    new("@s3_object_key", session.S3ObjectKey, NpgsqlTypes.NpgsqlDbType.Varchar),
                    new("@timeout_threshold_ms", session.TimeoutThresholdMs, NpgsqlTypes.NpgsqlDbType.Integer),
                    new("@store_unmapped_registers", session.StoreUnmappedRegisters, NpgsqlTypes.NpgsqlDbType.Boolean),
                    new("@status", PersistenceWireFormat.ToWire(SessionStatus.Processing), NpgsqlTypes.NpgsqlDbType.Varchar)
                };

                await tx.ExecuteAsync(insertSessionSql, sessionParams, token);

                if (devicePairList.Count > 0)
                {
                    await CopyInBatchesAsync(tx, TimescaleDbTables.DevicePairs, devicePairList, token);
                }

                if (tagList.Count > 0)
                {
                    await CopyInBatchesAsync(tx, TimescaleDbTables.TagDefinitions, tagList, token);
                }
            },
            ct);
    }

    public async Task WriteBatchAsync(ProtocolDecodeOutput batch, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(batch);

        if (batch.DataPoints.Count > 0)
        {
            foreach (var dp in batch.DataPoints)
            {
                var sessionStates = _initialStatesBySession.GetOrAdd(dp.SessionId, _ => new ConcurrentDictionary<Guid, TagInitialState>());
                sessionStates.TryAdd(dp.TagId, new TagInitialState(
                    dp.TagId,
                    dp.UnscaledNumericValue,
                    dp.ScaledNumericValue,
                    dp.BooleanValue,
                    dp.RawHex));
            }
        }

        if (batch.Transactions.Count == 0 &&
            batch.DataPoints.Count == 0 &&
            batch.CommandEvents.Count == 0 &&
            batch.UnmappedRegisters.Count == 0)
        {
            return;
        }

        await _writer.RunInTransactionAsync(
            async (tx, token) =>
            {
                await CopyInBatchesAsync(tx, TimescaleDbTables.RedTransactions, batch.Transactions, token);
                await CopyInBatchesAsync(tx, TimescaleDbTables.TagValues, batch.DataPoints, token);
                await CopyInBatchesAsync(tx, TimescaleDbTables.CapturedCommandEvents, batch.CommandEvents, token);
                await CopyInBatchesAsync(tx, TimescaleDbTables.ModbusRawUnmapped, batch.UnmappedRegisters, token);
            },
            ct);
    }

    public async Task UpdateTagInitialStatesAsync(Guid sessionId, CancellationToken ct)
    {
        if (!_initialStatesBySession.TryGetValue(sessionId, out var sessionStates) || sessionStates.IsEmpty)
        {
            return;
        }

        var states = sessionStates.Values.ToArray();
        if (states.Length == 0)
        {
            return;
        }

        await _writer.RunInTransactionAsync(
            async (tx, token) =>
            {
                const string updateSql = """
                    UPDATE tag_definitions AS t
                    SET initial_unscaled_numeric_value = v.unscaled,
                        initial_scaled_numeric_value = v.scaled,
                        initial_boolean_value = v.bool_val,
                        initial_raw_hex = v.raw_hex
                    FROM unnest(
                        @tag_ids,
                        @unscaled_values,
                        @scaled_values,
                        @boolean_values,
                        @raw_hexes
                    ) AS v(id, unscaled, scaled, bool_val, raw_hex)
                    WHERE t.id = v.id;
                    """;

                foreach (var chunk in states.Chunk(_batchSize))
                {
                    var tagIds = chunk.Select(s => s.TagId).ToArray();
                    var unscaledValues = chunk.Select(s => s.InitialUnscaledNumericValue).ToArray();
                    var scaledValues = chunk.Select(s => s.InitialScaledNumericValue).ToArray();
                    var boolValues = chunk.Select(s => s.InitialBooleanValue).ToArray();
                    var rawHexes = chunk.Select(s => s.InitialRawHex).ToArray();

                    var parameters = new SqlParameterValue[]
                    {
                        new("@tag_ids", tagIds, NpgsqlTypes.NpgsqlDbType.Array | NpgsqlTypes.NpgsqlDbType.Uuid),
                        new("@unscaled_values", unscaledValues, NpgsqlTypes.NpgsqlDbType.Array | NpgsqlTypes.NpgsqlDbType.Double),
                        new("@scaled_values", scaledValues, NpgsqlTypes.NpgsqlDbType.Array | NpgsqlTypes.NpgsqlDbType.Double),
                        new("@boolean_values", boolValues, NpgsqlTypes.NpgsqlDbType.Array | NpgsqlTypes.NpgsqlDbType.Boolean),
                        new("@raw_hexes", rawHexes, NpgsqlTypes.NpgsqlDbType.Array | NpgsqlTypes.NpgsqlDbType.Varchar)
                    };

                    await tx.ExecuteAsync(updateSql, parameters, token);
                }
            },
            ct);
    }

    public async Task CompleteSessionAsync(Guid sessionId, SessionStatus status, CancellationToken ct)
    {
        await _writer.RunInTransactionAsync(
            async (tx, token) =>
            {
                const string updateSql = """
                    UPDATE test_sessions
                    SET status = @status
                    WHERE id = @id;
                    """;

                var parameters = new SqlParameterValue[]
                {
                    new("@status", PersistenceWireFormat.ToWire(status), NpgsqlTypes.NpgsqlDbType.Varchar),
                    new("@id", sessionId, NpgsqlTypes.NpgsqlDbType.Uuid)
                };

                await tx.ExecuteAsync(updateSql, parameters, token);
            },
            ct);

        _initialStatesBySession.TryRemove(sessionId, out _);
    }

    private async Task CopyInBatchesAsync<TRecord>(
        IPostgresTransaction tx,
        CopyTableMap<TRecord> table,
        IReadOnlyList<TRecord> records,
        CancellationToken ct)
    {
        foreach (var chunk in records.Chunk(_batchSize))
        {
            await tx.CopyBinaryAsync(table.Target, Array.ConvertAll(chunk, table.ToRow), ct);
        }
    }
}
