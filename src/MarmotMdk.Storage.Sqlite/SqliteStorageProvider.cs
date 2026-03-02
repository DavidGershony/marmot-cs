using System.Text.Json;
using Microsoft.Data.Sqlite;
using MarmotMdk.Storage.Abstractions;

namespace MarmotMdk.Storage.Sqlite;

/// <summary>
/// SQLite-backed implementation of <see cref="IMdkStorageProvider"/>.
/// Uses a single long-lived connection with WAL mode for good read concurrency.
/// All queries use parameterised SQL to prevent injection.
/// </summary>
public sealed class SqliteStorageProvider : IMdkStorageProvider, IGroupStorage, IMessageStorage, IWelcomeStorage, IDisposable
{
    private readonly SqliteConnection _connection;

    public SqliteStorageProvider(string connectionString)
    {
        _connection = new SqliteConnection(connectionString);
        _connection.Open();

        // Enable WAL mode for better concurrent-read performance.
        using var pragma = _connection.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL;";
        pragma.ExecuteNonQuery();

        SqliteMigrations.Apply(_connection);
    }

    // ── IMdkStorageProvider ────────────────────────────────────────────
    public IGroupStorage Groups => this;
    public IMessageStorage Messages => this;
    public IWelcomeStorage Welcomes => this;

    // ================================================================
    // IGroupStorage
    // ================================================================

    async Task IGroupStorage.SaveGroupAsync(Group group, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO groups (group_id, state, name, image, group_data, epoch,
                                self_update_state, self_update_completed_at,
                                created_at, updated_at)
            VALUES (@group_id, @state, @name, @image, @group_data, @epoch,
                    @self_update_state, @self_update_completed_at,
                    @created_at, @updated_at);";
        BindGroupParams(cmd, group);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task<Group?> IGroupStorage.GetGroupAsync(MlsGroupId id, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM groups WHERE group_id = @group_id;";
        cmd.Parameters.AddWithValue("@group_id", id.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadGroup(reader) : null;
    }

    async Task<IReadOnlyList<Group>> IGroupStorage.GetGroupsAsync(GroupState? state, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        if (state.HasValue)
        {
            cmd.CommandText = "SELECT * FROM groups WHERE state = @state;";
            cmd.Parameters.AddWithValue("@state", state.Value.ToString());
        }
        else
        {
            cmd.CommandText = "SELECT * FROM groups;";
        }

        var results = new List<Group>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            results.Add(ReadGroup(reader));
        return results.AsReadOnly();
    }

    async Task IGroupStorage.UpdateGroupAsync(Group group, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            UPDATE groups SET
                state = @state,
                name = @name,
                image = @image,
                group_data = @group_data,
                epoch = @epoch,
                self_update_state = @self_update_state,
                self_update_completed_at = @self_update_completed_at,
                created_at = @created_at,
                updated_at = @updated_at
            WHERE group_id = @group_id;";
        BindGroupParams(cmd, group);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task IGroupStorage.DeleteGroupAsync(MlsGroupId id, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = "DELETE FROM groups WHERE group_id = @group_id;";
        cmd.Parameters.AddWithValue("@group_id", id.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task IGroupStorage.SaveGroupRelayAsync(GroupRelay relay, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT OR IGNORE INTO group_relays (group_id, relay_url)
            VALUES (@group_id, @relay_url);";
        cmd.Parameters.AddWithValue("@group_id", relay.GroupId.Value);
        cmd.Parameters.AddWithValue("@relay_url", relay.RelayUrl);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task<IReadOnlyList<GroupRelay>> IGroupStorage.GetGroupRelaysAsync(MlsGroupId groupId, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT group_id, relay_url FROM group_relays WHERE group_id = @group_id;";
        cmd.Parameters.AddWithValue("@group_id", groupId.Value);

        var results = new List<GroupRelay>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            results.Add(new GroupRelay(
                new MlsGroupId((byte[])reader["group_id"]),
                reader.GetString(reader.GetOrdinal("relay_url"))));
        }
        return results.AsReadOnly();
    }

    async Task IGroupStorage.DeleteGroupRelaysAsync(MlsGroupId groupId, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = "DELETE FROM group_relays WHERE group_id = @group_id;";
        cmd.Parameters.AddWithValue("@group_id", groupId.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task IGroupStorage.SaveExporterSecretAsync(GroupExporterSecret secret, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT OR REPLACE INTO exporter_secrets (group_id, epoch, secret)
            VALUES (@group_id, @epoch, @secret);";
        cmd.Parameters.AddWithValue("@group_id", secret.GroupId.Value);
        cmd.Parameters.AddWithValue("@epoch", (long)secret.Epoch);
        cmd.Parameters.AddWithValue("@secret", secret.Secret);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task<GroupExporterSecret?> IGroupStorage.GetExporterSecretAsync(MlsGroupId groupId, ulong epoch, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            SELECT group_id, epoch, secret FROM exporter_secrets
            WHERE group_id = @group_id AND epoch = @epoch;";
        cmd.Parameters.AddWithValue("@group_id", groupId.Value);
        cmd.Parameters.AddWithValue("@epoch", (long)epoch);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return null;

        return new GroupExporterSecret(
            new MlsGroupId((byte[])reader["group_id"]),
            (ulong)(long)reader["epoch"],
            (byte[])reader["secret"]);
    }

    // ================================================================
    // IMessageStorage
    // ================================================================

    async Task IMessageStorage.SaveMessageAsync(Message message, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO messages (id, group_id, sender_identity, content, epoch, state, created_at)
            VALUES (@id, @group_id, @sender_identity, @content, @epoch, @state, @created_at);";
        BindMessageParams(cmd, message);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task<Message?> IMessageStorage.GetMessageAsync(string id, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM messages WHERE id = @id;";
        cmd.Parameters.AddWithValue("@id", id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadMessage(reader) : null;
    }

    async Task<IReadOnlyList<Message>> IMessageStorage.GetMessagesAsync(
        MlsGroupId groupId,
        Pagination? pagination,
        MessageSortOrder order,
        CancellationToken ct)
    {
        var paging = pagination ?? new Pagination();
        var dir = order == MessageSortOrder.Ascending ? "ASC" : "DESC";

        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = $@"
            SELECT * FROM messages
            WHERE group_id = @group_id
            ORDER BY created_at {dir}
            LIMIT @limit OFFSET @offset;";
        cmd.Parameters.AddWithValue("@group_id", groupId.Value);
        cmd.Parameters.AddWithValue("@limit", paging.Limit);
        cmd.Parameters.AddWithValue("@offset", paging.Offset);

        var results = new List<Message>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            results.Add(ReadMessage(reader));
        return results.AsReadOnly();
    }

    async Task<Message?> IMessageStorage.GetLastMessageAsync(MlsGroupId groupId, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            SELECT * FROM messages
            WHERE group_id = @group_id
            ORDER BY created_at DESC
            LIMIT 1;";
        cmd.Parameters.AddWithValue("@group_id", groupId.Value);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadMessage(reader) : null;
    }

    async Task IMessageStorage.SaveProcessedMessageAsync(ProcessedMessage processed, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT OR REPLACE INTO processed_messages (event_id, group_id, state, processed_at)
            VALUES (@event_id, @group_id, @state, @processed_at);";
        cmd.Parameters.AddWithValue("@event_id", processed.EventId);
        cmd.Parameters.AddWithValue("@group_id", processed.GroupId.Value);
        cmd.Parameters.AddWithValue("@state", processed.State.ToString());
        cmd.Parameters.AddWithValue("@processed_at", processed.ProcessedAt.ToString("o"));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task<ProcessedMessage?> IMessageStorage.GetProcessedMessageAsync(string eventId, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM processed_messages WHERE event_id = @event_id;";
        cmd.Parameters.AddWithValue("@event_id", eventId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return null;

        return new ProcessedMessage(
            reader.GetString(reader.GetOrdinal("event_id")),
            new MlsGroupId((byte[])reader["group_id"]),
            Enum.Parse<ProcessedMessageState>(reader.GetString(reader.GetOrdinal("state"))),
            DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("processed_at"))));
    }

    async Task IMessageStorage.InvalidateMessagesAfterEpochAsync(MlsGroupId groupId, ulong epoch, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            DELETE FROM messages
            WHERE group_id = @group_id AND epoch > @epoch;";
        cmd.Parameters.AddWithValue("@group_id", groupId.Value);
        cmd.Parameters.AddWithValue("@epoch", (long)epoch);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    // ================================================================
    // IWelcomeStorage
    // ================================================================

    async Task IWelcomeStorage.SaveWelcomeAsync(Welcome welcome, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO welcomes (id, group_id, welcome_data, state, group_data,
                                  sender_nostr_pubkey, created_at)
            VALUES (@id, @group_id, @welcome_data, @state, @group_data,
                    @sender_nostr_pubkey, @created_at);";
        BindWelcomeParams(cmd, welcome);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task<Welcome?> IWelcomeStorage.GetWelcomeAsync(string id, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM welcomes WHERE id = @id;";
        cmd.Parameters.AddWithValue("@id", id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadWelcome(reader) : null;
    }

    async Task<IReadOnlyList<Welcome>> IWelcomeStorage.GetPendingWelcomesAsync(CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM welcomes WHERE state = @state;";
        cmd.Parameters.AddWithValue("@state", WelcomeState.Pending.ToString());

        var results = new List<Welcome>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            results.Add(ReadWelcome(reader));
        return results.AsReadOnly();
    }

    async Task IWelcomeStorage.UpdateWelcomeAsync(Welcome welcome, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            UPDATE welcomes SET
                group_id = @group_id,
                welcome_data = @welcome_data,
                state = @state,
                group_data = @group_data,
                sender_nostr_pubkey = @sender_nostr_pubkey,
                created_at = @created_at
            WHERE id = @id;";
        BindWelcomeParams(cmd, welcome);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task IWelcomeStorage.SaveProcessedWelcomeAsync(ProcessedWelcome processed, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT OR REPLACE INTO processed_welcomes (event_id, state, processed_at)
            VALUES (@event_id, @state, @processed_at);";
        cmd.Parameters.AddWithValue("@event_id", processed.EventId);
        cmd.Parameters.AddWithValue("@state", processed.State.ToString());
        cmd.Parameters.AddWithValue("@processed_at", processed.ProcessedAt.ToString("o"));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    async Task<ProcessedWelcome?> IWelcomeStorage.GetProcessedWelcomeAsync(string eventId, CancellationToken ct)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM processed_welcomes WHERE event_id = @event_id;";
        cmd.Parameters.AddWithValue("@event_id", eventId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return null;

        return new ProcessedWelcome(
            reader.GetString(reader.GetOrdinal("event_id")),
            Enum.Parse<ProcessedWelcomeState>(reader.GetString(reader.GetOrdinal("state"))),
            DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("processed_at"))));
    }

    // ================================================================
    // Snapshot operations
    // ================================================================

    public async Task<string> CreateSnapshotAsync(MlsGroupId groupId, CancellationToken ct = default)
    {
        var snapshotId = Guid.NewGuid().ToString("N");
        var groupIdBytes = groupId.Value;

        var snapshotData = new SnapshotData();

        // Collect group
        await using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = "SELECT * FROM groups WHERE group_id = @gid;";
            cmd.Parameters.AddWithValue("@gid", groupIdBytes);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            if (await r.ReadAsync(ct))
                snapshotData.Group = GroupToDto(ReadGroup(r));
        }

        // Collect relays
        await using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = "SELECT * FROM group_relays WHERE group_id = @gid;";
            cmd.Parameters.AddWithValue("@gid", groupIdBytes);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
                snapshotData.Relays.Add(new GroupRelayDto
                {
                    GroupId = Convert.ToBase64String((byte[])r["group_id"]),
                    RelayUrl = r.GetString(r.GetOrdinal("relay_url")),
                });
        }

        // Collect exporter secrets
        await using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = "SELECT * FROM exporter_secrets WHERE group_id = @gid;";
            cmd.Parameters.AddWithValue("@gid", groupIdBytes);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
                snapshotData.ExporterSecrets.Add(new ExporterSecretDto
                {
                    GroupId = Convert.ToBase64String((byte[])r["group_id"]),
                    Epoch = (ulong)(long)r["epoch"],
                    Secret = Convert.ToBase64String((byte[])r["secret"]),
                });
        }

        // Collect messages
        await using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = "SELECT * FROM messages WHERE group_id = @gid;";
            cmd.Parameters.AddWithValue("@gid", groupIdBytes);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
                snapshotData.Messages.Add(MessageToDto(ReadMessage(r)));
        }

        // Collect processed messages
        await using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = "SELECT * FROM processed_messages WHERE group_id = @gid;";
            cmd.Parameters.AddWithValue("@gid", groupIdBytes);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
                snapshotData.ProcessedMessages.Add(new ProcessedMessageDto
                {
                    EventId = r.GetString(r.GetOrdinal("event_id")),
                    GroupId = Convert.ToBase64String((byte[])r["group_id"]),
                    State = r.GetString(r.GetOrdinal("state")),
                    ProcessedAt = r.GetString(r.GetOrdinal("processed_at")),
                });
        }

        // Collect welcomes
        await using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = "SELECT * FROM welcomes WHERE group_id = @gid;";
            cmd.Parameters.AddWithValue("@gid", groupIdBytes);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
                snapshotData.Welcomes.Add(WelcomeToDto(ReadWelcome(r)));
        }

        // Collect processed welcomes (all, since they are not group-keyed)
        await using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = "SELECT * FROM processed_welcomes;";
            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
                snapshotData.ProcessedWelcomes.Add(new ProcessedWelcomeDto
                {
                    EventId = r.GetString(r.GetOrdinal("event_id")),
                    State = r.GetString(r.GetOrdinal("state")),
                    ProcessedAt = r.GetString(r.GetOrdinal("processed_at")),
                });
        }

        // Serialise and store the snapshot
        var json = JsonSerializer.SerializeToUtf8Bytes(snapshotData);

        await using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = @"
                INSERT INTO snapshots (id, group_id, data, created_at)
                VALUES (@id, @group_id, @data, @created_at);";
            cmd.Parameters.AddWithValue("@id", snapshotId);
            cmd.Parameters.AddWithValue("@group_id", groupIdBytes);
            cmd.Parameters.AddWithValue("@data", json);
            cmd.Parameters.AddWithValue("@created_at", DateTimeOffset.UtcNow.ToString("o"));
            await cmd.ExecuteNonQueryAsync(ct);
        }

        return snapshotId;
    }

    public async Task RollbackToSnapshotAsync(string snapshotId, CancellationToken ct = default)
    {
        byte[] data;
        byte[] groupIdBytes;

        await using (var cmd = _connection.CreateCommand())
        {
            cmd.CommandText = "SELECT group_id, data FROM snapshots WHERE id = @id;";
            cmd.Parameters.AddWithValue("@id", snapshotId);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            if (!await r.ReadAsync(ct))
                throw new KeyNotFoundException($"Snapshot '{snapshotId}' not found.");
            groupIdBytes = (byte[])r["group_id"];
            data = (byte[])r["data"];
        }

        var snap = JsonSerializer.Deserialize<SnapshotData>(data)
            ?? throw new InvalidOperationException("Failed to deserialise snapshot data.");

        using var tx = _connection.BeginTransaction();
        try
        {
            // Delete current data for this group
            await DeleteGroupDataAsync(groupIdBytes, ct);

            // Restore group
            if (snap.Group is not null)
            {
                var group = DtoToGroup(snap.Group);
                await using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT INTO groups (group_id, state, name, image, group_data, epoch,
                                        self_update_state, self_update_completed_at,
                                        created_at, updated_at)
                    VALUES (@group_id, @state, @name, @image, @group_data, @epoch,
                            @self_update_state, @self_update_completed_at,
                            @created_at, @updated_at);";
                BindGroupParams(cmd, group);
                await cmd.ExecuteNonQueryAsync(ct);
            }

            // Restore relays
            foreach (var dto in snap.Relays)
            {
                await using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT OR IGNORE INTO group_relays (group_id, relay_url)
                    VALUES (@group_id, @relay_url);";
                cmd.Parameters.AddWithValue("@group_id", Convert.FromBase64String(dto.GroupId));
                cmd.Parameters.AddWithValue("@relay_url", dto.RelayUrl);
                await cmd.ExecuteNonQueryAsync(ct);
            }

            // Restore exporter secrets
            foreach (var dto in snap.ExporterSecrets)
            {
                await using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO exporter_secrets (group_id, epoch, secret)
                    VALUES (@group_id, @epoch, @secret);";
                cmd.Parameters.AddWithValue("@group_id", Convert.FromBase64String(dto.GroupId));
                cmd.Parameters.AddWithValue("@epoch", (long)dto.Epoch);
                cmd.Parameters.AddWithValue("@secret", Convert.FromBase64String(dto.Secret));
                await cmd.ExecuteNonQueryAsync(ct);
            }

            // Restore messages
            foreach (var dto in snap.Messages)
            {
                var msg = DtoToMessage(dto);
                await using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT INTO messages (id, group_id, sender_identity, content, epoch, state, created_at)
                    VALUES (@id, @group_id, @sender_identity, @content, @epoch, @state, @created_at);";
                BindMessageParams(cmd, msg);
                await cmd.ExecuteNonQueryAsync(ct);
            }

            // Restore processed messages
            foreach (var dto in snap.ProcessedMessages)
            {
                await using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO processed_messages (event_id, group_id, state, processed_at)
                    VALUES (@event_id, @group_id, @state, @processed_at);";
                cmd.Parameters.AddWithValue("@event_id", dto.EventId);
                cmd.Parameters.AddWithValue("@group_id", Convert.FromBase64String(dto.GroupId));
                cmd.Parameters.AddWithValue("@state", dto.State);
                cmd.Parameters.AddWithValue("@processed_at", dto.ProcessedAt);
                await cmd.ExecuteNonQueryAsync(ct);
            }

            // Restore welcomes
            foreach (var dto in snap.Welcomes)
            {
                var w = DtoToWelcome(dto);
                await using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT INTO welcomes (id, group_id, welcome_data, state, group_data,
                                          sender_nostr_pubkey, created_at)
                    VALUES (@id, @group_id, @welcome_data, @state, @group_data,
                            @sender_nostr_pubkey, @created_at);";
                BindWelcomeParams(cmd, w);
                await cmd.ExecuteNonQueryAsync(ct);
            }

            // Restore processed welcomes (full replacement)
            await using (var delCmd = _connection.CreateCommand())
            {
                delCmd.CommandText = "DELETE FROM processed_welcomes;";
                await delCmd.ExecuteNonQueryAsync(ct);
            }

            foreach (var dto in snap.ProcessedWelcomes)
            {
                await using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO processed_welcomes (event_id, state, processed_at)
                    VALUES (@event_id, @state, @processed_at);";
                cmd.Parameters.AddWithValue("@event_id", dto.EventId);
                cmd.Parameters.AddWithValue("@state", dto.State);
                cmd.Parameters.AddWithValue("@processed_at", dto.ProcessedAt);
                await cmd.ExecuteNonQueryAsync(ct);
            }

            tx.Commit();
        }
        catch
        {
            tx.Rollback();
            throw;
        }
    }

    public async Task ReleaseSnapshotAsync(string snapshotId, CancellationToken ct = default)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = "DELETE FROM snapshots WHERE id = @id;";
        cmd.Parameters.AddWithValue("@id", snapshotId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task PruneSnapshotsAsync(MlsGroupId groupId, int keepCount, CancellationToken ct = default)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            DELETE FROM snapshots
            WHERE group_id = @group_id
              AND id NOT IN (
                  SELECT id FROM snapshots
                  WHERE group_id = @group_id
                  ORDER BY created_at DESC
                  LIMIT @keep
              );";
        cmd.Parameters.AddWithValue("@group_id", groupId.Value);
        cmd.Parameters.AddWithValue("@keep", keepCount);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    // ================================================================
    // IDisposable
    // ================================================================

    public void Dispose() => _connection.Dispose();

    // ================================================================
    // Private helpers -- parameter binding
    // ================================================================

    private static void BindGroupParams(SqliteCommand cmd, Group group)
    {
        cmd.Parameters.AddWithValue("@group_id", group.Id.Value);
        cmd.Parameters.AddWithValue("@state", group.State.ToString());
        cmd.Parameters.AddWithValue("@name", group.Name);
        cmd.Parameters.AddWithValue("@image", (object?)group.Image ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@group_data", (object?)group.GroupData ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@epoch", (long)group.Epoch);

        if (group.SelfUpdate is SelfUpdateState.Required)
        {
            cmd.Parameters.AddWithValue("@self_update_state", "Required");
            cmd.Parameters.AddWithValue("@self_update_completed_at", DBNull.Value);
        }
        else if (group.SelfUpdate is SelfUpdateState.CompletedAt completed)
        {
            cmd.Parameters.AddWithValue("@self_update_state", "CompletedAt");
            cmd.Parameters.AddWithValue("@self_update_completed_at", completed.Completed.ToString("o"));
        }
        else
        {
            cmd.Parameters.AddWithValue("@self_update_state", DBNull.Value);
            cmd.Parameters.AddWithValue("@self_update_completed_at", DBNull.Value);
        }

        cmd.Parameters.AddWithValue("@created_at", group.CreatedAt.ToString("o"));
        cmd.Parameters.AddWithValue("@updated_at", group.UpdatedAt.ToString("o"));
    }

    private static void BindMessageParams(SqliteCommand cmd, Message message)
    {
        cmd.Parameters.AddWithValue("@id", message.Id);
        cmd.Parameters.AddWithValue("@group_id", message.GroupId.Value);
        cmd.Parameters.AddWithValue("@sender_identity", message.SenderIdentity);
        cmd.Parameters.AddWithValue("@content", message.Content);
        cmd.Parameters.AddWithValue("@epoch", (long)message.Epoch);
        cmd.Parameters.AddWithValue("@state", message.State.ToString());
        cmd.Parameters.AddWithValue("@created_at", message.CreatedAt.ToString("o"));
    }

    private static void BindWelcomeParams(SqliteCommand cmd, Welcome welcome)
    {
        cmd.Parameters.AddWithValue("@id", welcome.Id);
        cmd.Parameters.AddWithValue("@group_id", welcome.GroupId.Value);
        cmd.Parameters.AddWithValue("@welcome_data", welcome.WelcomeData);
        cmd.Parameters.AddWithValue("@state", welcome.State.ToString());
        cmd.Parameters.AddWithValue("@group_data", (object?)welcome.GroupData ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@sender_nostr_pubkey", (object?)welcome.SenderNostrPubkey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@created_at", welcome.CreatedAt.ToString("o"));
    }

    // ================================================================
    // Private helpers -- reading rows
    // ================================================================

    private static Group ReadGroup(SqliteDataReader reader)
    {
        SelfUpdateState? selfUpdate = null;
        var selfUpdateStateStr = reader.IsDBNull(reader.GetOrdinal("self_update_state"))
            ? null
            : reader.GetString(reader.GetOrdinal("self_update_state"));

        if (selfUpdateStateStr == "Required")
        {
            selfUpdate = new SelfUpdateState.Required();
        }
        else if (selfUpdateStateStr == "CompletedAt")
        {
            var completedAt = DateTimeOffset.Parse(
                reader.GetString(reader.GetOrdinal("self_update_completed_at")));
            selfUpdate = new SelfUpdateState.CompletedAt(completedAt);
        }

        return new Group(
            new MlsGroupId((byte[])reader["group_id"]),
            Enum.Parse<GroupState>(reader.GetString(reader.GetOrdinal("state"))),
            reader.GetString(reader.GetOrdinal("name")),
            reader.IsDBNull(reader.GetOrdinal("image")) ? null : (byte[])reader["image"],
            reader.IsDBNull(reader.GetOrdinal("group_data")) ? null : (byte[])reader["group_data"],
            (ulong)(long)reader["epoch"],
            selfUpdate,
            DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("created_at"))),
            DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("updated_at"))));
    }

    private static Message ReadMessage(SqliteDataReader reader) =>
        new(
            reader.GetString(reader.GetOrdinal("id")),
            new MlsGroupId((byte[])reader["group_id"]),
            (byte[])reader["sender_identity"],
            (byte[])reader["content"],
            (ulong)(long)reader["epoch"],
            Enum.Parse<MessageState>(reader.GetString(reader.GetOrdinal("state"))),
            DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("created_at"))));

    private static Welcome ReadWelcome(SqliteDataReader reader) =>
        new(
            reader.GetString(reader.GetOrdinal("id")),
            new MlsGroupId((byte[])reader["group_id"]),
            (byte[])reader["welcome_data"],
            Enum.Parse<WelcomeState>(reader.GetString(reader.GetOrdinal("state"))),
            reader.IsDBNull(reader.GetOrdinal("group_data")) ? null : (byte[])reader["group_data"],
            reader.IsDBNull(reader.GetOrdinal("sender_nostr_pubkey"))
                ? null
                : reader.GetString(reader.GetOrdinal("sender_nostr_pubkey")),
            DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("created_at"))));

    // ================================================================
    // Private helpers -- delete group data (for rollback)
    // ================================================================

    private async Task DeleteGroupDataAsync(byte[] groupIdBytes, CancellationToken ct)
    {
        string[] tables = { "groups", "group_relays", "exporter_secrets", "messages", "processed_messages", "welcomes" };
        foreach (var table in tables)
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = $"DELETE FROM {table} WHERE group_id = @gid;";
            cmd.Parameters.AddWithValue("@gid", groupIdBytes);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    // ================================================================
    // Snapshot DTO types for JSON serialisation
    // ================================================================
    // These use Base64 strings for byte[] fields so they round-trip
    // cleanly through System.Text.Json.

    private sealed class SnapshotData
    {
        public GroupDto? Group { get; set; }
        public List<GroupRelayDto> Relays { get; set; } = new();
        public List<ExporterSecretDto> ExporterSecrets { get; set; } = new();
        public List<MessageDto> Messages { get; set; } = new();
        public List<ProcessedMessageDto> ProcessedMessages { get; set; } = new();
        public List<WelcomeDto> Welcomes { get; set; } = new();
        public List<ProcessedWelcomeDto> ProcessedWelcomes { get; set; } = new();
    }

    private sealed class GroupDto
    {
        public string GroupId { get; set; } = "";
        public string State { get; set; } = "";
        public string Name { get; set; } = "";
        public string? Image { get; set; }
        public string? GroupData { get; set; }
        public ulong Epoch { get; set; }
        public string? SelfUpdateState { get; set; }
        public string? SelfUpdateCompletedAt { get; set; }
        public string CreatedAt { get; set; } = "";
        public string UpdatedAt { get; set; } = "";
    }

    private sealed class GroupRelayDto
    {
        public string GroupId { get; set; } = "";
        public string RelayUrl { get; set; } = "";
    }

    private sealed class ExporterSecretDto
    {
        public string GroupId { get; set; } = "";
        public ulong Epoch { get; set; }
        public string Secret { get; set; } = "";
    }

    private sealed class MessageDto
    {
        public string Id { get; set; } = "";
        public string GroupId { get; set; } = "";
        public string SenderIdentity { get; set; } = "";
        public string Content { get; set; } = "";
        public ulong Epoch { get; set; }
        public string State { get; set; } = "";
        public string CreatedAt { get; set; } = "";
    }

    private sealed class ProcessedMessageDto
    {
        public string EventId { get; set; } = "";
        public string GroupId { get; set; } = "";
        public string State { get; set; } = "";
        public string ProcessedAt { get; set; } = "";
    }

    private sealed class WelcomeDto
    {
        public string Id { get; set; } = "";
        public string GroupId { get; set; } = "";
        public string WelcomeData { get; set; } = "";
        public string State { get; set; } = "";
        public string? GroupData { get; set; }
        public string? SenderNostrPubkey { get; set; }
        public string CreatedAt { get; set; } = "";
    }

    private sealed class ProcessedWelcomeDto
    {
        public string EventId { get; set; } = "";
        public string State { get; set; } = "";
        public string ProcessedAt { get; set; } = "";
    }

    // ================================================================
    // Domain <-> DTO mapping
    // ================================================================

    private static GroupDto GroupToDto(Group g) => new()
    {
        GroupId = Convert.ToBase64String(g.Id.Value),
        State = g.State.ToString(),
        Name = g.Name,
        Image = g.Image is not null ? Convert.ToBase64String(g.Image) : null,
        GroupData = g.GroupData is not null ? Convert.ToBase64String(g.GroupData) : null,
        Epoch = g.Epoch,
        SelfUpdateState = g.SelfUpdate switch
        {
            Abstractions.SelfUpdateState.Required => "Required",
            Abstractions.SelfUpdateState.CompletedAt => "CompletedAt",
            _ => null,
        },
        SelfUpdateCompletedAt = g.SelfUpdate is Abstractions.SelfUpdateState.CompletedAt c
            ? c.Completed.ToString("o")
            : null,
        CreatedAt = g.CreatedAt.ToString("o"),
        UpdatedAt = g.UpdatedAt.ToString("o"),
    };

    private static Group DtoToGroup(GroupDto dto)
    {
        SelfUpdateState? selfUpdate = dto.SelfUpdateState switch
        {
            "Required" => new SelfUpdateState.Required(),
            "CompletedAt" => new SelfUpdateState.CompletedAt(
                DateTimeOffset.Parse(dto.SelfUpdateCompletedAt!)),
            _ => null,
        };

        return new Group(
            new MlsGroupId(Convert.FromBase64String(dto.GroupId)),
            Enum.Parse<GroupState>(dto.State),
            dto.Name,
            dto.Image is not null ? Convert.FromBase64String(dto.Image) : null,
            dto.GroupData is not null ? Convert.FromBase64String(dto.GroupData) : null,
            dto.Epoch,
            selfUpdate,
            DateTimeOffset.Parse(dto.CreatedAt),
            DateTimeOffset.Parse(dto.UpdatedAt));
    }

    private static MessageDto MessageToDto(Message m) => new()
    {
        Id = m.Id,
        GroupId = Convert.ToBase64String(m.GroupId.Value),
        SenderIdentity = Convert.ToBase64String(m.SenderIdentity),
        Content = Convert.ToBase64String(m.Content),
        Epoch = m.Epoch,
        State = m.State.ToString(),
        CreatedAt = m.CreatedAt.ToString("o"),
    };

    private static Message DtoToMessage(MessageDto dto) => new(
        dto.Id,
        new MlsGroupId(Convert.FromBase64String(dto.GroupId)),
        Convert.FromBase64String(dto.SenderIdentity),
        Convert.FromBase64String(dto.Content),
        dto.Epoch,
        Enum.Parse<MessageState>(dto.State),
        DateTimeOffset.Parse(dto.CreatedAt));

    private static WelcomeDto WelcomeToDto(Welcome w) => new()
    {
        Id = w.Id,
        GroupId = Convert.ToBase64String(w.GroupId.Value),
        WelcomeData = Convert.ToBase64String(w.WelcomeData),
        State = w.State.ToString(),
        GroupData = w.GroupData is not null ? Convert.ToBase64String(w.GroupData) : null,
        SenderNostrPubkey = w.SenderNostrPubkey,
        CreatedAt = w.CreatedAt.ToString("o"),
    };

    private static Welcome DtoToWelcome(WelcomeDto dto) => new(
        dto.Id,
        new MlsGroupId(Convert.FromBase64String(dto.GroupId)),
        Convert.FromBase64String(dto.WelcomeData),
        Enum.Parse<WelcomeState>(dto.State),
        dto.GroupData is not null ? Convert.FromBase64String(dto.GroupData) : null,
        dto.SenderNostrPubkey,
        DateTimeOffset.Parse(dto.CreatedAt));
}
