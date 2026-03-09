using Microsoft.Data.Sqlite;

namespace MarmotCs.Storage.Sqlite;

/// <summary>
/// Manages schema versioning and migrations for the SQLite storage backend.
/// Each migration is applied exactly once and the current version is tracked
/// in a <c>schema_version</c> table.
/// </summary>
internal static class SqliteMigrations
{
    private static readonly (int Version, string Name, Action<SqliteConnection> Apply)[] Migrations =
    {
        (1, "Core tables", V001),
        (2, "Snapshots table", V002),
        (3, "Add indexes", V003),
        (4, "Message sort index", V004),
    };

    /// <summary>
    /// Applies all pending migrations to the given open connection.
    /// </summary>
    public static void Apply(SqliteConnection connection)
    {
        EnsureSchemaVersionTable(connection);

        var currentVersion = GetCurrentVersion(connection);

        foreach (var (version, name, apply) in Migrations)
        {
            if (version <= currentVersion)
                continue;

            using var transaction = connection.BeginTransaction();
            try
            {
                apply(connection);
                RecordVersion(connection, version, name);
                transaction.Commit();
            }
            catch
            {
                transaction.Rollback();
                throw;
            }
        }
    }

    // ────────────────────────────────────────────────────────────────
    // Schema version tracking
    // ────────────────────────────────────────────────────────────────

    private static void EnsureSchemaVersionTable(SqliteConnection connection)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS schema_version (
                version     INTEGER PRIMARY KEY,
                name        TEXT    NOT NULL,
                applied_at  TEXT    NOT NULL
            );";
        cmd.ExecuteNonQuery();
    }

    private static int GetCurrentVersion(SqliteConnection connection)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COALESCE(MAX(version), 0) FROM schema_version;";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    private static void RecordVersion(SqliteConnection connection, int version, string name)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO schema_version (version, name, applied_at)
            VALUES (@version, @name, @applied_at);";
        cmd.Parameters.AddWithValue("@version", version);
        cmd.Parameters.AddWithValue("@name", name);
        cmd.Parameters.AddWithValue("@applied_at", DateTimeOffset.UtcNow.ToString("o"));
        cmd.ExecuteNonQuery();
    }

    // ────────────────────────────────────────────────────────────────
    // V001 – Core tables
    // ────────────────────────────────────────────────────────────────

    private static void V001(SqliteConnection connection)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE groups (
                group_id                    BLOB    NOT NULL PRIMARY KEY,
                state                       TEXT    NOT NULL,
                name                        TEXT    NOT NULL,
                image                       BLOB,
                group_data                  BLOB,
                epoch                       INTEGER NOT NULL,
                self_update_state           TEXT,
                self_update_completed_at    TEXT,
                created_at                  TEXT    NOT NULL,
                updated_at                  TEXT    NOT NULL
            );

            CREATE TABLE messages (
                id                  TEXT    NOT NULL PRIMARY KEY,
                group_id            BLOB   NOT NULL,
                sender_identity     BLOB   NOT NULL,
                content             BLOB   NOT NULL,
                epoch               INTEGER NOT NULL,
                state               TEXT    NOT NULL,
                created_at          TEXT    NOT NULL
            );

            CREATE TABLE processed_messages (
                event_id        TEXT    NOT NULL PRIMARY KEY,
                group_id        BLOB   NOT NULL,
                state           TEXT    NOT NULL,
                processed_at    TEXT    NOT NULL
            );

            CREATE TABLE welcomes (
                id                      TEXT    NOT NULL PRIMARY KEY,
                group_id                BLOB   NOT NULL,
                welcome_data            BLOB   NOT NULL,
                state                   TEXT    NOT NULL,
                group_data              BLOB,
                sender_nostr_pubkey     TEXT,
                created_at              TEXT    NOT NULL
            );

            CREATE TABLE processed_welcomes (
                event_id        TEXT    NOT NULL PRIMARY KEY,
                state           TEXT    NOT NULL,
                processed_at    TEXT    NOT NULL
            );

            CREATE TABLE group_relays (
                group_id    BLOB    NOT NULL,
                relay_url   TEXT    NOT NULL,
                PRIMARY KEY (group_id, relay_url)
            );

            CREATE TABLE exporter_secrets (
                group_id    BLOB    NOT NULL,
                epoch       INTEGER NOT NULL,
                secret      BLOB    NOT NULL,
                PRIMARY KEY (group_id, epoch)
            );";
        cmd.ExecuteNonQuery();
    }

    // ────────────────────────────────────────────────────────────────
    // V002 – Snapshots table
    // ────────────────────────────────────────────────────────────────

    private static void V002(SqliteConnection connection)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE snapshots (
                id          TEXT    NOT NULL PRIMARY KEY,
                group_id    BLOB   NOT NULL,
                data        BLOB   NOT NULL,
                created_at  TEXT   NOT NULL
            );";
        cmd.ExecuteNonQuery();
    }

    // ────────────────────────────────────────────────────────────────
    // V003 – Indexes for common query patterns
    // ────────────────────────────────────────────────────────────────

    private static void V003(SqliteConnection connection)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            CREATE INDEX idx_messages_group ON messages(group_id, created_at);
            CREATE INDEX idx_welcomes_state ON welcomes(state);";
        cmd.ExecuteNonQuery();
    }

    // ────────────────────────────────────────────────────────────────
    // V004 – Message sort by epoch index
    // ────────────────────────────────────────────────────────────────

    private static void V004(SqliteConnection connection)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            CREATE INDEX idx_messages_epoch ON messages(group_id, epoch);";
        cmd.ExecuteNonQuery();
    }
}
