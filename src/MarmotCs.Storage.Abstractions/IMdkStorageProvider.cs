namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Top-level storage provider that aggregates all storage concerns
/// and provides snapshot/rollback capabilities for transactional safety.
/// </summary>
public interface IMdkStorageProvider
{
    IGroupStorage Groups { get; }

    IMessageStorage Messages { get; }

    IWelcomeStorage Welcomes { get; }

    /// <summary>
    /// Creates a snapshot of all data associated with the specified group.
    /// Returns a snapshot identifier that can be used for rollback or release.
    /// </summary>
    Task<string> CreateSnapshotAsync(MlsGroupId groupId, CancellationToken ct = default);

    /// <summary>
    /// Rolls back the storage state to the specified snapshot, discarding any
    /// changes made after the snapshot was created.
    /// </summary>
    Task RollbackToSnapshotAsync(string snapshotId, CancellationToken ct = default);

    /// <summary>
    /// Releases a snapshot, freeing any resources associated with it.
    /// The current state is kept as-is.
    /// </summary>
    Task ReleaseSnapshotAsync(string snapshotId, CancellationToken ct = default);

    /// <summary>
    /// Prunes old snapshots for the specified group, keeping only the most
    /// recent <paramref name="keepCount"/> snapshots.
    /// </summary>
    Task PruneSnapshotsAsync(MlsGroupId groupId, int keepCount, CancellationToken ct = default);
}
