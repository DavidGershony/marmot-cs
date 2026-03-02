using MarmotMdk.Storage.Abstractions;

namespace MarmotMdk.Core;

/// <summary>
/// Manages epoch snapshots for transactional safety during commit processing.
/// Creates snapshots before mutations and supports rollback on failure.
/// </summary>
internal sealed class EpochSnapshotManager
{
    private readonly IMdkStorageProvider _storage;
    private readonly int _maxSnapshots;

    public EpochSnapshotManager(IMdkStorageProvider storage, int maxSnapshots)
    {
        _storage = storage;
        _maxSnapshots = maxSnapshots;
    }

    /// <summary>
    /// Creates a snapshot of the group's current state and prunes old snapshots.
    /// </summary>
    /// <param name="groupId">The group to snapshot.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The snapshot identifier for later rollback or release.</returns>
    public async Task<string> CreateSnapshotAsync(MlsGroupId groupId, CancellationToken ct = default)
    {
        var snapshotId = await _storage.CreateSnapshotAsync(groupId, ct);
        await _storage.PruneSnapshotsAsync(groupId, _maxSnapshots, ct);
        return snapshotId;
    }

    /// <summary>
    /// Rolls back to the specified snapshot, discarding all changes made after it.
    /// </summary>
    /// <param name="snapshotId">The snapshot to roll back to.</param>
    /// <param name="ct">Cancellation token.</param>
    public Task RollbackAsync(string snapshotId, CancellationToken ct = default)
        => _storage.RollbackToSnapshotAsync(snapshotId, ct);

    /// <summary>
    /// Releases a snapshot, freeing associated resources while keeping the current state.
    /// </summary>
    /// <param name="snapshotId">The snapshot to release.</param>
    /// <param name="ct">Cancellation token.</param>
    public Task ReleaseAsync(string snapshotId, CancellationToken ct = default)
        => _storage.ReleaseSnapshotAsync(snapshotId, ct);
}
