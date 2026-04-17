namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Storage operations for MLS groups, relays, and exporter secrets.
/// </summary>
public interface IGroupStorage
{
    Task SaveGroupAsync(Group group, CancellationToken ct = default);

    Task<Group?> GetGroupAsync(MlsGroupId id, CancellationToken ct = default);

    Task<IReadOnlyList<Group>> GetGroupsAsync(GroupState? state = null, CancellationToken ct = default);

    Task UpdateGroupAsync(Group group, CancellationToken ct = default);

    Task DeleteGroupAsync(MlsGroupId id, CancellationToken ct = default);

    Task SaveGroupRelayAsync(GroupRelay relay, CancellationToken ct = default);

    Task<IReadOnlyList<GroupRelay>> GetGroupRelaysAsync(MlsGroupId groupId, CancellationToken ct = default);

    Task DeleteGroupRelaysAsync(MlsGroupId groupId, CancellationToken ct = default);

    Task SaveExporterSecretAsync(GroupExporterSecret secret, CancellationToken ct = default);

    Task<GroupExporterSecret?> GetExporterSecretAsync(MlsGroupId groupId, ulong epoch, CancellationToken ct = default);

    /// <summary>
    /// Records which commit was applied for a given group and epoch (MIP-03 race resolution).
    /// </summary>
    Task SaveAppliedCommitAsync(MlsGroupId groupId, ulong epoch, string eventId, DateTimeOffset createdAt, CancellationToken ct = default);

    /// <summary>
    /// Gets the applied commit metadata for a given group and epoch.
    /// Returns null if no commit has been applied for that epoch.
    /// </summary>
    Task<(string EventId, DateTimeOffset CreatedAt)?> GetAppliedCommitAsync(MlsGroupId groupId, ulong epoch, CancellationToken ct = default);
}
