namespace MarmotMdk.Storage.Abstractions;

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
}
