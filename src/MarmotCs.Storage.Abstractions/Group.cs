namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Represents an MLS group with its associated metadata.
/// </summary>
/// <param name="MlsState">Opaque binary MLS group state (ratchet tree, secrets, etc.).
/// Exported via MlsGroup.Export() and imported via MlsGroup.Import().
/// Null when creating a new group (state set after first export).</param>
public sealed record Group(
    MlsGroupId Id,
    GroupState State,
    string Name,
    byte[]? Image,
    byte[]? GroupData,
    ulong Epoch,
    SelfUpdateState? SelfUpdate,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    byte[]? MlsState = null);
