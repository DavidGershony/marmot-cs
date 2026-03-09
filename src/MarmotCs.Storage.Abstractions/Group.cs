namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Represents an MLS group with its associated metadata.
/// </summary>
public sealed record Group(
    MlsGroupId Id,
    GroupState State,
    string Name,
    byte[]? Image,
    byte[]? GroupData,
    ulong Epoch,
    SelfUpdateState? SelfUpdate,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);
