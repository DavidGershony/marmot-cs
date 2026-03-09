namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Represents an MLS Welcome message received from a group member.
/// </summary>
public sealed record Welcome(
    string Id,
    MlsGroupId GroupId,
    byte[] WelcomeData,
    WelcomeState State,
    byte[]? GroupData,
    string? SenderNostrPubkey,
    DateTimeOffset CreatedAt);
