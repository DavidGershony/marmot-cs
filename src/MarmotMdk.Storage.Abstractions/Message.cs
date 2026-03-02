namespace MarmotMdk.Storage.Abstractions;

/// <summary>
/// Represents a plaintext message within an MLS group.
/// </summary>
public sealed record Message(
    string Id,
    MlsGroupId GroupId,
    byte[] SenderIdentity,
    byte[] Content,
    ulong Epoch,
    MessageState State,
    DateTimeOffset CreatedAt);
