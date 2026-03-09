namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Associates an MLS group with a Nostr relay URL.
/// </summary>
public sealed record GroupRelay(
    MlsGroupId GroupId,
    string RelayUrl);
