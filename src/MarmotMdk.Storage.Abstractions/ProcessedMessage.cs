namespace MarmotMdk.Storage.Abstractions;

/// <summary>
/// Tracks whether a Nostr message event has been processed.
/// </summary>
public sealed record ProcessedMessage(
    string EventId,
    MlsGroupId GroupId,
    ProcessedMessageState State,
    DateTimeOffset ProcessedAt);
