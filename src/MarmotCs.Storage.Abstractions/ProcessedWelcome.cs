namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Tracks whether a Nostr Welcome event has been processed.
/// </summary>
public sealed record ProcessedWelcome(
    string EventId,
    ProcessedWelcomeState State,
    DateTimeOffset ProcessedAt);
