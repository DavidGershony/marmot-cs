namespace MarmotMdk.Storage.Abstractions;

/// <summary>
/// Storage operations for MLS Welcome messages and processed welcome tracking.
/// </summary>
public interface IWelcomeStorage
{
    Task SaveWelcomeAsync(Welcome welcome, CancellationToken ct = default);

    Task<Welcome?> GetWelcomeAsync(string id, CancellationToken ct = default);

    Task<IReadOnlyList<Welcome>> GetPendingWelcomesAsync(CancellationToken ct = default);

    Task UpdateWelcomeAsync(Welcome welcome, CancellationToken ct = default);

    Task SaveProcessedWelcomeAsync(ProcessedWelcome processed, CancellationToken ct = default);

    Task<ProcessedWelcome?> GetProcessedWelcomeAsync(string eventId, CancellationToken ct = default);
}
