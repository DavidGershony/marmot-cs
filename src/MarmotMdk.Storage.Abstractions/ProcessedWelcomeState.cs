namespace MarmotMdk.Storage.Abstractions;

/// <summary>
/// Represents the processing state of an inbound Welcome event.
/// </summary>
public enum ProcessedWelcomeState
{
    Pending,
    Completed,
    Failed
}
