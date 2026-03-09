namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Represents the processing state of an inbound message event.
/// </summary>
public enum ProcessedMessageState
{
    Pending,
    Completed,
    Failed
}
