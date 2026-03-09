namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Represents the delivery state of a message.
/// </summary>
public enum MessageState
{
    Pending,
    Sent,
    Delivered
}
