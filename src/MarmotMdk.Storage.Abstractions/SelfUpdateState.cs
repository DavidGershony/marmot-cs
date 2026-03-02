namespace MarmotMdk.Storage.Abstractions;

/// <summary>
/// Discriminated union representing the self-update state of a group member.
/// </summary>
public abstract record SelfUpdateState
{
    private SelfUpdateState() { }

    /// <summary>
    /// Indicates that a self-update is required.
    /// </summary>
    public sealed record Required() : SelfUpdateState;

    /// <summary>
    /// Indicates that a self-update was completed at the specified time.
    /// </summary>
    public sealed record CompletedAt(DateTimeOffset Completed) : SelfUpdateState;
}
