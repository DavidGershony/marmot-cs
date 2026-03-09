namespace MarmotCs.Core;

/// <summary>
/// Configuration options for the Marmot CS public API.
/// </summary>
public sealed record MdkConfig
{
    /// <summary>
    /// The maximum age of events to process. Events older than this are ignored.
    /// </summary>
    public TimeSpan MaxEventAge { get; init; } = TimeSpan.FromDays(7);

    /// <summary>
    /// The maximum number of messages that can be received out of order
    /// within a single epoch.
    /// </summary>
    public int OutOfOrderTolerance { get; init; } = 5;

    /// <summary>
    /// The maximum forward distance (in generations) for message processing.
    /// Prevents denial-of-service by limiting how far a ratchet can be advanced.
    /// </summary>
    public int MaxForwardDistance { get; init; } = 1000;

    /// <summary>
    /// The maximum number of epoch snapshots to keep per group for rollback support.
    /// </summary>
    public int MaxSnapshotsPerGroup { get; init; } = 5;

    /// <summary>
    /// The MLS cipher suite identifier. Currently only 0x0001 is supported.
    /// </summary>
    public ushort CipherSuite { get; init; } = 0x0001;

    /// <summary>
    /// Returns a default configuration.
    /// </summary>
    public static MdkConfig Default => new();
}
