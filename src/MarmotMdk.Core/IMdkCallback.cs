namespace MarmotMdk.Core;

/// <summary>
/// Callback interface for notifications about group state changes.
/// Implementations can use these to update UI, send notifications, or trigger side effects.
/// </summary>
public interface IMdkCallback
{
    /// <summary>
    /// Called when a group state is rolled back due to a failed commit processing.
    /// </summary>
    /// <param name="groupId">The group identifier.</param>
    /// <param name="fromEpoch">The epoch before rollback.</param>
    /// <param name="toEpoch">The epoch after rollback.</param>
    /// <param name="ct">Cancellation token.</param>
    Task OnRollbackAsync(byte[] groupId, ulong fromEpoch, ulong toEpoch, CancellationToken ct = default);

    /// <summary>
    /// Called when the group epoch advances (after a commit is processed or merged).
    /// </summary>
    /// <param name="groupId">The group identifier.</param>
    /// <param name="newEpoch">The new epoch number.</param>
    /// <param name="ct">Cancellation token.</param>
    Task OnEpochAdvanceAsync(byte[] groupId, ulong newEpoch, CancellationToken ct = default);

    /// <summary>
    /// Called when a new member is added to the group.
    /// </summary>
    /// <param name="groupId">The group identifier.</param>
    /// <param name="memberIdentity">The identity bytes of the added member.</param>
    /// <param name="ct">Cancellation token.</param>
    Task OnMemberAddedAsync(byte[] groupId, byte[] memberIdentity, CancellationToken ct = default);

    /// <summary>
    /// Called when a member is removed from the group.
    /// </summary>
    /// <param name="groupId">The group identifier.</param>
    /// <param name="memberIdentity">The identity bytes of the removed member.</param>
    /// <param name="ct">Cancellation token.</param>
    Task OnMemberRemovedAsync(byte[] groupId, byte[] memberIdentity, CancellationToken ct = default);
}
