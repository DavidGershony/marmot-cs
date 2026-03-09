using MarmotCs.Storage.Abstractions;

namespace MarmotCs.Core.Results;

/// <summary>
/// Result from creating a new MLS group.
/// </summary>
/// <param name="Group">The persisted group record.</param>
/// <param name="KeyPackageBytes">Serialized key package bytes for publishing to relays.</param>
public sealed record GroupResult(
    Group Group,
    byte[] KeyPackageBytes);

/// <summary>
/// Result from a group update operation (add members, remove members, self-update).
/// </summary>
/// <param name="Group">The updated group record.</param>
/// <param name="CommitMessageBytes">Serialized PublicMessage to publish as a kind 445 Nostr event.</param>
/// <param name="WelcomeBytes">Serialized Welcome for new members (kind 444), or null if no new members.</param>
/// <param name="AddedIdentities">Hex-encoded identities of added members.</param>
/// <param name="RemovedIdentities">Hex-encoded identities of removed members.</param>
public sealed record UpdateGroupResult(
    Group Group,
    byte[] CommitMessageBytes,
    byte[]? WelcomeBytes,
    string[] AddedIdentities,
    string[] RemovedIdentities);

/// <summary>
/// Abstract base for message processing results.
/// </summary>
public abstract record MessageProcessingResult;

/// <summary>
/// Result when an application (chat) message was successfully decrypted.
/// </summary>
/// <param name="Message">The decrypted and stored message.</param>
public sealed record ApplicationMessageResult(
    Message Message) : MessageProcessingResult;

/// <summary>
/// Result when a commit message was successfully processed, advancing the epoch.
/// </summary>
/// <param name="UpdatedGroup">The group record after the epoch advance.</param>
public sealed record CommitResult(
    Group UpdatedGroup) : MessageProcessingResult;

/// <summary>
/// Result when a standalone proposal was received.
/// </summary>
/// <param name="ProposalType">The type of proposal (Add, Remove, Update, etc.).</param>
/// <param name="SenderIdentity">The identity bytes of the proposal sender.</param>
public sealed record ProposalResult(
    string ProposalType,
    byte[] SenderIdentity) : MessageProcessingResult;

/// <summary>
/// Result when a message could not be processed.
/// </summary>
/// <param name="Reason">A human-readable explanation of why processing failed.</param>
public sealed record UnprocessableResult(
    string Reason) : MessageProcessingResult;

/// <summary>
/// Preview of a Welcome message before the user accepts or declines it.
/// </summary>
/// <param name="WelcomeId">The storage identifier for this welcome.</param>
/// <param name="GroupId">The MLS group identifier bytes.</param>
/// <param name="GroupName">The group name from NostrGroupData extension, or empty.</param>
/// <param name="MemberIdentities">Hex-encoded identities of current group members.</param>
/// <param name="SenderNostrPubkey">The Nostr pubkey of the welcome sender, if known.</param>
public sealed record WelcomePreview(
    string WelcomeId,
    byte[] GroupId,
    string GroupName,
    string[] MemberIdentities,
    string? SenderNostrPubkey);

/// <summary>
/// Describes pending member changes that have been proposed but not yet committed.
/// </summary>
/// <param name="PendingAdds">Hex-encoded identities of members pending addition.</param>
/// <param name="PendingRemovals">Hex-encoded identities of members pending removal.</param>
public sealed record PendingMemberChanges(
    string[] PendingAdds,
    string[] PendingRemovals);
