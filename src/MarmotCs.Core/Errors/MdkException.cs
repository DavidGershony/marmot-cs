namespace MarmotCs.Core.Errors;

/// <summary>
/// Base exception for all Marmot CS errors.
/// </summary>
public class MdkException : Exception
{
    public MdkException(string message) : base(message) { }
    public MdkException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Thrown when a group is not found in the local cache or storage.
/// </summary>
public class GroupNotFoundException : MdkException
{
    public byte[] GroupId { get; }

    public GroupNotFoundException(byte[] groupId)
        : base($"Group {Convert.ToHexString(groupId)} not found")
    {
        GroupId = groupId;
    }
}

/// <summary>
/// Thrown when a received message cannot be parsed or validated.
/// </summary>
public class InvalidMessageException : MdkException
{
    public InvalidMessageException(string message) : base(message) { }
    public InvalidMessageException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Thrown when Welcome processing fails.
/// </summary>
public class WelcomeProcessingException : MdkException
{
    public WelcomeProcessingException(string message) : base(message) { }
    public WelcomeProcessingException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Thrown when a commit operation fails.
/// </summary>
public class CommitException : MdkException
{
    public CommitException(string message) : base(message) { }
    public CommitException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Thrown when a message with the same event ID has already been processed.
/// </summary>
public class DuplicateMessageException : MdkException
{
    public string EventId { get; }

    public DuplicateMessageException(string eventId)
        : base($"Message {eventId} already processed")
    {
        EventId = eventId;
    }
}

/// <summary>
/// Thrown when a locally staged commit loses the MIP-03 tiebreaker against an incoming
/// commit at the same epoch. The caller should discard their pending operation and
/// retry at the new epoch.
/// </summary>
public class RaceLostException : MdkException
{
    /// <summary>The new epoch after the winning commit was applied.</summary>
    public ulong NewEpoch { get; }

    /// <summary>The Nostr event ID of the winning incoming commit.</summary>
    public string WinnerEventId { get; }

    public RaceLostException(ulong newEpoch, string winnerEventId)
        : base($"Staged commit lost race at epoch {newEpoch - 1}; winner is {winnerEventId}. Retry at epoch {newEpoch}.")
    {
        NewEpoch = newEpoch;
        WinnerEventId = winnerEventId;
    }
}

/// <summary>
/// Thrown when a message's epoch is behind the group's current epoch
/// beyond the tolerance window.
/// </summary>
public class StaleEpochException : MdkException
{
    public ulong MessageEpoch { get; }
    public ulong CurrentEpoch { get; }

    public StaleEpochException(ulong messageEpoch, ulong currentEpoch)
        : base($"Message epoch {messageEpoch} is behind current epoch {currentEpoch}")
    {
        MessageEpoch = messageEpoch;
        CurrentEpoch = currentEpoch;
    }
}
