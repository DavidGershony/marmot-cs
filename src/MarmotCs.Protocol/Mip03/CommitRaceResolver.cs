namespace MarmotCs.Protocol.Mip03;

/// <summary>
/// Resolves races when multiple MLS commits arrive for the same epoch.
/// </summary>
/// <remarks>
/// When multiple commits target the same epoch, the winner is determined by:
/// <list type="number">
///   <item>Earliest <c>created_at</c> timestamp wins.</item>
///   <item>If timestamps are tied, the smallest event ID (lexicographic hex comparison) wins.</item>
/// </list>
/// </remarks>
public static class CommitRaceResolver
{
    /// <summary>
    /// Determines the winning commit event ID from a set of competing commits.
    /// </summary>
    /// <param name="commits">
    /// An array of tuples where each element contains the Nostr event ID (hex string)
    /// and the <c>created_at</c> timestamp of the commit event.
    /// </param>
    /// <returns>The event ID of the winning commit.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="commits"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="commits"/> is empty.</exception>
    public static string ResolveWinner(
        (string eventId, DateTimeOffset createdAt)[] commits)
    {
        ArgumentNullException.ThrowIfNull(commits);
        if (commits.Length == 0)
            throw new ArgumentException("Commits array must not be empty.", nameof(commits));

        if (commits.Length == 1)
            return commits[0].eventId;

        // Sort by created_at ascending, then by event ID lexicographically ascending
        var winner = commits[0];
        for (int i = 1; i < commits.Length; i++)
        {
            var candidate = commits[i];
            int cmp = candidate.createdAt.CompareTo(winner.createdAt);
            if (cmp < 0)
            {
                winner = candidate;
            }
            else if (cmp == 0)
            {
                // Tie-break: smallest event ID (case-insensitive hex comparison)
                if (string.Compare(candidate.eventId, winner.eventId, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    winner = candidate;
                }
            }
        }

        return winner.eventId;
    }
}
