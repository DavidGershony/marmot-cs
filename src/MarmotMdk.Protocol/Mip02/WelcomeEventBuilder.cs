namespace MarmotMdk.Protocol.Mip02;

/// <summary>
/// Builds the content and tags for a Nostr kind 444 event containing an MLS Welcome message.
/// These events are typically unsigned and intended for NIP-59 gift wrapping.
/// </summary>
public static class WelcomeEventBuilder
{
    /// <summary>
    /// Creates the content string and tags array for a kind 444 Nostr event.
    /// </summary>
    /// <param name="welcomeBytes">The serialized MLS Welcome message bytes.</param>
    /// <param name="keyPackageEventId">
    /// The Nostr event ID of the kind 443 KeyPackage event that this Welcome is in response to.
    /// </param>
    /// <param name="relays">List of relay URLs for the event.</param>
    /// <returns>
    /// A tuple of (content, tags) where content is the base64-encoded Welcome message
    /// and tags is the array of string arrays for the Nostr event.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when welcomeBytes is empty or keyPackageEventId is empty.</exception>
    public static (string content, string[][] tags) BuildWelcomeEvent(
        byte[] welcomeBytes,
        string keyPackageEventId,
        string[] relays)
    {
        ArgumentNullException.ThrowIfNull(welcomeBytes);
        ArgumentNullException.ThrowIfNull(keyPackageEventId);
        ArgumentNullException.ThrowIfNull(relays);

        if (welcomeBytes.Length == 0)
            throw new ArgumentException("Welcome bytes must not be empty.", nameof(welcomeBytes));
        if (string.IsNullOrEmpty(keyPackageEventId))
            throw new ArgumentException("Key package event ID must not be empty.", nameof(keyPackageEventId));

        string content = Convert.ToBase64String(welcomeBytes);

        // Build the relays tag: ["relays", relay1, relay2, ...]
        string[] relaysTag = new string[1 + relays.Length];
        relaysTag[0] = "relays";
        Array.Copy(relays, 0, relaysTag, 1, relays.Length);

        string[][] tags = new[]
        {
            new[] { "e", keyPackageEventId },
            relaysTag,
            new[] { "encoding", "mls-base64" }
        };

        return (content, tags);
    }
}
