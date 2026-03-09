namespace MarmotCs.Protocol.Mip02;

/// <summary>
/// Parses the content and tags of a Nostr kind 444 event to extract MLS Welcome data.
/// </summary>
public static class WelcomeEventParser
{
    /// <summary>
    /// Parses a kind 444 Nostr event's content and tags to extract the Welcome message bytes,
    /// the referenced KeyPackage event ID, and relay URLs.
    /// </summary>
    /// <param name="content">The base64-encoded content of the Nostr event.</param>
    /// <param name="tags">The tags array from the Nostr event.</param>
    /// <returns>
    /// A tuple of (welcomeBytes, keyPackageEventId, relays) containing the decoded Welcome
    /// message, the referenced event ID, and the relay URL list.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when content or tags is null.</exception>
    /// <exception cref="FormatException">Thrown when the event format is invalid or required tags are missing.</exception>
    public static (byte[] welcomeBytes, string keyPackageEventId, string[] relays) ParseWelcomeEvent(
        string content, string[][] tags)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(tags);

        // Validate encoding tag
        string? encoding = FindTagValue(tags, "encoding");
        if (encoding != "mls-base64")
            throw new FormatException($"Unsupported encoding: '{encoding ?? "(missing)"}'. Expected 'mls-base64'.");

        // Decode the Welcome message from base64
        byte[] welcomeBytes;
        try
        {
            welcomeBytes = Convert.FromBase64String(content);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Content is not valid base64.", ex);
        }

        if (welcomeBytes.Length == 0)
            throw new FormatException("Welcome content is empty.");

        // Extract key package event ID from the "e" tag
        string? keyPackageEventId = FindTagValue(tags, "e");
        if (string.IsNullOrEmpty(keyPackageEventId))
            throw new FormatException("Missing or empty 'e' tag for key package event reference.");

        // Extract relays from the "relays" tag: ["relays", relay1, relay2, ...]
        string[] relays = Array.Empty<string>();
        foreach (string[] tag in tags)
        {
            if (tag.Length >= 1 && tag[0] == "relays")
            {
                relays = new string[tag.Length - 1];
                Array.Copy(tag, 1, relays, 0, relays.Length);
                break;
            }
        }

        return (welcomeBytes, keyPackageEventId, relays);
    }

    private static string? FindTagValue(string[][] tags, string tagName)
    {
        foreach (string[] tag in tags)
        {
            if (tag.Length >= 2 && tag[0] == tagName)
                return tag[1];
        }
        return null;
    }
}
