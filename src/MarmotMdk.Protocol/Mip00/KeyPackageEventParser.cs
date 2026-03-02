namespace MarmotMdk.Protocol.Mip00;

/// <summary>
/// Parses the content and tags of a Nostr kind 443 event to extract MLS KeyPackage data.
/// </summary>
public static class KeyPackageEventParser
{
    /// <summary>
    /// Parses a kind 443 Nostr event's content and tags to extract the KeyPackage bytes,
    /// identity hex, and relay URLs.
    /// </summary>
    /// <param name="content">The base64-encoded content of the Nostr event.</param>
    /// <param name="tags">The tags array from the Nostr event.</param>
    /// <returns>
    /// A tuple of (keyPackageBytes, identityHex, relays) where keyPackageBytes is the decoded
    /// MLS KeyPackage, identityHex is the identity string, and relays is the array of relay URLs.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when content or tags is null.</exception>
    /// <exception cref="FormatException">Thrown when the event format is invalid or required tags are missing.</exception>
    public static (byte[] keyPackageBytes, string identityHex, string[] relays) ParseKeyPackageEvent(
        string content, string[][] tags)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(tags);

        // Validate encoding tag
        string? encoding = FindTagValue(tags, "encoding");
        if (encoding != "mls-base64")
            throw new FormatException($"Unsupported encoding: '{encoding ?? "(missing)"}'. Expected 'mls-base64'.");

        // Decode the key package from base64
        byte[] keyPackageBytes;
        try
        {
            keyPackageBytes = Convert.FromBase64String(content);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Content is not valid base64.", ex);
        }

        if (keyPackageBytes.Length == 0)
            throw new FormatException("Key package content is empty.");

        // Extract identity from the "i" tag: ["i", identity_hex, "mls"]
        string? identityHex = null;
        foreach (string[] tag in tags)
        {
            if (tag.Length >= 3 && tag[0] == "i" && tag[2] == "mls")
            {
                identityHex = tag[1];
                break;
            }
        }

        if (string.IsNullOrEmpty(identityHex))
            throw new FormatException("Missing or empty 'i' tag with 'mls' marker.");

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

        return (keyPackageBytes, identityHex, relays);
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
