namespace MarmotCs.Protocol.Mip00;

/// <summary>
/// Builds the content and tags for a Nostr kind 443 event containing an MLS KeyPackage.
/// </summary>
/// <remarks>
/// MIP-00 defines the format for publishing MLS KeyPackages to Nostr relays:
/// <list type="bullet">
///   <item>Content: base64-encoded MLS KeyPackage bytes.</item>
///   <item>Tags: encoding, protocol_version, ciphersuite, extensions, relays, and identity.</item>
/// </list>
/// </remarks>
public static class KeyPackageEventBuilder
{
    /// <summary>
    /// Creates the content string and tags array for a kind 443 Nostr event.
    /// </summary>
    /// <param name="keyPackageBytes">The serialized MLS KeyPackage bytes.</param>
    /// <param name="identityHex">Hex-encoded identity (typically the Nostr public key).</param>
    /// <param name="relays">List of relay URLs where this key package should be discoverable.</param>
    /// <returns>
    /// A tuple of (content, tags) where content is the base64-encoded KeyPackage
    /// and tags is the array of string arrays for the Nostr event.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when keyPackageBytes is empty or identityHex is empty.</exception>
    public static (string content, string[][] tags) BuildKeyPackageEvent(
        byte[] keyPackageBytes,
        string identityHex,
        string[] relays)
    {
        ArgumentNullException.ThrowIfNull(keyPackageBytes);
        ArgumentNullException.ThrowIfNull(identityHex);
        ArgumentNullException.ThrowIfNull(relays);

        if (keyPackageBytes.Length == 0)
            throw new ArgumentException("Key package bytes must not be empty.", nameof(keyPackageBytes));
        if (string.IsNullOrEmpty(identityHex))
            throw new ArgumentException("Identity hex must not be empty.", nameof(identityHex));

        string content = Convert.ToBase64String(keyPackageBytes);

        // Build the relays tag: ["relays", relay1, relay2, ...]
        string[] relaysTag = new string[1 + relays.Length];
        relaysTag[0] = "relays";
        Array.Copy(relays, 0, relaysTag, 1, relays.Length);

        string[][] tags = new[]
        {
            new[] { "encoding", "mls-base64" },
            new[] { "protocol_version", "0" },
            new[] { "ciphersuite", "1" },
            new[] { "extensions", "" },
            relaysTag,
            new[] { "i", identityHex, "mls" }
        };

        return (content, tags);
    }
}
