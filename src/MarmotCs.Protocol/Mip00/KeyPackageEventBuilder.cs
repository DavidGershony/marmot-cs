using DotnetMls.Crypto;
using DotnetMls.Types;

namespace MarmotCs.Protocol.Mip00;

/// <summary>
/// Builds the content and tags for a Nostr kind 443 event containing an MLS KeyPackage.
/// </summary>
/// <remarks>
/// MIP-00 defines the format for publishing MLS KeyPackages to Nostr relays:
/// <list type="bullet">
///   <item>Content: base64-encoded MLS KeyPackage bytes.</item>
///   <item>Tags: encoding, protocol_version, ciphersuite, extensions, relays, and i (KeyPackageRef).</item>
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
        string[] relays,
        ushort[]? supportedExtensionTypes = null)
    {
        ArgumentNullException.ThrowIfNull(keyPackageBytes);
        ArgumentNullException.ThrowIfNull(identityHex);
        ArgumentNullException.ThrowIfNull(relays);

        if (keyPackageBytes.Length == 0)
            throw new ArgumentException("Key package bytes must not be empty.", nameof(keyPackageBytes));
        if (string.IsNullOrEmpty(identityHex))
            throw new ArgumentException("Identity hex must not be empty.", nameof(identityHex));

        string content = Convert.ToBase64String(keyPackageBytes);

        // Compute KeyPackageRef per RFC 9420 Section 5.2:
        // MakeKeyPackageRef(value) = RefHash("MLS 1.0 KeyPackage Reference", value)
        var cs = new CipherSuite0x0001();
        var kpRef = KeyPackageRef.Compute(cs, keyPackageBytes);
        string kpRefHex = Convert.ToHexString(kpRef.Value).ToLowerInvariant();

        // Build the relays tag: ["relays", relay1, relay2, ...]
        string[] relaysTag = new string[1 + relays.Length];
        relaysTag[0] = "relays";
        Array.Copy(relays, 0, relaysTag, 1, relays.Length);

        // Build the mls_extensions tag: ["mls_extensions", "0xf2ee", "0x000a", ...]
        var extensionsTag = new List<string> { "mls_extensions" };
        if (supportedExtensionTypes is { Length: > 0 })
        {
            foreach (var extType in supportedExtensionTypes)
                extensionsTag.Add($"0x{extType:x4}");
        }

        string[][] tags = new[]
        {
            new[] { "encoding", "base64" },
            new[] { "mls_protocol_version", "1.0" },
            new[] { "mls_ciphersuite", "0x0001" },
            extensionsTag.ToArray(),
            relaysTag,
            new[] { "i", kpRefHex }
        };

        return (content, tags);
    }
}
