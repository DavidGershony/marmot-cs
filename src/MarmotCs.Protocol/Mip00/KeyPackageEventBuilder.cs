using DotnetMls.Crypto;
using DotnetMls.Types;

namespace MarmotCs.Protocol.Mip00;

/// <summary>
/// Builds the content and tags for a Nostr kind 30443 (addressable) event containing an MLS KeyPackage.
/// </summary>
/// <remarks>
/// MIP-00 defines the format for publishing MLS KeyPackages to Nostr relays:
/// <list type="bullet">
///   <item>Content: base64-encoded MLS KeyPackage bytes.</item>
///   <item>Tags: d (slot), encoding, protocol_version, ciphersuite, extensions, relays, and i (KeyPackageRef).</item>
/// </list>
/// Kind 30443 is an addressable event — relays auto-replace by (kind, pubkey, d-tag) tuple.
/// </remarks>
public static class KeyPackageEventBuilder
{
    /// <summary>
    /// Creates the content string and tags array for a kind 30443 Nostr event.
    /// </summary>
    /// <param name="keyPackageBytes">The serialized MLS KeyPackage bytes.</param>
    /// <param name="identityHex">Hex-encoded identity (typically the Nostr public key).</param>
    /// <param name="relays">List of relay URLs where this key package should be discoverable.</param>
    /// <param name="supportedExtensionTypes">Optional MLS extension type IDs to advertise.</param>
    /// <param name="slotId">
    /// d-tag value for the kind 30443 addressable event slot.
    /// <para>
    /// Per MIP-00, this MUST be a stable, cryptographically random 32-byte hex string that the client
    /// generates <b>once</b> per slot (see <see cref="KeyPackageSlotId.GenerateNew"/>) and reuses on
    /// every subsequent KeyPackage rotation, so relays replace the previous KeyPackage in place.
    /// </para>
    /// <para>
    /// If null, a fresh random slot ID is generated for this call. This fallback exists for
    /// one-shot/test scenarios only — production callers that publish KeyPackages for the same identity
    /// more than once MUST supply a persisted <paramref name="slotId"/>, otherwise each publish creates
    /// a new addressable-event slot and stale KeyPackages accumulate on the relay.
    /// </para>
    /// </param>
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
        ushort[]? supportedExtensionTypes = null,
        string? slotId = null)
    {
        ArgumentNullException.ThrowIfNull(keyPackageBytes);
        ArgumentNullException.ThrowIfNull(identityHex);
        ArgumentNullException.ThrowIfNull(relays);

        if (keyPackageBytes.Length == 0)
            throw new ArgumentException("Key package bytes must not be empty.", nameof(keyPackageBytes));
        if (string.IsNullOrEmpty(identityHex))
            throw new ArgumentException("Identity hex must not be empty.", nameof(identityHex));

        string content = Convert.ToBase64String(keyPackageBytes);

        // Generate a one-shot d-tag slot ID if the caller didn't supply one.
        // NOTE: production callers that publish more than once for the same identity MUST pass a
        // persisted slotId — see the parameter doc above.
        if (string.IsNullOrEmpty(slotId))
        {
            slotId = KeyPackageSlotId.GenerateNew();
        }

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

        // d tag first — required for kind 30443 addressable events
        string[][] tags = new[]
        {
            new[] { "d", slotId },
            new[] { "encoding", "base64" },
            new[] { "mls_protocol_version", "1.0" },
            new[] { "mls_ciphersuite", "0x0001" },
            extensionsTag.ToArray(),
            new[] { "mls_proposals", "0x000a" },
            relaysTag,
            new[] { "i", kpRefHex }
        };

        return (content, tags);
    }
}
