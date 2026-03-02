using DotnetMls.Types;

namespace MarmotMdk.Protocol.Mip01;

/// <summary>
/// Holds Nostr group metadata encoded in the 0xF2EE MLS extension type.
/// </summary>
public sealed class NostrGroupData
{
    /// <summary>
    /// The human-readable name of the group.
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// A textual description of the group.
    /// </summary>
    public string Description { get; set; } = "";

    /// <summary>
    /// Optional raw image bytes for the group avatar.
    /// </summary>
    public byte[]? Image { get; set; }

    /// <summary>
    /// Optional SHA-256 hash of the image for integrity verification.
    /// </summary>
    public byte[]? ImageHash { get; set; }

    /// <summary>
    /// Optional encrypted image bytes (encrypted with a key derived from the MLS exporter secret).
    /// </summary>
    public byte[]? EncryptedImage { get; set; }

    /// <summary>
    /// Concatenated 32-byte Nostr public keys of group administrators.
    /// </summary>
    public byte[] AdminPubkeys { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// List of relay URLs for the group.
    /// </summary>
    public string[] Relays { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Encoding version. Currently version 2.
    /// </summary>
    public ushort Version { get; set; } = 2;
}

/// <summary>
/// Converts <see cref="NostrGroupData"/> to and from an MLS <see cref="Extension"/> with type 0xF2EE.
/// </summary>
public static class NostrGroupDataExtension
{
    /// <summary>
    /// The MLS extension type identifier for Nostr group data.
    /// </summary>
    public const ushort ExtensionType = 0xF2EE;

    /// <summary>
    /// Encodes a <see cref="NostrGroupData"/> as an MLS <see cref="Extension"/> with type 0xF2EE.
    /// </summary>
    /// <param name="data">The group data to encode.</param>
    /// <returns>An MLS Extension containing the serialized group data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
    public static Extension ToExtension(NostrGroupData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        byte[] encoded = NostrGroupDataCodec.Encode(data);
        return new Extension(ExtensionType, encoded);
    }

    /// <summary>
    /// Decodes a <see cref="NostrGroupData"/> from an MLS <see cref="Extension"/>.
    /// </summary>
    /// <param name="ext">The MLS Extension to decode. Must have type 0xF2EE.</param>
    /// <returns>The decoded <see cref="NostrGroupData"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ext"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when the extension type is not 0xF2EE.</exception>
    public static NostrGroupData FromExtension(Extension ext)
    {
        ArgumentNullException.ThrowIfNull(ext);
        if (ext.ExtensionType != ExtensionType)
            throw new ArgumentException(
                $"Expected extension type 0x{ExtensionType:X4} but got 0x{ext.ExtensionType:X4}.",
                nameof(ext));

        return NostrGroupDataCodec.Decode(ext.ExtensionData);
    }
}
