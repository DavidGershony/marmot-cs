using DotnetMls.Types;

namespace MarmotCs.Protocol.Mip01;

/// <summary>
/// Holds Nostr group metadata encoded in the 0xF2EE MLS extension type.
/// Wire format matches the Rust MDK TlsNostrGroupDataExtension (TLS codec).
/// </summary>
public sealed class NostrGroupData
{
    /// <summary>
    /// Encoding version. Current version is 2.
    /// </summary>
    public ushort Version { get; set; } = 2;

    /// <summary>
    /// 32-byte Nostr group identifier.
    /// </summary>
    public byte[] NostrGroupId { get; set; } = new byte[32];

    /// <summary>
    /// The human-readable name of the group.
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// A textual description of the group.
    /// </summary>
    public string Description { get; set; } = "";

    /// <summary>
    /// Concatenated 32-byte Nostr public keys of group administrators.
    /// </summary>
    public byte[] AdminPubkeys { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// List of relay URLs for the group.
    /// </summary>
    public string[] Relays { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Optional SHA-256 hash of the group image (32 bytes, or empty).
    /// </summary>
    public byte[] ImageHash { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Optional image key/seed (32 bytes, or empty).
    /// v2: seed for HKDF derivation. v1: direct encryption key.
    /// </summary>
    public byte[] ImageKey { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Optional nonce for image decryption (12 bytes, or empty).
    /// </summary>
    public byte[] ImageNonce { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Optional upload seed for Blossom authentication (32 bytes, or empty). v2 only.
    /// </summary>
    public byte[] ImageUploadKey { get; set; } = Array.Empty<byte>();
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
    public static Extension ToExtension(NostrGroupData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        byte[] encoded = NostrGroupDataCodec.Encode(data);
        return new Extension(ExtensionType, encoded);
    }

    /// <summary>
    /// Decodes a <see cref="NostrGroupData"/> from an MLS <see cref="Extension"/>.
    /// </summary>
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
