using System.Text;
using DotnetMls.Codec;

namespace MarmotCs.Protocol.Mip01;

/// <summary>
/// Encodes and decodes <see cref="NostrGroupData"/> using TLS codec,
/// matching the Rust MDK <c>TlsNostrGroupDataExtension</c> wire format exactly.
/// </summary>
/// <remarks>
/// Wire format (all length prefixes are MLS VarInt per RFC 9000 Section 16):
/// <list type="bullet">
///   <item>u16: version</item>
///   <item>[u8; 32]: nostr_group_id</item>
///   <item>opaque&lt;V&gt;: name (UTF-8)</item>
///   <item>opaque&lt;V&gt;: description (UTF-8)</item>
///   <item>vector&lt;V&gt; of [u8; 32]: admin_pubkeys</item>
///   <item>vector&lt;V&gt; of opaque&lt;V&gt;: relays (UTF-8 strings)</item>
///   <item>opaque&lt;V&gt;: image_hash (0 or 32 bytes)</item>
///   <item>opaque&lt;V&gt;: image_key (0 or 32 bytes)</item>
///   <item>opaque&lt;V&gt;: image_nonce (0 or 12 bytes)</item>
///   <item>opaque&lt;V&gt;: image_upload_key (0 or 32 bytes, v2 only)</item>
/// </list>
/// </remarks>
public static class NostrGroupDataCodec
{
    /// <summary>
    /// Encodes a <see cref="NostrGroupData"/> to its TLS binary representation.
    /// </summary>
    public static byte[] Encode(NostrGroupData data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.AdminPubkeys.Length % 32 != 0)
            throw new ArgumentException(
                "AdminPubkeys must be a concatenation of 32-byte public keys.",
                nameof(data));

        if (data.NostrGroupId.Length != 32)
            throw new ArgumentException(
                "NostrGroupId must be exactly 32 bytes.",
                nameof(data));

        using var writer = new TlsWriter();

        // version: u16
        writer.WriteUint16(data.Version);

        // nostr_group_id: [u8; 32]
        writer.WriteBytes(data.NostrGroupId);

        // name: opaque<V>
        writer.WriteOpaqueV(Encoding.UTF8.GetBytes(data.Name));

        // description: opaque<V>
        writer.WriteOpaqueV(Encoding.UTF8.GetBytes(data.Description));

        // admin_pubkeys: vector<V> of [u8; 32]
        writer.WriteVarIntLength(data.AdminPubkeys.Length);
        if (data.AdminPubkeys.Length > 0)
            writer.WriteBytes(data.AdminPubkeys);

        // relays: vector<V> of opaque<V>
        writer.WriteVectorV(inner =>
        {
            foreach (var relay in data.Relays)
            {
                inner.WriteOpaqueV(Encoding.UTF8.GetBytes(relay));
            }
        });

        // image_hash: opaque<V>
        writer.WriteOpaqueV(data.ImageHash);

        // image_key: opaque<V>
        writer.WriteOpaqueV(data.ImageKey);

        // image_nonce: opaque<V>
        writer.WriteOpaqueV(data.ImageNonce);

        // image_upload_key: opaque<V> (v2 only)
        if (data.Version >= 2)
        {
            writer.WriteOpaqueV(data.ImageUploadKey);
        }

        return writer.ToArray();
    }

    /// <summary>
    /// Decodes a <see cref="NostrGroupData"/> from its TLS binary representation.
    /// </summary>
    public static NostrGroupData Decode(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        var reader = new TlsReader(data);
        var result = new NostrGroupData();

        // version: u16
        result.Version = reader.ReadUint16();

        if (result.Version == 0)
            throw new FormatException("NostrGroupData version 0 is not supported.");

        // nostr_group_id: [u8; 32]
        result.NostrGroupId = reader.ReadBytes(32);

        // name: opaque<V>
        result.Name = Encoding.UTF8.GetString(reader.ReadOpaqueV());

        // description: opaque<V>
        result.Description = Encoding.UTF8.GetString(reader.ReadOpaqueV());

        // admin_pubkeys: vector<V> of [u8; 32]
        int adminBytesLen = reader.ReadVarIntLength();
        if (adminBytesLen > 0)
        {
            if (adminBytesLen % 32 != 0)
                throw new FormatException(
                    $"admin_pubkeys byte length {adminBytesLen} is not a multiple of 32.");
            result.AdminPubkeys = reader.ReadBytes(adminBytesLen);
        }

        // relays: vector<V> of opaque<V>
        var relayReader = reader.ReadVectorV();
        var relays = new List<string>();
        while (!relayReader.IsEmpty)
        {
            var relayData = relayReader.ReadOpaqueV();
            relays.Add(Encoding.UTF8.GetString(relayData));
        }
        result.Relays = relays.ToArray();

        // image_hash: opaque<V>
        if (reader.Remaining > 0)
            result.ImageHash = reader.ReadOpaqueV();

        // image_key: opaque<V>
        if (reader.Remaining > 0)
            result.ImageKey = reader.ReadOpaqueV();

        // image_nonce: opaque<V>
        if (reader.Remaining > 0)
            result.ImageNonce = reader.ReadOpaqueV();

        // image_upload_key: opaque<V> (v2 only)
        if (result.Version >= 2 && reader.Remaining > 0)
        {
            result.ImageUploadKey = reader.ReadOpaqueV();
        }

        return result;
    }
}
