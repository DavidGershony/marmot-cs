using System.Text;
using DotnetMls.Codec;

namespace MarmotCs.Protocol.Mip01;

/// <summary>
/// Encodes and decodes <see cref="NostrGroupData"/> using TLS codec,
/// matching the Rust MDK <c>TlsNostrGroupDataExtension</c> wire format exactly.
/// </summary>
/// <remarks>
/// Wire format (all length prefixes are u16 big-endian):
/// <list type="bullet">
///   <item>u16: version</item>
///   <item>[u8; 32]: nostr_group_id</item>
///   <item>opaque&lt;2&gt;: name (UTF-8)</item>
///   <item>opaque&lt;2&gt;: description (UTF-8)</item>
///   <item>vector&lt;2&gt; of [u8; 32]: admin_pubkeys</item>
///   <item>vector&lt;2&gt; of opaque&lt;2&gt;: relays (UTF-8 strings)</item>
///   <item>opaque&lt;2&gt;: image_hash (0 or 32 bytes)</item>
///   <item>opaque&lt;2&gt;: image_key (0 or 32 bytes)</item>
///   <item>opaque&lt;2&gt;: image_nonce (0 or 12 bytes)</item>
///   <item>opaque&lt;2&gt;: image_upload_key (0 or 32 bytes, v2 only)</item>
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

        // name: opaque<2>
        WriteOpaque2(writer, Encoding.UTF8.GetBytes(data.Name));

        // description: opaque<2>
        WriteOpaque2(writer, Encoding.UTF8.GetBytes(data.Description));

        // admin_pubkeys: vector<2> of [u8; 32]
        // The u16 prefix is the total byte count of all keys
        writer.WriteUint16((ushort)data.AdminPubkeys.Length);
        if (data.AdminPubkeys.Length > 0)
            writer.WriteBytes(data.AdminPubkeys);

        // relays: vector<2> of opaque<2>
        // Need to compute total byte length of all relay entries first
        byte[][] relayBytes = new byte[data.Relays.Length][];
        int totalRelayBytes = 0;
        for (int i = 0; i < data.Relays.Length; i++)
        {
            relayBytes[i] = Encoding.UTF8.GetBytes(data.Relays[i]);
            totalRelayBytes += 2 + relayBytes[i].Length; // u16 prefix + data
        }
        writer.WriteUint16((ushort)totalRelayBytes);
        foreach (byte[] rb in relayBytes)
        {
            WriteOpaque2(writer, rb);
        }

        // image_hash: opaque<2>
        WriteOpaque2(writer, data.ImageHash);

        // image_key: opaque<2>
        WriteOpaque2(writer, data.ImageKey);

        // image_nonce: opaque<2>
        WriteOpaque2(writer, data.ImageNonce);

        // image_upload_key: opaque<2> (v2 only)
        if (data.Version >= 2)
        {
            WriteOpaque2(writer, data.ImageUploadKey);
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

        // name: opaque<2>
        result.Name = Encoding.UTF8.GetString(ReadOpaque2(reader));

        // description: opaque<2>
        result.Description = Encoding.UTF8.GetString(ReadOpaque2(reader));

        // admin_pubkeys: vector<2> of [u8; 32]
        ushort adminBytesLen = reader.ReadUint16();
        if (adminBytesLen > 0)
        {
            if (adminBytesLen % 32 != 0)
                throw new FormatException(
                    $"admin_pubkeys byte length {adminBytesLen} is not a multiple of 32.");
            result.AdminPubkeys = reader.ReadBytes(adminBytesLen);
        }

        // relays: vector<2> of opaque<2>
        ushort relayBytesLen = reader.ReadUint16();
        var relays = new List<string>();
        int relayBytesRead = 0;
        while (relayBytesRead < relayBytesLen)
        {
            ushort entryLen = reader.ReadUint16();
            relayBytesRead += 2;
            byte[] entryBytes = reader.ReadBytes(entryLen);
            relayBytesRead += entryLen;
            relays.Add(Encoding.UTF8.GetString(entryBytes));
        }
        result.Relays = relays.ToArray();

        // image_hash: opaque<2>
        result.ImageHash = ReadOpaque2(reader);

        // image_key: opaque<2>
        result.ImageKey = ReadOpaque2(reader);

        // image_nonce: opaque<2>
        result.ImageNonce = ReadOpaque2(reader);

        // image_upload_key: opaque<2> (v2 only)
        if (result.Version >= 2 && reader.Remaining > 0)
        {
            result.ImageUploadKey = ReadOpaque2(reader);
        }

        return result;
    }

    private static void WriteOpaque2(TlsWriter writer, byte[] value)
    {
        writer.WriteUint16((ushort)value.Length);
        if (value.Length > 0)
            writer.WriteBytes(value);
    }

    private static byte[] ReadOpaque2(TlsReader reader)
    {
        ushort length = reader.ReadUint16();
        if (length == 0)
            return Array.Empty<byte>();
        return reader.ReadBytes(length);
    }
}
