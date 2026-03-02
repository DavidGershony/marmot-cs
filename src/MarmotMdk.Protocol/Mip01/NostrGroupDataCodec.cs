using System.Text;
using DotnetMls.Codec;

namespace MarmotMdk.Protocol.Mip01;

/// <summary>
/// Encodes and decodes <see cref="NostrGroupData"/> using QUIC varint-based binary format (version 2).
/// </summary>
/// <remarks>
/// Version 2 encoding layout:
/// <list type="bullet">
///   <item>QUIC varint: version (2)</item>
///   <item>QUIC varint-prefixed UTF-8: name</item>
///   <item>QUIC varint-prefixed UTF-8: description</item>
///   <item>QUIC varint: num_admins, followed by num_admins * 32 bytes of concatenated public keys</item>
///   <item>QUIC varint: num_relays, followed by QUIC varint-prefixed UTF-8 relay URLs</item>
/// </list>
/// </remarks>
public static class NostrGroupDataCodec
{
    /// <summary>
    /// Encodes a <see cref="NostrGroupData"/> to its binary representation.
    /// </summary>
    /// <param name="data">The group data to encode.</param>
    /// <returns>The serialized byte array.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when AdminPubkeys length is not a multiple of 32 bytes.
    /// </exception>
    public static byte[] Encode(NostrGroupData data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.AdminPubkeys.Length % 32 != 0)
            throw new ArgumentException(
                "AdminPubkeys must be a concatenation of 32-byte public keys.",
                nameof(data));

        using var writer = new TlsWriter();

        // Version
        QuicVarint.Write(writer, data.Version);

        // Name (QUIC varint-prefixed UTF-8)
        WriteQuicString(writer, data.Name);

        // Description (QUIC varint-prefixed UTF-8)
        WriteQuicString(writer, data.Description);

        // Admin pubkeys: count then raw 32-byte keys
        int numAdmins = data.AdminPubkeys.Length / 32;
        QuicVarint.Write(writer, (ulong)numAdmins);
        if (numAdmins > 0)
            writer.WriteBytes(data.AdminPubkeys);

        // Relays: count then QUIC varint-prefixed UTF-8 strings
        QuicVarint.Write(writer, (ulong)data.Relays.Length);
        foreach (string relay in data.Relays)
        {
            WriteQuicString(writer, relay);
        }

        return writer.ToArray();
    }

    /// <summary>
    /// Decodes a <see cref="NostrGroupData"/> from its binary representation.
    /// </summary>
    /// <param name="data">The serialized byte array.</param>
    /// <returns>The decoded <see cref="NostrGroupData"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
    /// <exception cref="FormatException">Thrown when the data format is invalid.</exception>
    public static NostrGroupData Decode(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        var reader = new TlsReader(data);
        var result = new NostrGroupData();

        // Version
        result.Version = (ushort)QuicVarint.Read(reader);

        if (result.Version != 2)
            throw new FormatException($"Unsupported NostrGroupData version: {result.Version}. Expected 2.");

        // Name
        result.Name = ReadQuicString(reader);

        // Description
        result.Description = ReadQuicString(reader);

        // Admin pubkeys
        int numAdmins = (int)QuicVarint.Read(reader);
        if (numAdmins > 0)
        {
            result.AdminPubkeys = reader.ReadBytes(numAdmins * 32);
        }

        // Relays
        int numRelays = (int)QuicVarint.Read(reader);
        result.Relays = new string[numRelays];
        for (int i = 0; i < numRelays; i++)
        {
            result.Relays[i] = ReadQuicString(reader);
        }

        return result;
    }

    private static void WriteQuicString(TlsWriter writer, string value)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(value);
        QuicVarint.Write(writer, (ulong)utf8.Length);
        writer.WriteBytes(utf8);
    }

    private static string ReadQuicString(TlsReader reader)
    {
        int length = (int)QuicVarint.Read(reader);
        byte[] utf8 = reader.ReadBytes(length);
        return Encoding.UTF8.GetString(utf8);
    }
}
