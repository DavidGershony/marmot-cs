using System.Security.Cryptography;
using MarmotCs.Protocol.Crypto;

namespace MarmotCs.Protocol.Mip03;

/// <summary>
/// Parses the content and tags of a Nostr kind 445 event to extract an MLS group message.
/// The content is decrypted with ChaCha20-Poly1305 using the MLS exporter secret directly as the key.
/// </summary>
public static class GroupEventParser
{
    /// <summary>
    /// Parses a kind 445 Nostr event's content and tags to extract the MLS message bytes
    /// and group identifier.
    /// </summary>
    /// <param name="content">The ChaCha20-Poly1305 encrypted content as base64(nonce || ciphertext).</param>
    /// <param name="tags">The tags array from the Nostr event.</param>
    /// <param name="decryptionKey">
    /// 32-byte symmetric key derived via MLS-Exporter("marmot", "group-event", 32),
    /// used directly as the ChaCha20-Poly1305 key.
    /// </param>
    /// <returns>
    /// A tuple of (mlsMessageBytes, groupId) containing the decrypted MLS message
    /// and the group identifier bytes.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="FormatException">Thrown when the event format is invalid or required tags are missing.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails (invalid base64, short nonce, or AEAD auth failure).</exception>
    public static (byte[] mlsMessageBytes, byte[] groupId) ParseGroupEvent(
        string content,
        string[][] tags,
        byte[] decryptionKey)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(tags);
        ArgumentNullException.ThrowIfNull(decryptionKey);

        if (decryptionKey.Length != 32)
            throw new ArgumentException("Decryption key must be 32 bytes.", nameof(decryptionKey));

        // Extract group ID from the "h" tag
        string? groupIdHex = null;
        foreach (string[] tag in tags)
        {
            if (tag.Length >= 2 && tag[0] == "h")
            {
                groupIdHex = tag[1];
                break;
            }
        }

        if (string.IsNullOrEmpty(groupIdHex))
            throw new FormatException("Missing or empty 'h' tag for group ID.");

        byte[] groupId = Convert.FromHexString(groupIdHex);

        // Decrypt the ChaCha20-Poly1305 encrypted content per MIP-03
        byte[] mlsMessageBytes = GroupEventEncryption.Decrypt(content, decryptionKey);

        return (mlsMessageBytes, groupId);
    }
}
