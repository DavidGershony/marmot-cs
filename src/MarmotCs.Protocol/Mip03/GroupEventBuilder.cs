using System.Security.Cryptography;
using MarmotCs.Protocol.Crypto;

namespace MarmotCs.Protocol.Mip03;

/// <summary>
/// Builds the content and tags for a Nostr kind 445 event containing an MLS group message.
/// The content is encrypted with ChaCha20-Poly1305 using the MLS exporter secret directly as the key.
/// </summary>
public static class GroupEventBuilder
{
    /// <summary>
    /// Creates the content string and tags array for a kind 445 Nostr event.
    /// </summary>
    /// <param name="mlsMessageBytes">The serialized MLS message bytes to encrypt.</param>
    /// <param name="groupId">The group identifier bytes (used as the "h" tag value in hex).</param>
    /// <param name="encryptionKey">
    /// 32-byte symmetric key derived via MLS-Exporter("marmot", "group-event", 32),
    /// used directly as the ChaCha20-Poly1305 key.
    /// </param>
    /// <returns>
    /// A tuple of (content, tags) where content is base64(nonce || ciphertext)
    /// and tags contains the group hash and encoding metadata.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when mlsMessageBytes is empty or key length is invalid.</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails.</exception>
    public static (string content, string[][] tags) BuildGroupEvent(
        byte[] mlsMessageBytes,
        byte[] groupId,
        byte[] encryptionKey)
    {
        ArgumentNullException.ThrowIfNull(mlsMessageBytes);
        ArgumentNullException.ThrowIfNull(groupId);
        ArgumentNullException.ThrowIfNull(encryptionKey);

        if (mlsMessageBytes.Length == 0)
            throw new ArgumentException("MLS message bytes must not be empty.", nameof(mlsMessageBytes));
        if (encryptionKey.Length != 32)
            throw new ArgumentException("Encryption key must be 32 bytes.", nameof(encryptionKey));

        // Encrypt the MLS message using ChaCha20-Poly1305 per MIP-03
        // content = base64(nonce || ciphertext) where ciphertext includes the 16-byte auth tag
        string encryptedContent = GroupEventEncryption.Encrypt(mlsMessageBytes, encryptionKey);

        // Group ID as hex string for the "h" tag
        string groupIdHex = Convert.ToHexString(groupId).ToLowerInvariant();

        string[][] tags =
        [
            ["h", groupIdHex],
            ["encoding", "base64"]
        ];

        return (encryptedContent, tags);
    }
}
