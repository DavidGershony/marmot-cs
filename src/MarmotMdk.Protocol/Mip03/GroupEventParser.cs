using MarmotMdk.Protocol.Nip44;

namespace MarmotMdk.Protocol.Mip03;

/// <summary>
/// Parses the content and tags of a Nostr kind 445 event to extract an MLS group message.
/// The content is NIP-44 decrypted using a key derived from the MLS exporter secret.
/// </summary>
public static class GroupEventParser
{
    /// <summary>
    /// Parses a kind 445 Nostr event's content and tags to extract the MLS message bytes
    /// and group identifier.
    /// </summary>
    /// <param name="content">The NIP-44 encrypted content of the Nostr event.</param>
    /// <param name="tags">The tags array from the Nostr event.</param>
    /// <param name="decryptionKey">
    /// 32-byte symmetric key derived from the MLS exporter secret, used as the NIP-44 conversation key.
    /// </param>
    /// <param name="senderPublicKey">
    /// The ephemeral public key of the sender for NIP-44 decryption.
    /// Not used directly when a pre-derived conversation key is provided,
    /// but included for protocol compatibility.
    /// </param>
    /// <returns>
    /// A tuple of (mlsMessageBytes, groupId) containing the decrypted MLS message
    /// and the group identifier bytes.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="FormatException">Thrown when the event format is invalid or required tags are missing.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown when decryption fails.
    /// </exception>
    public static (byte[] mlsMessageBytes, byte[] groupId) ParseGroupEvent(
        string content,
        string[][] tags,
        byte[] decryptionKey,
        byte[] senderPublicKey)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(tags);
        ArgumentNullException.ThrowIfNull(decryptionKey);
        ArgumentNullException.ThrowIfNull(senderPublicKey);

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

        // Decrypt the NIP-44 encrypted content using the exporter-derived key
        string decryptedBase64 = Nip44Encryption.Decrypt(content, decryptionKey);
        byte[] mlsMessageBytes = Convert.FromBase64String(decryptedBase64);

        return (mlsMessageBytes, groupId);
    }
}
