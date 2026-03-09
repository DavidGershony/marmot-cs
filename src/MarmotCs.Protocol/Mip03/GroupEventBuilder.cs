using MarmotCs.Protocol.Nip44;

namespace MarmotCs.Protocol.Mip03;

/// <summary>
/// Builds the content and tags for a Nostr kind 445 event containing an MLS group message.
/// The content is NIP-44 encrypted using a key derived from the MLS exporter secret.
/// </summary>
public static class GroupEventBuilder
{
    /// <summary>
    /// Creates the content string and tags array for a kind 445 Nostr event.
    /// </summary>
    /// <param name="mlsMessageBytes">The serialized MLS message bytes to encrypt.</param>
    /// <param name="groupId">The group identifier bytes (used as the "h" tag value in hex).</param>
    /// <param name="encryptionKey">
    /// 32-byte symmetric key derived from the MLS exporter secret, used as the NIP-44 conversation key.
    /// </param>
    /// <param name="ephemeralPrivateKey">
    /// 32-byte ephemeral secp256k1 private key used for the NIP-44 encryption step.
    /// Not used directly for encryption when a pre-derived conversation key is provided,
    /// but included for protocol compatibility.
    /// </param>
    /// <returns>
    /// A tuple of (content, tags) where content is the NIP-44 encrypted MLS message
    /// and tags contains the group hash and encoding metadata.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when mlsMessageBytes is empty or key lengths are invalid.</exception>
    public static (string content, string[][] tags) BuildGroupEvent(
        byte[] mlsMessageBytes,
        byte[] groupId,
        byte[] encryptionKey,
        byte[] ephemeralPrivateKey)
    {
        ArgumentNullException.ThrowIfNull(mlsMessageBytes);
        ArgumentNullException.ThrowIfNull(groupId);
        ArgumentNullException.ThrowIfNull(encryptionKey);
        ArgumentNullException.ThrowIfNull(ephemeralPrivateKey);

        if (mlsMessageBytes.Length == 0)
            throw new ArgumentException("MLS message bytes must not be empty.", nameof(mlsMessageBytes));
        if (encryptionKey.Length != 32)
            throw new ArgumentException("Encryption key must be 32 bytes.", nameof(encryptionKey));
        if (ephemeralPrivateKey.Length != 32)
            throw new ArgumentException("Ephemeral private key must be 32 bytes.", nameof(ephemeralPrivateKey));

        // Encrypt the MLS message using NIP-44 with the exporter-derived key as conversation key
        string mlsBase64 = Convert.ToBase64String(mlsMessageBytes);
        string encryptedContent = Nip44Encryption.Encrypt(mlsBase64, encryptionKey);

        // Group ID as hex string for the "h" tag
        string groupIdHex = Convert.ToHexString(groupId).ToLowerInvariant();

        string[][] tags = new[]
        {
            new[] { "h", groupIdHex },
            new[] { "encoding", "mls" }
        };

        return (encryptedContent, tags);
    }
}
