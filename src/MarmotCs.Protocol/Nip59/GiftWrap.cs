using MarmotCs.Protocol.Nip44;

namespace MarmotCs.Protocol.Nip59;

/// <summary>
/// NIP-59 gift wrapping for anonymous message delivery.
/// Provides sealing (NIP-44 encryption) and unsealing (NIP-44 decryption) of content
/// between a sender and recipient using secp256k1 key pairs.
/// </summary>
/// <remarks>
/// In a full NIP-59 implementation:
/// <list type="number">
///   <item>A "seal" event (kind 13) is created with NIP-44 encrypted content, signed by the sender.</item>
///   <item>The seal is wrapped in a "gift wrap" event (kind 1059) from an ephemeral key.</item>
/// </list>
/// For Marmot, this class provides the NIP-44 encryption/decryption primitives.
/// Actual Nostr event construction happens at the Core layer.
/// </remarks>
public static class GiftWrap
{
    /// <summary>
    /// Seals (encrypts) content from a sender to a recipient using NIP-44 encryption.
    /// </summary>
    /// <param name="content">The plaintext content bytes to seal.</param>
    /// <param name="senderPrivateKey">32-byte secp256k1 private key of the sender.</param>
    /// <param name="recipientPublicKey">32-byte x-only or 33-byte compressed secp256k1 public key of the recipient.</param>
    /// <returns>The sealed (encrypted) content as a byte array (base64-decoded NIP-44 payload).</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when key lengths are invalid or content is empty.</exception>
    public static byte[] SealContent(byte[] content, byte[] senderPrivateKey, byte[] recipientPublicKey)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(senderPrivateKey);
        ArgumentNullException.ThrowIfNull(recipientPublicKey);

        if (content.Length == 0)
            throw new ArgumentException("Content must not be empty.", nameof(content));

        // Derive the NIP-44 conversation key from sender's private key and recipient's public key
        byte[] conversationKey = Nip44Encryption.DeriveConversationKey(senderPrivateKey, recipientPublicKey);

        // Encrypt the content as a UTF-8 string (NIP-44 operates on strings)
        string contentString = Convert.ToBase64String(content);
        string encrypted = Nip44Encryption.Encrypt(contentString, conversationKey);

        return System.Text.Encoding.UTF8.GetBytes(encrypted);
    }

    /// <summary>
    /// Unseals (decrypts) content that was sealed from a sender to the recipient.
    /// </summary>
    /// <param name="sealedContent">The sealed content bytes (UTF-8 encoded NIP-44 payload).</param>
    /// <param name="recipientPrivateKey">32-byte secp256k1 private key of the recipient.</param>
    /// <param name="senderPublicKey">32-byte x-only or 33-byte compressed secp256k1 public key of the sender.</param>
    /// <returns>The original plaintext content bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when key lengths are invalid.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// Thrown when MAC verification or decryption fails.
    /// </exception>
    public static byte[] UnsealContent(byte[] sealedContent, byte[] recipientPrivateKey, byte[] senderPublicKey)
    {
        ArgumentNullException.ThrowIfNull(sealedContent);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ArgumentNullException.ThrowIfNull(senderPublicKey);

        // Derive the same conversation key (ECDH is commutative)
        byte[] conversationKey = Nip44Encryption.DeriveConversationKey(recipientPrivateKey, senderPublicKey);

        // Decrypt the NIP-44 payload
        string payload = System.Text.Encoding.UTF8.GetString(sealedContent);
        string decryptedBase64 = Nip44Encryption.Decrypt(payload, conversationKey);

        return Convert.FromBase64String(decryptedBase64);
    }
}
