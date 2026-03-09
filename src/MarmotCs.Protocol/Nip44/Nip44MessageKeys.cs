using System.Security.Cryptography;

namespace MarmotCs.Protocol.Nip44;

/// <summary>
/// Holds the per-message key material derived from the NIP-44 conversation key and a random nonce.
/// Keys are derived via HKDF-Expand(conversationKey, nonce, 76) then split into three parts.
/// </summary>
public sealed class Nip44MessageKeys
{
    /// <summary>
    /// 32-byte ChaCha20-Poly1305 encryption key.
    /// </summary>
    public byte[] EncryptionKey { get; }

    /// <summary>
    /// 12-byte ChaCha20-Poly1305 nonce.
    /// </summary>
    public byte[] Nonce { get; }

    /// <summary>
    /// 32-byte HMAC-SHA256 key for computing the MAC over nonce || ciphertext.
    /// </summary>
    public byte[] HmacKey { get; }

    private Nip44MessageKeys(byte[] encryptionKey, byte[] nonce, byte[] hmacKey)
    {
        EncryptionKey = encryptionKey;
        Nonce = nonce;
        HmacKey = hmacKey;
    }

    /// <summary>
    /// Derives per-message keys from a 32-byte conversation key and a 32-byte nonce.
    /// Uses HKDF-Expand(prk=conversationKey, info=nonce, L=76).
    /// </summary>
    /// <param name="conversationKey">32-byte NIP-44 conversation key (derived from ECDH).</param>
    /// <param name="nonce">32-byte random nonce for this message.</param>
    /// <returns>A <see cref="Nip44MessageKeys"/> containing the three derived keys.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="conversationKey"/> is not 32 bytes or <paramref name="nonce"/> is not 32 bytes.
    /// </exception>
    public static Nip44MessageKeys Derive(byte[] conversationKey, byte[] nonce)
    {
        if (conversationKey.Length != 32)
            throw new ArgumentException("Conversation key must be 32 bytes.", nameof(conversationKey));
        if (nonce.Length != 32)
            throw new ArgumentException("Nonce must be 32 bytes.", nameof(nonce));

        // HKDF-Expand with the conversation key as PRK and the nonce as info, producing 76 bytes
        byte[] expanded = HKDF.Expand(HashAlgorithmName.SHA256, conversationKey, 76, nonce);

        byte[] encryptionKey = new byte[32];
        byte[] chachaNonce = new byte[12];
        byte[] hmacKey = new byte[32];

        Buffer.BlockCopy(expanded, 0, encryptionKey, 0, 32);
        Buffer.BlockCopy(expanded, 32, chachaNonce, 0, 12);
        Buffer.BlockCopy(expanded, 44, hmacKey, 0, 32);

        return new Nip44MessageKeys(encryptionKey, chachaNonce, hmacKey);
    }
}
