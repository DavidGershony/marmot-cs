using System.Collections.Concurrent;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace MarmotCs.Protocol.Crypto;

/// <summary>
/// Thrown when a duplicate outbound nonce is detected per MIP-03 §"Encryption Details".
/// The caller MUST NOT transmit the event and SHOULD perform a self-update immediately.
/// </summary>
public class DuplicateNonceException : CryptographicException
{
    public DuplicateNonceException()
        : base("Duplicate outbound nonce detected. MUST NOT transmit per MIP-03. SHOULD self-update immediately.")
    { }
}

/// <summary>
/// ChaCha20-Poly1305 encryption/decryption for kind:445 group event content (MIP-03).
/// The encryption key is the MLS exporter secret derived via MLS-Exporter("marmot", "group-event", 32).
/// </summary>
public static class GroupEventEncryption
{
    /// <summary>MLS exporter label used by the Marmot protocol.</summary>
    public const string ExporterLabel = "marmot";

    /// <summary>MLS exporter context used for group message encryption.</summary>
    public static readonly byte[] ExporterContext = "group-event"u8.ToArray();

    /// <summary>Length of the exporter secret (and ChaCha20-Poly1305 key) in bytes.</summary>
    public const int ExporterLength = 32;

    private const int NonceSize = 12;
    private const int TagSizeBits = 128;

    // Per MIP-03: "If duplicate outbound nonce detected: MUST NOT transmit"
    // Tracks outbound nonces per key (key hex -> set of nonce hex strings).
    // In practice, collision probability is ~2^-48 per pair with a 12-byte random nonce,
    // but the spec mandates the check.
    private static readonly ConcurrentDictionary<string, HashSet<string>> _outboundNonces = new();

    /// <summary>
    /// Clears all tracked outbound nonces. Call when epoch advances (key rotation)
    /// since nonces are only meaningful within the same key context.
    /// </summary>
    public static void ResetNonceTracker() => _outboundNonces.Clear();

    /// <summary>
    /// Clears tracked outbound nonces for a specific key.
    /// </summary>
    public static void ResetNonceTracker(byte[] key)
    {
        var keyHex = Convert.ToHexString(key);
        _outboundNonces.TryRemove(keyHex, out _);
    }

    /// <summary>
    /// Encrypts MLS message bytes using ChaCha20-Poly1305 per MIP-03.
    /// </summary>
    /// <param name="plaintext">The serialized MLS message bytes to encrypt.</param>
    /// <param name="key">32-byte encryption key (the MLS exporter secret used directly).</param>
    /// <returns>Base64-encoded string of nonce (12 bytes) || ciphertext (includes 16-byte auth tag).</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when key is not 32 bytes or plaintext is empty.</exception>
    /// <exception cref="CryptographicException">Thrown when the RNG fails to produce a nonce.</exception>
    public static string Encrypt(byte[] plaintext, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes.", nameof(key));
        if (plaintext.Length == 0)
            throw new ArgumentException("Plaintext must not be empty.", nameof(plaintext));

        // Generate cryptographically random 12-byte nonce
        // RNG failure: CryptographicException propagates — MUST abort, MUST NOT use deterministic fallback (MIP-03)
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);

        // Per MIP-03 §"Encryption Details": "If duplicate outbound nonce detected: MUST NOT transmit"
        var keyHex = Convert.ToHexString(key);
        var nonceHex = Convert.ToHexString(nonce);
        var nonceSet = _outboundNonces.GetOrAdd(keyHex, _ => new HashSet<string>());
        lock (nonceSet)
        {
            if (!nonceSet.Add(nonceHex))
                throw new DuplicateNonceException();
        }

        var cipher = new BcChaCha20Poly1305();
        var parameters = new AeadParameters(
            new KeyParameter(key),
            TagSizeBits,
            nonce,
            Array.Empty<byte>() // AAD = empty byte string per MIP-03
        );

        cipher.Init(true, parameters);
        byte[] ciphertextWithTag = new byte[cipher.GetOutputSize(plaintext.Length)];
        int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertextWithTag, 0);
        len += cipher.DoFinal(ciphertextWithTag, len);

        // Output: base64(nonce || ciphertext_with_tag)
        byte[] combined = new byte[NonceSize + len];
        Buffer.BlockCopy(nonce, 0, combined, 0, NonceSize);
        Buffer.BlockCopy(ciphertextWithTag, 0, combined, NonceSize, len);

        return Convert.ToBase64String(combined);
    }

    /// <summary>
    /// Decrypts kind:445 event content using ChaCha20-Poly1305 per MIP-03.
    /// </summary>
    /// <param name="encryptedContent">Base64-encoded string of nonce (12 bytes) || ciphertext (includes 16-byte auth tag).</param>
    /// <param name="key">32-byte decryption key (the MLS exporter secret used directly).</param>
    /// <returns>The decrypted MLS message bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when key is not 32 bytes.</exception>
    /// <exception cref="CryptographicException">
    /// Thrown when base64 decoding fails, content is too short, or AEAD authentication fails.
    /// </exception>
    public static byte[] Decrypt(string encryptedContent, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(encryptedContent);
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes.", nameof(key));

        byte[] combined;
        try
        {
            combined = Convert.FromBase64String(encryptedContent);
        }
        catch (FormatException ex)
        {
            throw new CryptographicException("Failed to decode message content: invalid base64.", ex);
        }

        // Minimum: 12 (nonce) + 16 (tag) = 28 bytes, plus at least 1 byte of ciphertext
        if (combined.Length < NonceSize + 16 + 1)
            throw new CryptographicException("Malformed message content: too short to contain nonce and ciphertext.");

        if (combined.Length < NonceSize)
            throw new CryptographicException("Malformed message content: nonce is shorter than 12 bytes.");

        // Extract nonce
        byte[] nonce = new byte[NonceSize];
        Buffer.BlockCopy(combined, 0, nonce, 0, NonceSize);

        // Extract ciphertext + tag
        int ciphertextWithTagLen = combined.Length - NonceSize;
        byte[] ciphertextWithTag = new byte[ciphertextWithTagLen];
        Buffer.BlockCopy(combined, NonceSize, ciphertextWithTag, 0, ciphertextWithTagLen);

        var cipher = new BcChaCha20Poly1305();
        var parameters = new AeadParameters(
            new KeyParameter(key),
            TagSizeBits,
            nonce,
            Array.Empty<byte>() // AAD = empty byte string per MIP-03
        );

        cipher.Init(false, parameters);
        byte[] plaintext = new byte[cipher.GetOutputSize(ciphertextWithTagLen)];
        int len;
        try
        {
            len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTagLen, plaintext, 0);
            len += cipher.DoFinal(plaintext, len);
        }
        catch (Org.BouncyCastle.Crypto.InvalidCipherTextException ex)
        {
            throw new CryptographicException("AEAD authentication failed: wrong key or tampered ciphertext.", ex);
        }

        byte[] result = new byte[len];
        Buffer.BlockCopy(plaintext, 0, result, 0, len);
        return result;
    }
}
