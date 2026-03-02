using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace MarmotMdk.Protocol.Crypto;

/// <summary>
/// ChaCha20-Poly1305 encryption/decryption for group images (MIP-01).
/// The encryption key is derived from the MLS exporter secret using HKDF-Expand.
/// </summary>
public static class ImageEncryption
{
    private static readonly byte[] ImageKeyLabel = Encoding.UTF8.GetBytes("marmot-group-image");
    private const int NonceSize = 12;
    private const int TagSizeBits = 128;

    /// <summary>
    /// Encrypts an image using ChaCha20-Poly1305.
    /// A random 12-byte nonce is prepended to the output.
    /// </summary>
    /// <param name="image">The image bytes to encrypt.</param>
    /// <param name="key">32-byte encryption key (derived from HKDF-Expand(exporter_secret, "marmot-group-image", 32)).</param>
    /// <returns>The encrypted output: nonce (12 bytes) || ciphertext || tag (16 bytes).</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when key is not 32 bytes or image is empty.</exception>
    public static byte[] Encrypt(byte[] image, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(image);
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes.", nameof(key));
        if (image.Length == 0)
            throw new ArgumentException("Image must not be empty.", nameof(image));

        // Generate random nonce
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);

        var cipher = new BcChaCha20Poly1305();
        var parameters = new AeadParameters(
            new KeyParameter(key),
            TagSizeBits,
            nonce,
            Array.Empty<byte>()
        );

        cipher.Init(true, parameters);
        byte[] ciphertextWithTag = new byte[cipher.GetOutputSize(image.Length)];
        int len = cipher.ProcessBytes(image, 0, image.Length, ciphertextWithTag, 0);
        len += cipher.DoFinal(ciphertextWithTag, len);

        // Output: nonce || ciphertext || tag
        byte[] output = new byte[NonceSize + len];
        Buffer.BlockCopy(nonce, 0, output, 0, NonceSize);
        Buffer.BlockCopy(ciphertextWithTag, 0, output, NonceSize, len);

        return output;
    }

    /// <summary>
    /// Decrypts an image that was encrypted with <see cref="Encrypt"/>.
    /// Expects the input format: nonce (12 bytes) || ciphertext || tag (16 bytes).
    /// </summary>
    /// <param name="encrypted">The encrypted data including the prepended nonce.</param>
    /// <param name="key">32-byte encryption key (same key used for encryption).</param>
    /// <returns>The decrypted image bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when key is not 32 bytes or encrypted data is too short.</exception>
    /// <exception cref="Org.BouncyCastle.Crypto.InvalidCipherTextException">
    /// Thrown when authentication tag verification fails.
    /// </exception>
    public static byte[] Decrypt(byte[] encrypted, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(encrypted);
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
            throw new ArgumentException("Key must be 32 bytes.", nameof(key));
        // Minimum: 12 (nonce) + 16 (tag) = 28 bytes, plus at least 1 byte of ciphertext
        if (encrypted.Length < NonceSize + 16 + 1)
            throw new ArgumentException("Encrypted data is too short.", nameof(encrypted));

        // Extract nonce
        byte[] nonce = new byte[NonceSize];
        Buffer.BlockCopy(encrypted, 0, nonce, 0, NonceSize);

        // Extract ciphertext + tag
        int ciphertextWithTagLen = encrypted.Length - NonceSize;
        byte[] ciphertextWithTag = new byte[ciphertextWithTagLen];
        Buffer.BlockCopy(encrypted, NonceSize, ciphertextWithTag, 0, ciphertextWithTagLen);

        var cipher = new BcChaCha20Poly1305();
        var parameters = new AeadParameters(
            new KeyParameter(key),
            TagSizeBits,
            nonce,
            Array.Empty<byte>()
        );

        cipher.Init(false, parameters);
        byte[] plaintext = new byte[cipher.GetOutputSize(ciphertextWithTagLen)];
        int len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTagLen, plaintext, 0);
        len += cipher.DoFinal(plaintext, len);

        byte[] result = new byte[len];
        Buffer.BlockCopy(plaintext, 0, result, 0, len);
        return result;
    }

    /// <summary>
    /// Derives a 32-byte image encryption key from an MLS exporter secret.
    /// Uses HKDF-Expand(SHA256, exporterSecret, "marmot-group-image", 32).
    /// </summary>
    /// <param name="exporterSecret">The MLS exporter secret bytes.</param>
    /// <returns>A 32-byte key suitable for use with <see cref="Encrypt"/> and <see cref="Decrypt"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="exporterSecret"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="exporterSecret"/> is empty.</exception>
    public static byte[] DeriveImageKey(byte[] exporterSecret)
    {
        ArgumentNullException.ThrowIfNull(exporterSecret);
        if (exporterSecret.Length == 0)
            throw new ArgumentException("Exporter secret must not be empty.", nameof(exporterSecret));

        return HKDF.Expand(HashAlgorithmName.SHA256, exporterSecret, 32, ImageKeyLabel);
    }
}
