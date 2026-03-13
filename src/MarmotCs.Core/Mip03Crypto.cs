using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace MarmotCs.Core;

/// <summary>
/// MIP-03 message encryption/decryption using ChaCha20-Poly1305.
/// The exporter secret from the MLS key schedule is used directly as the symmetric key.
/// Wire format: <c>nonce[12] || ciphertext[N] || poly1305_tag[16]</c>.
/// </summary>
public static class Mip03Crypto
{
    /// <summary>MLS exporter label used by the Marmot protocol.</summary>
    public const string ExporterLabel = "marmot";

    /// <summary>MLS exporter context used for group message encryption.</summary>
    public static readonly byte[] ExporterContext = "group-event"u8.ToArray();

    /// <summary>Length of the exporter secret (and ChaCha20-Poly1305 key) in bytes.</summary>
    public const int ExporterLength = 32;

    private const int NonceSize = 12;
    private const int TagSize = 16;

    /// <summary>
    /// Encrypts plaintext MLS message bytes using MIP-03 (ChaCha20-Poly1305 with exporter secret).
    /// </summary>
    /// <param name="exporterSecret">The 32-byte MLS exporter secret, used directly as the key.</param>
    /// <param name="plaintext">The raw MLS message bytes to encrypt.</param>
    /// <returns>The wire-format bytes: <c>nonce[12] || ciphertext || tag[16]</c>.</returns>
    public static byte[] Encrypt(byte[] exporterSecret, byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(exporterSecret);
        ArgumentNullException.ThrowIfNull(plaintext);
        if (exporterSecret.Length != ExporterLength)
            throw new ArgumentException($"Exporter secret must be {ExporterLength} bytes.", nameof(exporterSecret));

        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        // BouncyCastle ChaCha20-Poly1305 produces ciphertext || tag in one output
        var cipher = new BcChaCha20Poly1305();
        cipher.Init(true, new AeadParameters(new KeyParameter(exporterSecret), TagSize * 8, nonce));

        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        cipher.DoFinal(output, len);

        // Wire format: nonce || ciphertext || tag
        // BouncyCastle output is already ciphertext || tag
        var result = new byte[NonceSize + output.Length];
        nonce.CopyTo(result, 0);
        output.CopyTo(result, NonceSize);
        return result;
    }

    /// <summary>
    /// Decrypts MIP-03 encrypted bytes using ChaCha20-Poly1305 with the exporter secret.
    /// </summary>
    /// <param name="exporterSecret">The 32-byte MLS exporter secret, used directly as the key.</param>
    /// <param name="encryptedData">The wire-format bytes: <c>nonce[12] || ciphertext || tag[16]</c>.</param>
    /// <returns>The decrypted plaintext (raw MLS message bytes).</returns>
    public static byte[] Decrypt(byte[] exporterSecret, byte[] encryptedData)
    {
        ArgumentNullException.ThrowIfNull(exporterSecret);
        ArgumentNullException.ThrowIfNull(encryptedData);
        if (exporterSecret.Length != ExporterLength)
            throw new ArgumentException($"Exporter secret must be {ExporterLength} bytes.", nameof(exporterSecret));
        if (encryptedData.Length < NonceSize + TagSize)
            throw new ArgumentException(
                $"Encrypted data must be at least {NonceSize + TagSize} bytes (nonce + tag).",
                nameof(encryptedData));

        var nonce = new byte[NonceSize];
        Array.Copy(encryptedData, 0, nonce, 0, NonceSize);

        // Input to BouncyCastle is ciphertext || tag (everything after nonce)
        int encLen = encryptedData.Length - NonceSize;

        var cipher = new BcChaCha20Poly1305();
        cipher.Init(false, new AeadParameters(new KeyParameter(exporterSecret), TagSize * 8, nonce));

        var plaintext = new byte[cipher.GetOutputSize(encLen)];
        int len = cipher.ProcessBytes(encryptedData, NonceSize, encLen, plaintext, 0);
        cipher.DoFinal(plaintext, len);

        return plaintext;
    }
}
