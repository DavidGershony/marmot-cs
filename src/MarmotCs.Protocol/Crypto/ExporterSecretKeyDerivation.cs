using System.Security.Cryptography;
using System.Text;
using NBitcoin.Secp256k1;

namespace MarmotCs.Protocol.Crypto;

/// <summary>
/// Derives secp256k1 key pairs from MLS exporter secrets.
/// Used for signing kind 445 events and deriving encryption keys for group messages.
/// </summary>
public static class ExporterSecretKeyDerivation
{
    private static readonly byte[] KeyDerivationLabel = Encoding.UTF8.GetBytes("marmot-nostr-key");

    /// <summary>
    /// Derives a secp256k1 key pair from an MLS exporter secret.
    /// </summary>
    /// <param name="exporterSecret">The MLS exporter secret bytes (typically 32 bytes).</param>
    /// <returns>
    /// A tuple of (privateKey, publicKey) where privateKey is 32 bytes and publicKey
    /// is 32 bytes (x-only / Schnorr format, suitable for Nostr).
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="exporterSecret"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="exporterSecret"/> is empty.</exception>
    /// <exception cref="CryptographicException">
    /// Thrown if a valid secp256k1 private key cannot be derived (extremely unlikely).
    /// </exception>
    public static (byte[] privateKey, byte[] publicKey) DeriveKeyPair(byte[] exporterSecret)
    {
        ArgumentNullException.ThrowIfNull(exporterSecret);
        if (exporterSecret.Length == 0)
            throw new ArgumentException("Exporter secret must not be empty.", nameof(exporterSecret));

        // Derive a 32-byte private key candidate using HKDF-Expand
        // private_key = HKDF-Expand(SHA256, exporter_secret, "marmot-nostr-key", 32)
        byte[] privateKeyBytes = HKDF.Expand(HashAlgorithmName.SHA256, exporterSecret, 32, KeyDerivationLabel);

        // Ensure the derived key is a valid secp256k1 private key (non-zero, < curve order)
        // If it happens to be invalid (astronomically unlikely), increment and retry
        if (!ECPrivKey.TryCreate(privateKeyBytes, out ECPrivKey? privKey))
        {
            // Extremely unlikely: derived key is zero or >= curve order
            // Try with a different label suffix as a fallback
            for (int i = 1; i <= 255; i++)
            {
                byte[] retryLabel = new byte[KeyDerivationLabel.Length + 1];
                Buffer.BlockCopy(KeyDerivationLabel, 0, retryLabel, 0, KeyDerivationLabel.Length);
                retryLabel[^1] = (byte)i;

                privateKeyBytes = HKDF.Expand(HashAlgorithmName.SHA256, exporterSecret, 32, retryLabel);
                if (ECPrivKey.TryCreate(privateKeyBytes, out privKey))
                    break;
            }

            if (privKey is null)
                throw new CryptographicException("Failed to derive a valid secp256k1 private key from the exporter secret.");
        }

        // Get the public key in x-only format (32 bytes)
        ECPubKey pubKey = privKey.CreatePubKey();
        ECXOnlyPubKey xOnlyPubKey = pubKey.ToXOnlyPubKey(out _);
        byte[] publicKeyBytes = new byte[32];
        xOnlyPubKey.WriteToSpan(publicKeyBytes);

        return (privateKeyBytes, publicKeyBytes);
    }
}
