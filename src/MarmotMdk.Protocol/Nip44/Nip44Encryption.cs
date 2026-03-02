using System.Security.Cryptography;
using System.Text;
using NBitcoin.Secp256k1;
using Org.BouncyCastle.Crypto.Parameters;
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace MarmotMdk.Protocol.Nip44;

/// <summary>
/// NIP-44 v2 encryption/decryption using secp256k1 ECDH + HKDF + ChaCha20-Poly1305.
/// </summary>
/// <remarks>
/// Protocol steps:
/// <list type="number">
///   <item>Conversation key: HKDF-Extract(salt="nip44-v2", ikm=shared_x) where shared_x is the
///         32-byte x-coordinate from secp256k1 ECDH.</item>
///   <item>Per-message: nonce = random 32 bytes; message_keys = HKDF-Expand(conversation_key, nonce, 76).</item>
///   <item>Encrypt: ChaCha20-Poly1305(key=encryption_key, nonce=chacha_nonce, aad=empty, plaintext=padded_message).</item>
///   <item>MAC: HMAC-SHA256(hmac_key, nonce || ciphertext).</item>
///   <item>Result: base64(0x02 || nonce || ciphertext || mac).</item>
/// </list>
/// </remarks>
public static class Nip44Encryption
{
    private const byte Version = 0x02;
    private static readonly byte[] HkdfSalt = Encoding.UTF8.GetBytes("nip44-v2");

    /// <summary>
    /// Derives a 32-byte NIP-44 conversation key from a private key and a public key using secp256k1 ECDH.
    /// </summary>
    /// <param name="privateKey">32-byte secp256k1 private key.</param>
    /// <param name="publicKey">32-byte x-only or 33-byte compressed secp256k1 public key.</param>
    /// <returns>32-byte conversation key.</returns>
    /// <exception cref="ArgumentException">Thrown when key lengths are invalid.</exception>
    public static byte[] DeriveConversationKey(byte[] privateKey, byte[] publicKey)
    {
        if (privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes.", nameof(privateKey));
        if (publicKey.Length != 32 && publicKey.Length != 33)
            throw new ArgumentException("Public key must be 32 bytes (x-only) or 33 bytes (compressed).", nameof(publicKey));

        ECPrivKey privKey = ECPrivKey.Create(privateKey);

        ECPubKey pubKey;
        if (publicKey.Length == 32)
        {
            // x-only pubkey: prefix with 0x02 to create compressed format (even parity)
            byte[] compressed = new byte[33];
            compressed[0] = 0x02;
            Buffer.BlockCopy(publicKey, 0, compressed, 1, 32);
            pubKey = ECPubKey.Create(compressed);
        }
        else
        {
            pubKey = ECPubKey.Create(publicKey);
        }

        // ECDH: multiply pubKey by privKey scalar, get shared point
        ECPubKey sharedPoint = pubKey.GetSharedPubkey(privKey);

        // Extract x-coordinate (32 bytes) from the shared point
        // WriteToSpan produces compressed format: [prefix_byte | 32_bytes_x]
        Span<byte> sharedCompressed = stackalloc byte[33];
        sharedPoint.WriteToSpan(true, sharedCompressed, out _);
        byte[] sharedX = sharedCompressed.Slice(1, 32).ToArray();

        // conversation_key = HKDF-Extract(salt="nip44-v2", ikm=shared_x)
        byte[] conversationKey = HKDF.Extract(HashAlgorithmName.SHA256, sharedX, HkdfSalt);
        return conversationKey;
    }

    /// <summary>
    /// Encrypts a plaintext string using NIP-44 v2 with the given conversation key.
    /// </summary>
    /// <param name="plaintext">The message to encrypt.</param>
    /// <param name="conversationKey">32-byte conversation key derived from ECDH.</param>
    /// <returns>Base64-encoded NIP-44 payload.</returns>
    /// <exception cref="ArgumentException">Thrown when conversation key length is invalid.</exception>
    /// <exception cref="ArgumentNullException">Thrown when plaintext is null.</exception>
    public static string Encrypt(string plaintext, byte[] conversationKey)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if (conversationKey.Length != 32)
            throw new ArgumentException("Conversation key must be 32 bytes.", nameof(conversationKey));

        byte[] messageBytes = Encoding.UTF8.GetBytes(plaintext);
        if (messageBytes.Length == 0 || messageBytes.Length > 65535)
            throw new ArgumentException("Plaintext must be between 1 and 65535 bytes when UTF-8 encoded.", nameof(plaintext));

        // Generate random 32-byte nonce
        byte[] nonce = RandomNumberGenerator.GetBytes(32);

        return EncryptWithNonce(messageBytes, conversationKey, nonce);
    }

    /// <summary>
    /// Decrypts a NIP-44 v2 payload using the given conversation key.
    /// </summary>
    /// <param name="payload">Base64-encoded NIP-44 payload.</param>
    /// <param name="conversationKey">32-byte conversation key derived from ECDH.</param>
    /// <returns>The decrypted plaintext string.</returns>
    /// <exception cref="ArgumentException">Thrown when conversation key length is invalid or payload is malformed.</exception>
    /// <exception cref="CryptographicException">Thrown when MAC verification or decryption fails.</exception>
    public static string Decrypt(string payload, byte[] conversationKey)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (conversationKey.Length != 32)
            throw new ArgumentException("Conversation key must be 32 bytes.", nameof(conversationKey));

        byte[] data = Convert.FromBase64String(payload);

        // Minimum: 1 (version) + 32 (nonce) + 16 (min ciphertext with poly1305 tag for 32 bytes padded = 32+16=48) + 32 (mac)
        // Actually min padded size is 32 bytes, so ciphertext = 32 + 16 (tag) = 48
        if (data.Length < 1 + 32 + 48 + 32)
            throw new ArgumentException("Payload too short.", nameof(payload));

        // Check version
        if (data[0] != Version)
            throw new ArgumentException($"Unsupported NIP-44 version: {data[0]}.", nameof(payload));

        // Parse: version(1) || nonce(32) || ciphertext(variable) || mac(32)
        byte[] nonce = new byte[32];
        Buffer.BlockCopy(data, 1, nonce, 0, 32);

        int ciphertextLength = data.Length - 1 - 32 - 32;
        byte[] ciphertext = new byte[ciphertextLength];
        Buffer.BlockCopy(data, 33, ciphertext, 0, ciphertextLength);

        byte[] mac = new byte[32];
        Buffer.BlockCopy(data, data.Length - 32, mac, 0, 32);

        // Derive message keys
        Nip44MessageKeys keys = Nip44MessageKeys.Derive(conversationKey, nonce);

        // Verify MAC: HMAC-SHA256(hmac_key, nonce || ciphertext)
        byte[] expectedMac = ComputeMac(keys.HmacKey, nonce, ciphertext);
        if (!CryptographicOperations.FixedTimeEquals(mac, expectedMac))
            throw new CryptographicException("NIP-44 MAC verification failed.");

        // Decrypt with ChaCha20-Poly1305
        byte[] padded = ChaCha20Poly1305Decrypt(keys.EncryptionKey, keys.Nonce, ciphertext);

        // Unpad
        byte[] messageBytes = UnpadMessage(padded);
        return Encoding.UTF8.GetString(messageBytes);
    }

    /// <summary>
    /// Pads a message according to NIP-44 padding scheme.
    /// The padded output is: uint16BE(message.Length) || message || zero_padding.
    /// Total padded size is at least 32 and rounds up to the next power of 2 when needed.
    /// </summary>
    internal static byte[] PadMessage(byte[] message)
    {
        int msgLen = message.Length;
        if (msgLen < 1 || msgLen > 65535)
            throw new ArgumentException("Message length must be between 1 and 65535.", nameof(message));

        int paddedLen = CalcPaddedLength(msgLen);
        byte[] padded = new byte[2 + paddedLen];

        // Write message length as uint16 big-endian
        padded[0] = (byte)(msgLen >> 8);
        padded[1] = (byte)(msgLen & 0xFF);

        // Copy message
        Buffer.BlockCopy(message, 0, padded, 2, msgLen);

        // Remaining bytes are already zero
        return padded;
    }

    /// <summary>
    /// Removes NIP-44 padding and returns the original message bytes.
    /// </summary>
    internal static byte[] UnpadMessage(byte[] padded)
    {
        if (padded.Length < 2)
            throw new ArgumentException("Padded data too short.", nameof(padded));

        // Read message length from uint16 big-endian prefix
        int msgLen = (padded[0] << 8) | padded[1];

        if (msgLen < 1 || msgLen > padded.Length - 2)
            throw new ArgumentException("Invalid padding: message length out of range.", nameof(padded));

        int expectedPaddedLen = CalcPaddedLength(msgLen);
        if (padded.Length != 2 + expectedPaddedLen)
            throw new ArgumentException("Invalid padding: unexpected padded length.", nameof(padded));

        byte[] message = new byte[msgLen];
        Buffer.BlockCopy(padded, 2, message, 0, msgLen);
        return message;
    }

    private static string EncryptWithNonce(byte[] messageBytes, byte[] conversationKey, byte[] nonce)
    {
        // Derive message keys
        Nip44MessageKeys keys = Nip44MessageKeys.Derive(conversationKey, nonce);

        // Pad the message
        byte[] padded = PadMessage(messageBytes);

        // Encrypt with ChaCha20-Poly1305
        byte[] ciphertext = ChaCha20Poly1305Encrypt(keys.EncryptionKey, keys.Nonce, padded);

        // MAC: HMAC-SHA256(hmac_key, nonce || ciphertext)
        byte[] mac = ComputeMac(keys.HmacKey, nonce, ciphertext);

        // Assemble: version || nonce || ciphertext || mac
        byte[] result = new byte[1 + 32 + ciphertext.Length + 32];
        result[0] = Version;
        Buffer.BlockCopy(nonce, 0, result, 1, 32);
        Buffer.BlockCopy(ciphertext, 0, result, 33, ciphertext.Length);
        Buffer.BlockCopy(mac, 0, result, 33 + ciphertext.Length, 32);

        return Convert.ToBase64String(result);
    }

    private static byte[] ComputeMac(byte[] hmacKey, byte[] nonce, byte[] ciphertext)
    {
        using var hmac = new System.Security.Cryptography.HMACSHA256(hmacKey);
        hmac.TransformBlock(nonce, 0, nonce.Length, null, 0);
        hmac.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        return hmac.Hash!;
    }

    private static byte[] ChaCha20Poly1305Encrypt(byte[] key, byte[] nonce, byte[] plaintext)
    {
        var cipher = new BcChaCha20Poly1305();
        var parameters = new AeadParameters(
            new KeyParameter(key),
            128, // tag size in bits
            nonce,
            Array.Empty<byte>() // no AAD
        );

        cipher.Init(true, parameters);
        byte[] output = new byte[cipher.GetOutputSize(plaintext.Length)];
        int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        len += cipher.DoFinal(output, len);

        // Output contains ciphertext + 16-byte tag
        byte[] result = new byte[len];
        Buffer.BlockCopy(output, 0, result, 0, len);
        return result;
    }

    private static byte[] ChaCha20Poly1305Decrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag)
    {
        var cipher = new BcChaCha20Poly1305();
        var parameters = new AeadParameters(
            new KeyParameter(key),
            128, // tag size in bits
            nonce,
            Array.Empty<byte>() // no AAD
        );

        cipher.Init(false, parameters);
        byte[] output = new byte[cipher.GetOutputSize(ciphertextWithTag.Length)];
        int len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, output, 0);
        len += cipher.DoFinal(output, len);

        byte[] result = new byte[len];
        Buffer.BlockCopy(output, 0, result, 0, len);
        return result;
    }

    /// <summary>
    /// Calculates the NIP-44 padded length for a given message length (excluding the 2-byte length prefix).
    /// If msgLen &lt;= 32: padded to 32.
    /// Otherwise: padded to next power of 2 relative to (msgLen - 1), with a minimum chunk size.
    /// </summary>
    private static int CalcPaddedLength(int msgLen)
    {
        if (msgLen <= 32)
            return 32;

        // Find the next power of 2 >= msgLen
        int nextPow2 = 1;
        while (nextPow2 < msgLen)
            nextPow2 <<= 1;

        // NIP-44 padding: divide into chunks based on the power of 2
        // chunk = max(32, nextPow2 / 8)
        int chunk = Math.Max(32, nextPow2 / 8);

        // Round up msgLen to the next multiple of chunk
        return chunk * ((msgLen - 1) / chunk + 1);
    }
}
