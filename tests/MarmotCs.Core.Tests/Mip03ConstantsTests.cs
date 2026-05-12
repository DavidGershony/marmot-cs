using System.Security.Cryptography;
using MarmotCs.Protocol.Crypto;
using Xunit;

namespace MarmotCs.Core.Tests;

/// <summary>
/// Regression tests pinning MIP-03 §"Encryption Details" constants.
/// These verify that the encryption layer uses exactly the values the spec requires:
/// - MLS-Exporter("marmot", "group-event", 32)
/// - ChaCha20-Poly1305 with empty AAD
/// - Random 12-byte nonce per event
/// - Output format: base64(nonce || ciphertext_with_tag)
/// </summary>
[Trait("Category", "MIP-Compliance")]
[Trait("MIP", "MIP-03")]
public class Mip03ConstantsTests
{
    [Fact]
    public void ExporterLabel_Is_Marmot()
    {
        Assert.Equal("marmot", GroupEventEncryption.ExporterLabel);
    }

    [Fact]
    public void ExporterContext_Is_GroupEvent()
    {
        Assert.Equal("group-event"u8.ToArray(), GroupEventEncryption.ExporterContext);
    }

    [Fact]
    public void ExporterLength_Is_32()
    {
        Assert.Equal(32, GroupEventEncryption.ExporterLength);
    }

    [Fact]
    public void Encrypt_OutputFormat_IsBase64_Of_Nonce12_CiphertextWithTag()
    {
        GroupEventEncryption.ResetNonceTracker();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "test payload for format check"u8.ToArray();

        var encrypted = GroupEventEncryption.Encrypt(plaintext, key);

        // Output is base64
        var combined = Convert.FromBase64String(encrypted);

        // First 12 bytes = nonce, rest = ciphertext + 16-byte Poly1305 tag
        Assert.True(combined.Length >= 12 + 16 + 1,
            $"Expected at least 29 bytes (12 nonce + 16 tag + 1 ciphertext), got {combined.Length}");

        // Exact size: 12 (nonce) + plaintext.Length + 16 (tag)
        Assert.Equal(12 + plaintext.Length + 16, combined.Length);

        GroupEventEncryption.ResetNonceTracker();
    }

    [Fact]
    public void Encrypt_Nonce_Is_12Bytes_Random()
    {
        GroupEventEncryption.ResetNonceTracker();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "nonce size test"u8.ToArray();

        var encrypted1 = GroupEventEncryption.Encrypt(plaintext, key);
        var encrypted2 = GroupEventEncryption.Encrypt(plaintext, key);

        var nonce1 = Convert.FromBase64String(encrypted1)[..12];
        var nonce2 = Convert.FromBase64String(encrypted2)[..12];

        // Each nonce is 12 bytes
        Assert.Equal(12, nonce1.Length);
        Assert.Equal(12, nonce2.Length);

        // Nonces are different (random)
        Assert.False(nonce1.SequenceEqual(nonce2), "Two consecutive nonces should differ");

        GroupEventEncryption.ResetNonceTracker();
    }

    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        GroupEventEncryption.ResetNonceTracker();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "round trip test message"u8.ToArray();

        var encrypted = GroupEventEncryption.Encrypt(plaintext, key);
        var decrypted = GroupEventEncryption.Decrypt(encrypted, key);

        Assert.Equal(plaintext, decrypted);
        GroupEventEncryption.ResetNonceTracker();
    }

    [Fact]
    public void Decrypt_WrongKey_ThrowsCryptographicException()
    {
        GroupEventEncryption.ResetNonceTracker();
        var key1 = new byte[32];
        var key2 = new byte[32];
        RandomNumberGenerator.Fill(key1);
        RandomNumberGenerator.Fill(key2);

        var encrypted = GroupEventEncryption.Encrypt("secret"u8.ToArray(), key1);

        // Wrong key → AEAD authentication failure (MIP-03: "drop, don't expose plaintext")
        Assert.Throws<CryptographicException>(() => GroupEventEncryption.Decrypt(encrypted, key2));
        GroupEventEncryption.ResetNonceTracker();
    }

    [Fact]
    public void Decrypt_InvalidBase64_ThrowsCryptographicException()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        Assert.Throws<CryptographicException>(() => GroupEventEncryption.Decrypt("not-valid-base64!!!", key));
    }

    [Fact]
    public void Decrypt_TooShort_ThrowsCryptographicException()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        // 27 bytes = less than 12 (nonce) + 16 (tag) + 1 (ciphertext minimum)
        var tooShort = Convert.ToBase64String(new byte[27]);
        Assert.Throws<CryptographicException>(() => GroupEventEncryption.Decrypt(tooShort, key));
    }

    [Fact]
    public void Encrypt_KeyMustBe32Bytes()
    {
        Assert.Throws<ArgumentException>(() =>
            GroupEventEncryption.Encrypt("test"u8.ToArray(), new byte[16]));
        Assert.Throws<ArgumentException>(() =>
            GroupEventEncryption.Encrypt("test"u8.ToArray(), new byte[64]));
    }
}
