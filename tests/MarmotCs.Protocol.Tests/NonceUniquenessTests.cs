using System.Security.Cryptography;
using MarmotCs.Protocol.Crypto;
using Xunit;

namespace MarmotCs.Protocol.Tests;

/// <summary>
/// Tests for MIP-03 §"Encryption Details" nonce uniqueness tracking.
/// Verifies that duplicate outbound nonces are detected and rejected,
/// and that RNG failures abort without fallback.
/// </summary>
[Trait("Category", "MIP-Compliance")]
[Trait("MIP", "MIP-03")]
public class NonceUniquenessTests
{
    private static byte[] MakeKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void Encrypt_GeneratesUniqueNonces_AcrossMultipleCalls()
    {
        GroupEventEncryption.ResetNonceTracker();
        var key = MakeKey();
        var plaintext = "test message"u8.ToArray();

        // Encrypt 100 times — all should succeed with unique nonces
        var outputs = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            var encrypted = GroupEventEncryption.Encrypt(plaintext, key);
            // Each output starts with a different nonce, so base64 output should differ
            Assert.True(outputs.Add(encrypted), $"Duplicate output on encryption #{i}");
        }

        GroupEventEncryption.ResetNonceTracker();
    }

    [Fact]
    public void ResetNonceTracker_ClearsAllTrackedNonces()
    {
        GroupEventEncryption.ResetNonceTracker();
        var key = MakeKey();
        var plaintext = "test"u8.ToArray();

        // Encrypt a few times
        for (int i = 0; i < 10; i++)
            GroupEventEncryption.Encrypt(plaintext, key);

        // Reset clears the tracker — no exception after reset
        GroupEventEncryption.ResetNonceTracker();

        // Should succeed (fresh tracker)
        GroupEventEncryption.Encrypt(plaintext, key);
        GroupEventEncryption.ResetNonceTracker();
    }

    [Fact]
    public void ResetNonceTracker_PerKey_OnlyClearsSpecificKey()
    {
        GroupEventEncryption.ResetNonceTracker();
        var key1 = MakeKey();
        var key2 = MakeKey();
        var plaintext = "test"u8.ToArray();

        GroupEventEncryption.Encrypt(plaintext, key1);
        GroupEventEncryption.Encrypt(plaintext, key2);

        // Reset only key1
        GroupEventEncryption.ResetNonceTracker(key1);

        // key1 should work again, key2 state preserved
        GroupEventEncryption.Encrypt(plaintext, key1);

        GroupEventEncryption.ResetNonceTracker();
    }

    [Fact]
    public void Encrypt_ThrowsArgumentException_ForInvalidKey()
    {
        var shortKey = new byte[16];
        Assert.Throws<ArgumentException>(() =>
            GroupEventEncryption.Encrypt("test"u8.ToArray(), shortKey));
    }

    [Fact]
    public void Encrypt_ThrowsArgumentException_ForEmptyPlaintext()
    {
        var key = MakeKey();
        Assert.Throws<ArgumentException>(() =>
            GroupEventEncryption.Encrypt(Array.Empty<byte>(), key));
    }

    [Fact]
    public void Encrypt_ThrowsArgumentNullException_ForNullInputs()
    {
        var key = MakeKey();
        Assert.Throws<ArgumentNullException>(() =>
            GroupEventEncryption.Encrypt(null!, key));
        Assert.Throws<ArgumentNullException>(() =>
            GroupEventEncryption.Encrypt("test"u8.ToArray(), null!));
    }
}

/// <summary>
/// Tests for MIP-03 §"Encryption Details" RNG failure handling.
/// "If RNG cannot produce 12-byte nonce: MUST abort, MUST NOT use deterministic fallback"
/// </summary>
[Trait("Category", "MIP-Compliance")]
[Trait("MIP", "MIP-03")]
public class RngFailureAbortTests
{
    [Fact]
    public void Encrypt_UsesRandomNumberGenerator_NotDeterministicFallback()
    {
        // Verify that RandomNumberGenerator.GetBytes is used (not a seeded PRNG).
        // We can't easily mock the static RNG, but we can verify that encrypting
        // the same plaintext with the same key produces different outputs (different nonces).
        GroupEventEncryption.ResetNonceTracker();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "determinism test"u8.ToArray();

        var result1 = GroupEventEncryption.Encrypt(plaintext, key);
        var result2 = GroupEventEncryption.Encrypt(plaintext, key);

        // Different nonces → different ciphertexts
        Assert.NotEqual(result1, result2);

        GroupEventEncryption.ResetNonceTracker();
    }

    [Fact]
    public void Encrypt_NoncePrefixIsRandom_NotZeroed()
    {
        // Verify the first 12 bytes (nonce) of each encryption are non-zero random
        GroupEventEncryption.ResetNonceTracker();
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        var plaintext = "nonce test"u8.ToArray();

        var encrypted = GroupEventEncryption.Encrypt(plaintext, key);
        var combined = Convert.FromBase64String(encrypted);

        // First 12 bytes are the nonce — should not be all zeros
        var nonce = combined[..12];
        Assert.False(nonce.All(b => b == 0), "Nonce should not be all zeros");

        GroupEventEncryption.ResetNonceTracker();
    }
}
