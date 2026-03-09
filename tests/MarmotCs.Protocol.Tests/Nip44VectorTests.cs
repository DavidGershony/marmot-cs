using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MarmotCs.Protocol.Nip44;
using Xunit;

namespace MarmotCs.Protocol.Tests;

/// <summary>
/// NIP-44 v2 compliance tests using official test vectors from
/// https://github.com/block-core/nostr-client/blob/master/nip44.vectors.json
/// </summary>
public class Nip44VectorTests
{
    private static readonly string VectorsPath =
        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "nip44.vectors.json");

    private static readonly Lazy<Nip44Vectors?> _vectors = new(LoadVectors);
    private static Nip44Vectors? Vectors => _vectors.Value;

    private static Nip44Vectors? LoadVectors()
    {
        if (!File.Exists(VectorsPath))
            return null;
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
        return JsonSerializer.Deserialize<Nip44Vectors>(
            File.ReadAllText(VectorsPath, Encoding.UTF8), options);
    }

    // ----------------------------------------------------------------
    // get_conversation_key – valid vectors
    // ----------------------------------------------------------------

    public static IEnumerable<object[]> ConversationKeyVectors() =>
        Vectors?.V2?.Valid?.GetConversationKey?
            .Select(v => new object[] { v.Sec1!, v.Pub2!, v.ConversationKey! })
        ?? [];

    [Theory]
    [MemberData(nameof(ConversationKeyVectors))]
    public void Valid_GetConversationKey_MatchesVector(
        string sec1Hex, string pub2Hex, string expectedConvKeyHex)
    {
        byte[] sec1 = Convert.FromHexString(sec1Hex);
        byte[] pub2 = Convert.FromHexString(pub2Hex);
        byte[] expectedConvKey = Convert.FromHexString(expectedConvKeyHex);

        byte[] actual = Nip44Encryption.DeriveConversationKey(sec1, pub2);

        Assert.Equal(expectedConvKey, actual);
    }

    // ----------------------------------------------------------------
    // get_message_keys – valid vectors
    // ----------------------------------------------------------------

    public static IEnumerable<object[]> MessageKeyVectors()
    {
        var mk = Vectors?.V2?.Valid?.GetMessageKeys;
        if (mk?.Keys == null) return [];
        return mk.Keys.Select(k => new object[]
        {
            mk.ConversationKey!, k.Nonce!, k.ChachaKey!, k.ChachaNonce!, k.HmacKey!
        });
    }

    [Theory]
    [MemberData(nameof(MessageKeyVectors))]
    public void Valid_GetMessageKeys_MatchesVector(
        string convKeyHex, string nonceHex,
        string expectedChachaKeyHex, string expectedChachaNonceHex, string expectedHmacKeyHex)
    {
        var keys = Nip44MessageKeys.Derive(
            Convert.FromHexString(convKeyHex),
            Convert.FromHexString(nonceHex));

        Assert.Equal(Convert.FromHexString(expectedChachaKeyHex), keys.EncryptionKey);
        Assert.Equal(Convert.FromHexString(expectedChachaNonceHex), keys.Nonce);
        Assert.Equal(Convert.FromHexString(expectedHmacKeyHex), keys.HmacKey);
    }

    // ----------------------------------------------------------------
    // calc_padded_len – valid vectors
    // ----------------------------------------------------------------

    public static IEnumerable<object[]> CalcPaddedLenVectors() =>
        Vectors?.V2?.Valid?.CalcPaddedLen?
            .Select(pair => new object[] { (int)pair[0], (int)pair[1] })
        ?? [];

    [Theory]
    [MemberData(nameof(CalcPaddedLenVectors))]
    public void Valid_CalcPaddedLen_MatchesVector(int inputLen, int expectedPaddedLen)
    {
        Assert.Equal(expectedPaddedLen, Nip44Encryption.CalcPaddedLength(inputLen));
    }

    // ----------------------------------------------------------------
    // encrypt_decrypt – decrypt known payload → expected plaintext
    // ----------------------------------------------------------------

    public static IEnumerable<object[]> DecryptVectors() =>
        Vectors?.V2?.Valid?.EncryptDecrypt?
            .Select(v => new object[] { v.ConversationKey!, v.Plaintext!, v.Payload! })
        ?? [];

    public static IEnumerable<object[]> EncryptWithNonceVectors() =>
        Vectors?.V2?.Valid?.EncryptDecrypt?
            .Select(v => new object[] { v.ConversationKey!, v.Nonce!, v.Plaintext!, v.Payload! })
        ?? [];

    [Theory]
    [MemberData(nameof(DecryptVectors))]
    public void Valid_Decrypt_WithKnownPayload_MatchesPlaintext(
        string convKeyHex, string expectedPlaintext, string payload)
    {
        string actual = Nip44Encryption.Decrypt(payload, Convert.FromHexString(convKeyHex));
        Assert.Equal(expectedPlaintext, actual);
    }

    // ----------------------------------------------------------------
    // encrypt_decrypt – re-encrypt with known nonce → expected payload
    // ----------------------------------------------------------------

    [Theory]
    [MemberData(nameof(EncryptWithNonceVectors))]
    public void Valid_EncryptWithKnownNonce_ProducesExpectedPayload(
        string convKeyHex, string nonceHex, string plaintext, string expectedPayload)
    {
        string actual = Nip44Encryption.EncryptWithNonce(
            Encoding.UTF8.GetBytes(plaintext),
            Convert.FromHexString(convKeyHex),
            Convert.FromHexString(nonceHex));

        Assert.Equal(expectedPayload, actual);
    }

    // ----------------------------------------------------------------
    // encrypt_decrypt_long_msg – SHA256 verification
    // ----------------------------------------------------------------

    public static IEnumerable<object[]> LongMsgVectors() =>
        Vectors?.V2?.Valid?.EncryptDecryptLongMsg?
            .Select(v => new object[]
            {
                v.ConversationKey!, v.Nonce!, v.Pattern!, v.Repeat,
                v.PlaintextSha256!, v.PayloadSha256!
            })
        ?? [];

    [Theory]
    [MemberData(nameof(LongMsgVectors))]
    public void Valid_LongMessage_PlaintextAndPayloadHashesMatch(
        string convKeyHex, string nonceHex, string pattern, int repeat,
        string expectedPlaintextSha256, string expectedPayloadSha256)
    {
        var sb = new StringBuilder(pattern.Length * repeat);
        for (int i = 0; i < repeat; i++) sb.Append(pattern);
        string plaintext = sb.ToString();

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        string actualPlaintextHash = Convert.ToHexString(SHA256.HashData(plaintextBytes)).ToLowerInvariant();
        Assert.Equal(expectedPlaintextSha256, actualPlaintextHash);

        string payload = Nip44Encryption.EncryptWithNonce(
            plaintextBytes,
            Convert.FromHexString(convKeyHex),
            Convert.FromHexString(nonceHex));
        // payload_sha256 is the SHA256 of the base64-encoded string (UTF-8 bytes), per the spec
        byte[] payloadStringBytes = Encoding.UTF8.GetBytes(payload);
        string actualPayloadHash = Convert.ToHexString(SHA256.HashData(payloadStringBytes)).ToLowerInvariant();
        Assert.Equal(expectedPayloadSha256, actualPayloadHash);
    }

    // ----------------------------------------------------------------
    // invalid – decrypt must throw
    // ----------------------------------------------------------------

    public static IEnumerable<object[]> InvalidDecryptVectors() =>
        Vectors?.V2?.Invalid?.Decrypt?
            .Select(v => new object[] { v.ConversationKey!, v.Payload! })
        ?? [];

    [Theory]
    [MemberData(nameof(InvalidDecryptVectors))]
    public void Invalid_Decrypt_ThrowsException(string convKeyHex, string payload)
    {
        byte[] convKey = Convert.FromHexString(convKeyHex);
        Assert.ThrowsAny<Exception>(() => Nip44Encryption.Decrypt(payload, convKey));
    }

    // ----------------------------------------------------------------
    // invalid – conversation key derivation must throw
    // ----------------------------------------------------------------

    public static IEnumerable<object[]> InvalidConversationKeyVectors() =>
        Vectors?.V2?.Invalid?.GetConversationKey?
            .Select(v => new object[] { v.Sec1!, v.Pub2! })
        ?? [];

    [Theory]
    [MemberData(nameof(InvalidConversationKeyVectors))]
    public void Invalid_GetConversationKey_ThrowsException(string sec1Hex, string pub2Hex)
    {
        byte[] sec1 = Convert.FromHexString(sec1Hex);
        byte[] pub2 = Convert.FromHexString(pub2Hex);
        Assert.ThrowsAny<Exception>(() => Nip44Encryption.DeriveConversationKey(sec1, pub2));
    }

    // ----------------------------------------------------------------
    // JSON deserialization DTOs (private nested)
    // ----------------------------------------------------------------

    private sealed class Nip44Vectors
    {
        public V2Data? V2 { get; set; }
    }

    private sealed class V2Data
    {
        public ValidTestCases? Valid { get; set; }
        public InvalidTestCases? Invalid { get; set; }
    }

    private sealed class ValidTestCases
    {
        public ConversationKeyVector[]? GetConversationKey { get; set; }
        public MessageKeysData? GetMessageKeys { get; set; }
        public long[][]? CalcPaddedLen { get; set; }
        public EncryptDecryptVector[]? EncryptDecrypt { get; set; }
        public LongMsgVector[]? EncryptDecryptLongMsg { get; set; }
    }

    private sealed class InvalidTestCases
    {
        public long[]? EncryptMsgLengths { get; set; }
        public ConversationKeyVector[]? GetConversationKey { get; set; }
        public DecryptVector[]? Decrypt { get; set; }
    }

    private sealed class ConversationKeyVector
    {
        public string? Sec1 { get; set; }
        public string? Pub2 { get; set; }
        public string? ConversationKey { get; set; }
        public string? Note { get; set; }
    }

    private sealed class MessageKeysData
    {
        public string? ConversationKey { get; set; }
        public MessageKeyEntry[]? Keys { get; set; }
    }

    private sealed class MessageKeyEntry
    {
        public string? Nonce { get; set; }
        public string? ChachaKey { get; set; }
        public string? ChachaNonce { get; set; }
        public string? HmacKey { get; set; }
    }

    private sealed class EncryptDecryptVector
    {
        public string? Sec1 { get; set; }
        public string? Sec2 { get; set; }
        public string? ConversationKey { get; set; }
        public string? Nonce { get; set; }
        public string? Plaintext { get; set; }
        public string? Payload { get; set; }
    }

    private sealed class LongMsgVector
    {
        public string? ConversationKey { get; set; }
        public string? Nonce { get; set; }
        public string? Pattern { get; set; }
        public int Repeat { get; set; }
        public string? PlaintextSha256 { get; set; }
        public string? PayloadSha256 { get; set; }
    }

    private sealed class DecryptVector
    {
        public string? ConversationKey { get; set; }
        public string? Nonce { get; set; }
        public string? Plaintext { get; set; }
        public string? Payload { get; set; }
        public string? Note { get; set; }
    }
}
