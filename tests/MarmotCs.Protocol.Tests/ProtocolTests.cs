using DotnetMls.Codec;
using DotnetMls.Types;
using MarmotCs.Protocol.Mip00;
using MarmotCs.Protocol.Mip01;
using MarmotCs.Protocol.Mip02;
using MarmotCs.Protocol.Mip03;
using MarmotCs.Protocol.Nip44;
using Xunit;

namespace MarmotCs.Protocol.Tests;

// ================================================================
// NIP-44 Tests
// ================================================================

public class Nip44EncryptionTests
{
    [Fact]
    public void EncryptDecrypt_WithConversationKey_RoundTrips()
    {
        // Use a known 32-byte conversation key (simulating the output of ECDH + HKDF)
        var conversationKey = new byte[32];
        conversationKey[0] = 0x42;
        conversationKey[31] = 0xFF;

        string plaintext = "Hello, NIP-44!";
        string encrypted = Nip44Encryption.Encrypt(plaintext, conversationKey);
        Assert.NotEqual(plaintext, encrypted);

        string decrypted = Nip44Encryption.Decrypt(encrypted, conversationKey);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_ProducesBase64Output()
    {
        var conversationKey = new byte[32];
        conversationKey[0] = 1;
        string encrypted = Nip44Encryption.Encrypt("test", conversationKey);

        // Should be valid base64
        byte[] decoded = Convert.FromBase64String(encrypted);
        Assert.True(decoded.Length > 0);
        // First byte should be version 0x02
        Assert.Equal(0x02, decoded[0]);
    }

    [Fact]
    public void Decrypt_WithWrongKey_ThrowsCryptographicException()
    {
        var key1 = new byte[32];
        key1[0] = 1;
        var key2 = new byte[32];
        key2[0] = 2;

        string encrypted = Nip44Encryption.Encrypt("secret", key1);
        Assert.ThrowsAny<Exception>(() => Nip44Encryption.Decrypt(encrypted, key2));
    }

    [Fact]
    public void Encrypt_DifferentCallsProduceDifferentCiphertexts()
    {
        var key = new byte[32];
        key[0] = 42;
        string pt = "same message";

        string ct1 = Nip44Encryption.Encrypt(pt, key);
        string ct2 = Nip44Encryption.Encrypt(pt, key);

        Assert.NotEqual(ct1, ct2); // random nonce each time
    }

    [Fact]
    public void EncryptDecrypt_UnicodeMessage_RoundTrips()
    {
        var key = new byte[32];
        key[0] = 0xAA;
        string plaintext = "Guten Tag! Kaffe kochen wir morgen.";

        string encrypted = Nip44Encryption.Encrypt(plaintext, key);
        string decrypted = Nip44Encryption.Decrypt(encrypted, key);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_LongMessage_RoundTrips()
    {
        var key = new byte[32];
        key[15] = 0xFF;
        string plaintext = new string('A', 5000);

        string encrypted = Nip44Encryption.Encrypt(plaintext, key);
        string decrypted = Nip44Encryption.Decrypt(encrypted, key);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_EmptyMessage_Throws()
    {
        var key = new byte[32];
        Assert.ThrowsAny<ArgumentException>(() => Nip44Encryption.Encrypt("", key));
    }

    [Fact]
    public void Encrypt_WrongKeyLength_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            Nip44Encryption.Encrypt("test", new byte[16]));
    }
}

public class Nip44PaddingTests
{
    [Theory]
    [InlineData(1, 34)]    // 1 byte => 2 (prefix) + 32 (padded) = 34
    [InlineData(10, 34)]   // 10 bytes => padded to 32 => total 34
    [InlineData(32, 34)]   // 32 bytes => padded to 32 => total 34
    public void PadMessage_ShortMessages_PaddedTo32(int msgLen, int expectedTotal)
    {
        var msg = new byte[msgLen];
        msg[0] = 0xFF;
        var padded = Nip44Encryption.PadMessage(msg);
        Assert.Equal(expectedTotal, padded.Length);

        // First two bytes encode the message length as big-endian uint16
        int encodedLen = (padded[0] << 8) | padded[1];
        Assert.Equal(msgLen, encodedLen);
    }

    [Fact]
    public void PadUnpad_RoundTrips()
    {
        var msg = "Hello padding!"u8.ToArray();
        var padded = Nip44Encryption.PadMessage(msg);
        var unpadded = Nip44Encryption.UnpadMessage(padded);
        Assert.Equal(msg, unpadded);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(64)]
    [InlineData(100)]
    [InlineData(256)]
    [InlineData(1000)]
    [InlineData(10000)]
    public void PadUnpad_VariousLengths_RoundTrips(int msgLen)
    {
        var msg = new byte[msgLen];
        new Random(msgLen).NextBytes(msg);
        var padded = Nip44Encryption.PadMessage(msg);
        var unpadded = Nip44Encryption.UnpadMessage(padded);
        Assert.Equal(msg, unpadded);
    }

    [Fact]
    public void PadMessage_ZeroLength_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            Nip44Encryption.PadMessage(Array.Empty<byte>()));
    }

    [Fact]
    public void UnpadMessage_TooShort_Throws()
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            Nip44Encryption.UnpadMessage(new byte[1]));
    }
}

public class Nip44MessageKeysTests
{
    [Fact]
    public void Derive_ProducesCorrectLengths()
    {
        var conversationKey = new byte[32];
        conversationKey[0] = 1;
        var nonce = new byte[32];
        nonce[0] = 2;

        var keys = Nip44MessageKeys.Derive(conversationKey, nonce);

        Assert.Equal(32, keys.EncryptionKey.Length);
        Assert.Equal(12, keys.Nonce.Length);
        Assert.Equal(32, keys.HmacKey.Length);
    }

    [Fact]
    public void Derive_IsDeterministic()
    {
        var ck = new byte[32];
        ck[0] = 0xAA;
        var nonce = new byte[32];
        nonce[0] = 0xBB;

        var keys1 = Nip44MessageKeys.Derive(ck, nonce);
        var keys2 = Nip44MessageKeys.Derive(ck, nonce);

        Assert.Equal(keys1.EncryptionKey, keys2.EncryptionKey);
        Assert.Equal(keys1.Nonce, keys2.Nonce);
        Assert.Equal(keys1.HmacKey, keys2.HmacKey);
    }

    [Fact]
    public void Derive_DifferentNonces_ProduceDifferentKeys()
    {
        var ck = new byte[32];
        var n1 = new byte[32]; n1[0] = 1;
        var n2 = new byte[32]; n2[0] = 2;

        var k1 = Nip44MessageKeys.Derive(ck, n1);
        var k2 = Nip44MessageKeys.Derive(ck, n2);

        Assert.NotEqual(k1.EncryptionKey, k2.EncryptionKey);
    }

    [Fact]
    public void Derive_WrongConversationKeyLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            Nip44MessageKeys.Derive(new byte[16], new byte[32]));
    }

    [Fact]
    public void Derive_WrongNonceLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            Nip44MessageKeys.Derive(new byte[32], new byte[16]));
    }
}

// ================================================================
// MIP-00 Tests (Key Package Events)
// ================================================================

public class Mip00Tests
{
    [Fact]
    public void BuildAndParseKeyPackageEvent_RoundTrips()
    {
        byte[] kpBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        string identity = "abcdef1234567890";
        string[] relays = new[] { "wss://relay1.example.com", "wss://relay2.example.com" };

        var (content, tags) = KeyPackageEventBuilder.BuildKeyPackageEvent(kpBytes, identity, relays);

        Assert.NotEmpty(content);
        Assert.NotEmpty(tags);

        // Parse it back
        var (parsedBytes, parsedKpRef, parsedRelays) =
            KeyPackageEventParser.ParseKeyPackageEvent(content, tags);

        Assert.Equal(kpBytes, parsedBytes);
        // The i tag now contains the KeyPackageRef hash, not the identity
        Assert.NotEmpty(parsedKpRef);
        Assert.Equal(relays, parsedRelays);
    }

    [Fact]
    public void Build_ITagContainsKeyPackageRef()
    {
        byte[] kpBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var (_, tags) = KeyPackageEventBuilder.BuildKeyPackageEvent(kpBytes, "abc123", Array.Empty<string>());

        var iTag = tags.First(t => t[0] == "i");
        // Must be exactly 2 elements: ["i", "<hex>"]
        Assert.Equal(2, iTag.Length);
        // Value must be valid hex
        Assert.NotEmpty(iTag[1]);
        Convert.FromHexString(iTag[1]);
    }

    [Fact]
    public void Build_ContainsRequiredTags()
    {
        var (_, tags) = KeyPackageEventBuilder.BuildKeyPackageEvent(
            new byte[] { 1 }, "abc123", new[] { "wss://relay.test" });

        var tagNames = tags.Select(t => t[0]).ToList();
        Assert.Contains("encoding", tagNames);
        Assert.Contains("protocol_version", tagNames);
        Assert.Contains("ciphersuite", tagNames);
        Assert.Contains("relays", tagNames);
        Assert.Contains("i", tagNames);
    }

    [Fact]
    public void Build_EncodingTagIsMlsBase64()
    {
        var (_, tags) = KeyPackageEventBuilder.BuildKeyPackageEvent(
            new byte[] { 1 }, "abc123", Array.Empty<string>());

        var encodingTag = tags.First(t => t[0] == "encoding");
        Assert.Equal("mls-base64", encodingTag[1]);
    }

    [Fact]
    public void Parse_MissingEncoding_Throws()
    {
        string content = Convert.ToBase64String(new byte[] { 1, 2, 3 });
        string[][] tags = new[]
        {
            new[] { "i", "abcdef01" }
        };

        Assert.Throws<FormatException>(() =>
            KeyPackageEventParser.ParseKeyPackageEvent(content, tags));
    }

    [Fact]
    public void Parse_MissingITag_Throws()
    {
        string content = Convert.ToBase64String(new byte[] { 1 });
        string[][] tags = new[]
        {
            new[] { "encoding", "mls-base64" }
        };

        Assert.Throws<FormatException>(() =>
            KeyPackageEventParser.ParseKeyPackageEvent(content, tags));
    }

    [Fact]
    public void Build_EmptyKpBytes_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            KeyPackageEventBuilder.BuildKeyPackageEvent(Array.Empty<byte>(), "abc", Array.Empty<string>()));
    }

    [Fact]
    public void Build_EmptyIdentity_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            KeyPackageEventBuilder.BuildKeyPackageEvent(new byte[] { 1 }, "", Array.Empty<string>()));
    }

    [Fact]
    public void Build_NoRelays_ParsesWithEmptyRelays()
    {
        var (content, tags) = KeyPackageEventBuilder.BuildKeyPackageEvent(
            new byte[] { 1, 2 }, "identity123", Array.Empty<string>());
        var (_, _, relays) = KeyPackageEventParser.ParseKeyPackageEvent(content, tags);
        Assert.Empty(relays);
    }
}

// ================================================================
// MIP-01 Tests (NostrGroupData)
// ================================================================

public class Mip01Tests
{
    [Fact]
    public void NostrGroupDataCodec_EncodeDecodeRoundTrips()
    {
        var data = new NostrGroupData
        {
            Name = "Test Group",
            Description = "A test group for unit tests",
            AdminPubkeys = new byte[64], // 2 admin pubkeys
            Relays = new[] { "wss://relay1.test", "wss://relay2.test" },
            Version = 2
        };
        data.AdminPubkeys[0] = 0xAA;
        data.AdminPubkeys[32] = 0xBB;

        byte[] encoded = NostrGroupDataCodec.Encode(data);
        Assert.NotEmpty(encoded);

        var decoded = NostrGroupDataCodec.Decode(encoded);
        Assert.Equal(data.Name, decoded.Name);
        Assert.Equal(data.Description, decoded.Description);
        Assert.Equal(data.AdminPubkeys, decoded.AdminPubkeys);
        Assert.Equal(data.Relays, decoded.Relays);
        Assert.Equal(2, decoded.Version);
    }

    [Fact]
    public void NostrGroupDataCodec_EmptyFields_RoundTrips()
    {
        var data = new NostrGroupData
        {
            Name = "",
            Description = "",
            AdminPubkeys = Array.Empty<byte>(),
            Relays = Array.Empty<string>(),
            Version = 2
        };

        byte[] encoded = NostrGroupDataCodec.Encode(data);
        var decoded = NostrGroupDataCodec.Decode(encoded);

        Assert.Equal("", decoded.Name);
        Assert.Equal("", decoded.Description);
        Assert.Empty(decoded.AdminPubkeys);
        Assert.Empty(decoded.Relays);
    }

    [Fact]
    public void NostrGroupDataCodec_InvalidAdminPubkeysLength_Throws()
    {
        var data = new NostrGroupData
        {
            AdminPubkeys = new byte[33] // Not a multiple of 32
        };

        Assert.Throws<ArgumentException>(() => NostrGroupDataCodec.Encode(data));
    }

    [Fact]
    public void NostrGroupDataExtension_ToFromExtension_RoundTrips()
    {
        var data = new NostrGroupData
        {
            Name = "My Group",
            Description = "Description",
            AdminPubkeys = new byte[32],
            Relays = new[] { "wss://relay.test" },
            Version = 2
        };

        Extension ext = NostrGroupDataExtension.ToExtension(data);
        Assert.Equal(0xF2EE, ext.ExtensionType);

        NostrGroupData decoded = NostrGroupDataExtension.FromExtension(ext);
        Assert.Equal("My Group", decoded.Name);
        Assert.Equal("Description", decoded.Description);
    }

    [Fact]
    public void NostrGroupDataExtension_WrongExtensionType_Throws()
    {
        var ext = new Extension(0x1234, new byte[] { 1, 2, 3 });
        Assert.Throws<ArgumentException>(() => NostrGroupDataExtension.FromExtension(ext));
    }

    [Fact]
    public void NostrGroupDataCodec_WrongVersion_ThrowsOnDecode()
    {
        // Encode version as 1 (unsupported)
        var encoded = TlsCodec.Serialize(w =>
        {
            QuicVarint.Write(w, 1); // version 1
        });

        Assert.Throws<FormatException>(() => NostrGroupDataCodec.Decode(encoded));
    }

    [Fact]
    public void NostrGroupDataCodec_UnicodeNameDescription_RoundTrips()
    {
        var data = new NostrGroupData
        {
            Name = "Gruppe Eins",
            Description = "Beschreibung fuer die Testgruppe",
            Relays = Array.Empty<string>(),
            Version = 2
        };

        byte[] encoded = NostrGroupDataCodec.Encode(data);
        var decoded = NostrGroupDataCodec.Decode(encoded);
        Assert.Equal(data.Name, decoded.Name);
        Assert.Equal(data.Description, decoded.Description);
    }
}

// ================================================================
// MIP-02 Tests (Welcome Events)
// ================================================================

public class Mip02Tests
{
    [Fact]
    public void BuildAndParseWelcomeEvent_RoundTrips()
    {
        byte[] welcomeBytes = new byte[] { 10, 20, 30, 40, 50 };
        string kpEventId = "abc123def456";
        string[] relays = new[] { "wss://relay.example.com" };

        var (content, tags) = WelcomeEventBuilder.BuildWelcomeEvent(
            welcomeBytes, kpEventId, relays);

        var (parsedWelcome, parsedKpId, parsedRelays) =
            WelcomeEventParser.ParseWelcomeEvent(content, tags);

        Assert.Equal(welcomeBytes, parsedWelcome);
        Assert.Equal(kpEventId, parsedKpId);
        Assert.Equal(relays, parsedRelays);
    }

    [Fact]
    public void Build_ContainsETag()
    {
        var (_, tags) = WelcomeEventBuilder.BuildWelcomeEvent(
            new byte[] { 1 }, "event123", Array.Empty<string>());

        var eTag = tags.First(t => t[0] == "e");
        Assert.Equal("event123", eTag[1]);
    }

    [Fact]
    public void Build_ContainsEncodingTag()
    {
        var (_, tags) = WelcomeEventBuilder.BuildWelcomeEvent(
            new byte[] { 1 }, "event123", Array.Empty<string>());

        var encoding = tags.First(t => t[0] == "encoding");
        Assert.Equal("mls-base64", encoding[1]);
    }

    [Fact]
    public void Build_EmptyWelcomeBytes_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            WelcomeEventBuilder.BuildWelcomeEvent(Array.Empty<byte>(), "abc", Array.Empty<string>()));
    }

    [Fact]
    public void Build_EmptyEventId_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            WelcomeEventBuilder.BuildWelcomeEvent(new byte[] { 1 }, "", Array.Empty<string>()));
    }

    [Fact]
    public void Parse_MissingETag_Throws()
    {
        string content = Convert.ToBase64String(new byte[] { 1, 2, 3 });
        string[][] tags = new[]
        {
            new[] { "encoding", "mls-base64" }
        };

        Assert.Throws<FormatException>(() =>
            WelcomeEventParser.ParseWelcomeEvent(content, tags));
    }
}

// ================================================================
// MIP-03 Tests (CommitRaceResolver)
// ================================================================

public class CommitRaceResolverTests
{
    [Fact]
    public void SingleCommit_ReturnsIt()
    {
        var commits = new[]
        {
            ("abc123", DateTimeOffset.UtcNow)
        };

        Assert.Equal("abc123", CommitRaceResolver.ResolveWinner(commits));
    }

    [Fact]
    public void EarliestTimestamp_Wins()
    {
        var now = DateTimeOffset.UtcNow;
        var commits = new[]
        {
            ("later_id", now.AddSeconds(10)),
            ("earlier_id", now),
            ("latest_id", now.AddSeconds(20))
        };

        Assert.Equal("earlier_id", CommitRaceResolver.ResolveWinner(commits));
    }

    [Fact]
    public void SameTimestamp_SmallestEventId_Wins()
    {
        var now = DateTimeOffset.UtcNow;
        var commits = new[]
        {
            ("fff", now),
            ("aaa", now),
            ("ccc", now)
        };

        Assert.Equal("aaa", CommitRaceResolver.ResolveWinner(commits));
    }

    [Fact]
    public void SameTimestamp_CaseInsensitiveComparison()
    {
        var now = DateTimeOffset.UtcNow;
        var commits = new[]
        {
            ("BBB", now),
            ("aaa", now)
        };

        // 'aaa' < 'BBB' case-insensitively
        Assert.Equal("aaa", CommitRaceResolver.ResolveWinner(commits));
    }

    [Fact]
    public void EmptyArray_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            CommitRaceResolver.ResolveWinner(Array.Empty<(string, DateTimeOffset)>()));
    }

    [Fact]
    public void NullArray_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            CommitRaceResolver.ResolveWinner(null!));
    }

    [Fact]
    public void MixedTimestamps_CorrectWinner()
    {
        var baseTime = DateTimeOffset.UtcNow;
        var commits = new[]
        {
            ("event3", baseTime.AddSeconds(1)),
            ("event1", baseTime),
            ("event2", baseTime),          // same time as event1
            ("event4", baseTime.AddSeconds(2))
        };

        // event1 and event2 tie on time; event1 < event2 lexicographically
        Assert.Equal("event1", CommitRaceResolver.ResolveWinner(commits));
    }
}
