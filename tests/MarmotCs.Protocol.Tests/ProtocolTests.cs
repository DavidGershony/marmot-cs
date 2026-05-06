using DotnetMls.Codec;
using DotnetMls.Types;
using MarmotCs.Protocol.Mip00;
using MarmotCs.Protocol.Mip01;
using MarmotCs.Protocol.Mip02;
using MarmotCs.Protocol.Mip03;
using MarmotCs.Protocol.Crypto;
using MarmotCs.Protocol.Nip44;
using MarmotCs.Protocol.Nip59;
using NBitcoin.Secp256k1;
using Xunit;

namespace MarmotCs.Protocol.Tests;

// ================================================================
// NIP-44 Tests
// ================================================================

[Trait("Category", "HkdfLinuxRegression")]
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

[Trait("Category", "HkdfLinuxRegression")]
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
        Assert.Contains("mls_protocol_version", tagNames);
        Assert.Contains("mls_ciphersuite", tagNames);
        Assert.Contains("mls_extensions", tagNames);
        Assert.Contains("relays", tagNames);
        Assert.Contains("i", tagNames);
    }

    [Fact]
    public void Build_EncodingTagIsBase64()
    {
        var (_, tags) = KeyPackageEventBuilder.BuildKeyPackageEvent(
            new byte[] { 1 }, "abc123", Array.Empty<string>());

        var encodingTag = tags.First(t => t[0] == "encoding");
        Assert.Equal("base64", encodingTag[1]);
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
            new[] { "encoding", "base64" }
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

    [Fact]
    public void Parse_WrongEncoding_Throws()
    {
        string content = Convert.ToBase64String(new byte[] { 1, 2, 3 });
        string[][] tags = new[]
        {
            new[] { "encoding", "hex" },
            new[] { "i", "abcdef01" }
        };

        var ex = Assert.Throws<FormatException>(() =>
            KeyPackageEventParser.ParseKeyPackageEvent(content, tags));
        Assert.Contains("hex", ex.Message);
    }

    [Fact]
    public void Build_TagValuesAreCorrect()
    {
        var (_, tags) = KeyPackageEventBuilder.BuildKeyPackageEvent(
            new byte[] { 1 }, "abc123", new[] { "wss://relay.test" });

        var protoTag = tags.First(t => t[0] == "mls_protocol_version");
        Assert.Equal("1.0", protoTag[1]);

        var csTag = tags.First(t => t[0] == "mls_ciphersuite");
        Assert.Equal("0x0001", csTag[1]);
    }

    [Fact]
    public void Build_WithExtensionTypes_ContainsHexValues()
    {
        var (_, tags) = KeyPackageEventBuilder.BuildKeyPackageEvent(
            new byte[] { 1 }, "abc123", Array.Empty<string>(),
            supportedExtensionTypes: new ushort[] { 0xF2EE, 0x000A });

        var extTag = tags.First(t => t[0] == "mls_extensions");
        Assert.Equal(3, extTag.Length); // "mls_extensions", "0xf2ee", "0x000a"
        Assert.Equal("0xf2ee", extTag[1]);
        Assert.Equal("0x000a", extTag[2]);
    }

    [Fact]
    public void Build_KeyPackageRefIsLowercaseHex()
    {
        var (_, tags) = KeyPackageEventBuilder.BuildKeyPackageEvent(
            new byte[] { 1, 2, 3, 4, 5 }, "abc123", Array.Empty<string>());

        var iTag = tags.First(t => t[0] == "i");
        string kpRef = iTag[1];

        // Must be lowercase hex
        Assert.Equal(kpRef, kpRef.ToLowerInvariant());
        // Must be valid hex (SHA-256 output = 32 bytes = 64 hex chars)
        Assert.Equal(64, kpRef.Length);
        Convert.FromHexString(kpRef);
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
    public void NostrGroupDataCodec_Version0_ThrowsOnDecode()
    {
        // Version 0 is rejected (same as Rust MDK)
        var encoded = TlsCodec.Serialize(w =>
        {
            w.WriteUint16(0); // version 0
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

    [Fact]
    public void NostrGroupDataCodec_Version1_DecodeOmitsImageUploadKey()
    {
        var data = new NostrGroupData
        {
            Name = "V1 Group",
            Description = "",
            Version = 1
        };

        byte[] encoded = NostrGroupDataCodec.Encode(data);
        var decoded = NostrGroupDataCodec.Decode(encoded);

        Assert.Equal(1, decoded.Version);
        Assert.Equal("V1 Group", decoded.Name);
        Assert.Empty(decoded.ImageUploadKey);
    }

    [Fact]
    public void NostrGroupDataCodec_Version2_IncludesImageUploadKey()
    {
        var uploadKey = new byte[32];
        uploadKey[0] = 0xCC;

        var data = new NostrGroupData
        {
            Name = "V2 Group",
            Version = 2,
            ImageUploadKey = uploadKey
        };

        byte[] encoded = NostrGroupDataCodec.Encode(data);
        var decoded = NostrGroupDataCodec.Decode(encoded);

        Assert.Equal(2, decoded.Version);
        Assert.Equal(uploadKey, decoded.ImageUploadKey);
    }

    [Fact]
    public void NostrGroupDataCodec_NostrGroupIdNot32Bytes_Throws()
    {
        var data = new NostrGroupData
        {
            NostrGroupId = new byte[16] // Wrong size
        };

        Assert.Throws<ArgumentException>(() => NostrGroupDataCodec.Encode(data));
    }

    [Fact]
    public void NostrGroupDataCodec_NostrGroupIdPreserved()
    {
        var groupId = new byte[32];
        new Random(42).NextBytes(groupId);

        var data = new NostrGroupData
        {
            NostrGroupId = groupId,
            Name = "ID Test"
        };

        byte[] encoded = NostrGroupDataCodec.Encode(data);
        var decoded = NostrGroupDataCodec.Decode(encoded);

        Assert.Equal(groupId, decoded.NostrGroupId);
    }

    [Fact]
    public void NostrGroupDataCodec_WireFormat_VersionAndGroupIdFirst()
    {
        var groupId = new byte[32];
        groupId[0] = 0xDE;
        groupId[31] = 0xAD;

        var data = new NostrGroupData
        {
            Version = 2,
            NostrGroupId = groupId,
            Name = "",
            Description = ""
        };

        byte[] encoded = NostrGroupDataCodec.Encode(data);

        // First 2 bytes: version (u16 big-endian) = 0x0002
        Assert.Equal(0x00, encoded[0]);
        Assert.Equal(0x02, encoded[1]);

        // Next 32 bytes: nostr_group_id
        Assert.Equal(0xDE, encoded[2]);
        Assert.Equal(0xAD, encoded[33]);
    }

    [Fact]
    public void NostrGroupDataCodec_ImageFields_RoundTrip()
    {
        var hash = new byte[32]; hash[0] = 0x11;
        var key = new byte[32]; key[0] = 0x22;
        var nonce = new byte[12]; nonce[0] = 0x33;

        var data = new NostrGroupData
        {
            Name = "Image Test",
            ImageHash = hash,
            ImageKey = key,
            ImageNonce = nonce,
            Version = 2
        };

        byte[] encoded = NostrGroupDataCodec.Encode(data);
        var decoded = NostrGroupDataCodec.Decode(encoded);

        Assert.Equal(hash, decoded.ImageHash);
        Assert.Equal(key, decoded.ImageKey);
        Assert.Equal(nonce, decoded.ImageNonce);
    }

    [Fact]
    public void NostrGroupDataExtension_ExtensionTypeIs0xF2EE()
    {
        Assert.Equal(0xF2EE, NostrGroupDataExtension.ExtensionType);
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
        Assert.Equal("base64", encoding[1]);
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
            new[] { "encoding", "base64" }
        };

        Assert.Throws<FormatException>(() =>
            WelcomeEventParser.ParseWelcomeEvent(content, tags));
    }
}

// ================================================================
// MIP-03 GroupEvent Tests (Encryption/Decryption)
// ================================================================

public class GroupEventTests
{
    private static byte[] RandomKey()
    {
        var key = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void BuildAndParseGroupEvent_RoundTrips()
    {
        byte[] key = RandomKey();
        byte[] mlsMessage = new byte[] { 10, 20, 30, 40, 50 };
        byte[] groupId = new byte[32];
        groupId[0] = 0xAB;

        var (content, tags) = GroupEventBuilder.BuildGroupEvent(mlsMessage, groupId, key);
        var (parsedMessage, parsedGroupId) = GroupEventParser.ParseGroupEvent(content, tags, key);

        Assert.Equal(mlsMessage, parsedMessage);
        Assert.Equal(groupId, parsedGroupId);
    }

    [Fact]
    public void Build_ContainsHTag()
    {
        byte[] key = RandomKey();
        byte[] groupId = new byte[] { 0xAB, 0xCD, 0xEF };

        var (_, tags) = GroupEventBuilder.BuildGroupEvent(new byte[] { 1 }, groupId, key);

        var hTag = tags.First(t => t[0] == "h");
        Assert.Equal("abcdef", hTag[1]); // lowercase hex
    }

    [Fact]
    public void Build_ContainsEncodingTag()
    {
        byte[] key = RandomKey();
        var (_, tags) = GroupEventBuilder.BuildGroupEvent(new byte[] { 1 }, new byte[4], key);

        var encoding = tags.First(t => t[0] == "encoding");
        Assert.Equal("base64", encoding[1]);
    }

    [Fact]
    public void Build_ContentIsBase64()
    {
        byte[] key = RandomKey();
        var (content, _) = GroupEventBuilder.BuildGroupEvent(new byte[] { 1 }, new byte[4], key);

        // Should not throw — content must be valid base64
        byte[] decoded = Convert.FromBase64String(content);

        // base64(nonce[12] + ciphertext[1+] + tag[16]) ≥ 29 bytes
        Assert.True(decoded.Length >= 29);
    }

    [Fact]
    public void Build_EmptyMlsMessage_Throws()
    {
        byte[] key = RandomKey();
        Assert.Throws<ArgumentException>(() =>
            GroupEventBuilder.BuildGroupEvent(Array.Empty<byte>(), new byte[4], key));
    }

    [Fact]
    public void Build_WrongKeyLength_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            GroupEventBuilder.BuildGroupEvent(new byte[] { 1 }, new byte[4], new byte[16]));
    }

    [Fact]
    public void Parse_WrongKey_Throws()
    {
        byte[] key1 = RandomKey();
        byte[] key2 = RandomKey();

        var (content, tags) = GroupEventBuilder.BuildGroupEvent(new byte[] { 1, 2, 3 }, new byte[4], key1);

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
            GroupEventParser.ParseGroupEvent(content, tags, key2));
    }

    [Fact]
    public void Parse_MissingHTag_Throws()
    {
        byte[] key = RandomKey();
        var (content, _) = GroupEventBuilder.BuildGroupEvent(new byte[] { 1 }, new byte[4], key);

        string[][] tagsWithoutH = new[] { new[] { "encoding", "base64" } };

        Assert.Throws<FormatException>(() =>
            GroupEventParser.ParseGroupEvent(content, tagsWithoutH, key));
    }

    [Fact]
    public void Encrypt_ProducesDifferentOutputEachTime()
    {
        byte[] key = RandomKey();
        byte[] plaintext = new byte[] { 1, 2, 3 };

        string enc1 = GroupEventEncryption.Encrypt(plaintext, key);
        string enc2 = GroupEventEncryption.Encrypt(plaintext, key);

        // Random nonce means different output each time
        Assert.NotEqual(enc1, enc2);
    }

    [Fact]
    public void Encrypt_WireFormat_NonceFirst_TagLast()
    {
        byte[] key = RandomKey();
        byte[] plaintext = new byte[] { 0xDE, 0xAD };

        string content = GroupEventEncryption.Encrypt(plaintext, key);
        byte[] decoded = Convert.FromBase64String(content);

        // nonce[12] + ciphertext[2] + tag[16] = 30 bytes
        Assert.Equal(30, decoded.Length);

        // First 12 bytes = nonce (verify by decrypting)
        byte[] decrypted = GroupEventEncryption.Decrypt(content, key);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_TooShort_Throws()
    {
        byte[] key = RandomKey();
        // 28 bytes = exactly nonce+tag, no ciphertext — too short
        string tooShort = Convert.ToBase64String(new byte[28]);

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            GroupEventEncryption.Decrypt(tooShort, key));
    }

    [Fact]
    public void Decrypt_InvalidBase64_Throws()
    {
        byte[] key = RandomKey();

        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            GroupEventEncryption.Decrypt("not-valid-base64!!!", key));
    }

    [Fact]
    public void BuildAndParse_LargeMessage_RoundTrips()
    {
        byte[] key = RandomKey();
        byte[] mlsMessage = new byte[4096];
        System.Security.Cryptography.RandomNumberGenerator.Fill(mlsMessage);
        byte[] groupId = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(groupId);

        var (content, tags) = GroupEventBuilder.BuildGroupEvent(mlsMessage, groupId, key);
        var (parsedMessage, parsedGroupId) = GroupEventParser.ParseGroupEvent(content, tags, key);

        Assert.Equal(mlsMessage, parsedMessage);
        Assert.Equal(groupId, parsedGroupId);
    }
}

// ================================================================
// NIP-59 GiftWrap Tests
// ================================================================

[Trait("Category", "HkdfLinuxRegression")]
public class GiftWrapTests
{
    private static (byte[] privKey, byte[] pubKey) GenerateKeyPair()
    {
        var ctx = Context.Instance;
        var privBytes = new byte[32];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        ECPrivKey? ecPriv;
        do
        {
            rng.GetBytes(privBytes);
        } while (!ECPrivKey.TryCreate(privBytes, ctx, out ecPriv));

        var ecPub = ecPriv!.CreateXOnlyPubKey();
        var pubBytes = new byte[32];
        ecPub.WriteToSpan(pubBytes);
        return (privBytes, pubBytes);
    }

    [Fact]
    public void SealUnseal_RoundTrips()
    {
        var (senderPriv, senderPub) = GenerateKeyPair();
        var (recipientPriv, recipientPub) = GenerateKeyPair();

        byte[] original = System.Text.Encoding.UTF8.GetBytes("Hello MIP-02 Gift Wrap!");
        byte[] sealed_ = GiftWrap.SealContent(original, senderPriv, recipientPub);
        byte[] unsealed = GiftWrap.UnsealContent(sealed_, recipientPriv, senderPub);

        Assert.Equal(original, unsealed);
    }

    [Fact]
    public void SealUnseal_BinaryContent_RoundTrips()
    {
        var (senderPriv, senderPub) = GenerateKeyPair();
        var (recipientPriv, recipientPub) = GenerateKeyPair();

        // Binary content (e.g. MLS Welcome bytes)
        byte[] original = new byte[256];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(original);

        byte[] sealed_ = GiftWrap.SealContent(original, senderPriv, recipientPub);
        byte[] unsealed = GiftWrap.UnsealContent(sealed_, recipientPriv, senderPub);

        Assert.Equal(original, unsealed);
    }

    [Fact]
    public void Seal_ProducesDifferentOutputEachTime()
    {
        var (senderPriv, _) = GenerateKeyPair();
        var (_, recipientPub) = GenerateKeyPair();

        byte[] content = new byte[] { 1, 2, 3 };
        byte[] sealed1 = GiftWrap.SealContent(content, senderPriv, recipientPub);
        byte[] sealed2 = GiftWrap.SealContent(content, senderPriv, recipientPub);

        // NIP-44 uses random nonce, so outputs differ
        Assert.NotEqual(sealed1, sealed2);
    }

    [Fact]
    public void Unseal_WrongKey_Throws()
    {
        var (senderPriv, senderPub) = GenerateKeyPair();
        var (_, recipientPub) = GenerateKeyPair();
        var (wrongPriv, _) = GenerateKeyPair();

        byte[] content = new byte[] { 1, 2, 3 };
        byte[] sealed_ = GiftWrap.SealContent(content, senderPriv, recipientPub);

        // Wrong recipient private key should fail MAC verification
        Assert.ThrowsAny<Exception>(() =>
            GiftWrap.UnsealContent(sealed_, wrongPriv, senderPub));
    }

    [Fact]
    public void Seal_EmptyContent_Throws()
    {
        var (senderPriv, _) = GenerateKeyPair();
        var (_, recipientPub) = GenerateKeyPair();

        Assert.Throws<ArgumentException>(() =>
            GiftWrap.SealContent(Array.Empty<byte>(), senderPriv, recipientPub));
    }

    [Fact]
    public void Seal_NullContent_Throws()
    {
        var (senderPriv, _) = GenerateKeyPair();
        var (_, recipientPub) = GenerateKeyPair();

        Assert.Throws<ArgumentNullException>(() =>
            GiftWrap.SealContent(null!, senderPriv, recipientPub));
    }

    [Fact]
    public void Unseal_NullSealedContent_Throws()
    {
        var (recipientPriv, _) = GenerateKeyPair();
        var (_, senderPub) = GenerateKeyPair();

        Assert.Throws<ArgumentNullException>(() =>
            GiftWrap.UnsealContent(null!, recipientPriv, senderPub));
    }

    [Fact]
    public void SealUnseal_LargeContent_RoundTrips()
    {
        var (senderPriv, senderPub) = GenerateKeyPair();
        var (recipientPriv, recipientPub) = GenerateKeyPair();

        // Large content (~4KB, typical MLS Welcome size)
        byte[] original = new byte[4096];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(original);

        byte[] sealed_ = GiftWrap.SealContent(original, senderPriv, recipientPub);
        byte[] unsealed = GiftWrap.UnsealContent(sealed_, recipientPriv, senderPub);

        Assert.Equal(original, unsealed);
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

// ================================================================
// HKDF-dependent crypto coverage — exercises the call sites that
// route through HkdfProvider (the .NET HKDF.Expand-on-Linux fix).
// ================================================================

public class ExporterSecretKeyDerivationTests
{
    [Fact]
    [Trait("Category", "HkdfLinuxRegression")]
    public void DeriveKeyPair_ProducesCorrectLengths()
    {
        var exporterSecret = new byte[32];
        for (int i = 0; i < 32; i++) exporterSecret[i] = (byte)i;

        var (priv, pub) = ExporterSecretKeyDerivation.DeriveKeyPair(exporterSecret);

        Assert.Equal(32, priv.Length);
        Assert.Equal(32, pub.Length);
    }

    [Fact]
    [Trait("Category", "HkdfLinuxRegression")]
    public void DeriveKeyPair_IsDeterministic()
    {
        var secret = new byte[32];
        for (int i = 0; i < 32; i++) secret[i] = (byte)(0xA0 + i);

        var (priv1, pub1) = ExporterSecretKeyDerivation.DeriveKeyPair(secret);
        var (priv2, pub2) = ExporterSecretKeyDerivation.DeriveKeyPair(secret);

        Assert.Equal(priv1, priv2);
        Assert.Equal(pub1, pub2);
    }

    [Fact]
    [Trait("Category", "HkdfLinuxRegression")]
    public void DeriveKeyPair_DifferentSecrets_ProduceDifferentKeys()
    {
        var s1 = new byte[32];
        var s2 = new byte[32];
        s1[0] = 1;
        s2[0] = 2;

        var (priv1, _) = ExporterSecretKeyDerivation.DeriveKeyPair(s1);
        var (priv2, _) = ExporterSecretKeyDerivation.DeriveKeyPair(s2);

        Assert.NotEqual(priv1, priv2);
    }

    [Fact]
    public void DeriveKeyPair_NullSecret_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            ExporterSecretKeyDerivation.DeriveKeyPair(null!));
    }

    [Fact]
    public void DeriveKeyPair_EmptySecret_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            ExporterSecretKeyDerivation.DeriveKeyPair(Array.Empty<byte>()));
    }
}

public class ImageEncryptionTests
{
    [Fact]
    [Trait("Category", "HkdfLinuxRegression")]
    public void DeriveImageKey_ProducesCorrectLength()
    {
        var secret = new byte[32];
        secret[0] = 0x42;

        var key = ImageEncryption.DeriveImageKey(secret);

        Assert.Equal(32, key.Length);
    }

    [Fact]
    [Trait("Category", "HkdfLinuxRegression")]
    public void DeriveImageKey_IsDeterministic()
    {
        var secret = new byte[32];
        for (int i = 0; i < 32; i++) secret[i] = (byte)i;

        var key1 = ImageEncryption.DeriveImageKey(secret);
        var key2 = ImageEncryption.DeriveImageKey(secret);

        Assert.Equal(key1, key2);
    }

    [Fact]
    [Trait("Category", "HkdfLinuxRegression")]
    public void EncryptDecrypt_WithDerivedKey_RoundTrips()
    {
        var secret = new byte[32];
        for (int i = 0; i < 32; i++) secret[i] = (byte)(0x10 + i);
        var key = ImageEncryption.DeriveImageKey(secret);
        var image = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        var encrypted = ImageEncryption.Encrypt(image, key);
        var decrypted = ImageEncryption.Decrypt(encrypted, key);

        Assert.Equal(image, decrypted);
    }

    [Fact]
    public void DeriveImageKey_NullSecret_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            ImageEncryption.DeriveImageKey(null!));
    }

    [Fact]
    public void DeriveImageKey_EmptySecret_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            ImageEncryption.DeriveImageKey(Array.Empty<byte>()));
    }
}
