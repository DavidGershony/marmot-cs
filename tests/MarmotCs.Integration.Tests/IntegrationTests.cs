using MarmotCs.Core;
using MarmotCs.Core.Errors;
using MarmotCs.Core.Results;
using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.Group;
using DotnetMls.Types;
using MarmotCs.Storage.Abstractions;
using MarmotCs.Storage.Memory;
using Xunit;

namespace MarmotCs.Integration.Tests;

// ================================================================
// Helper: Creates an Mdk<MemoryStorageProvider> instance with fresh storage
// ================================================================

internal static class MdkFactory
{
    public static Mdk<MemoryStorageProvider> Create(IMdkCallback? callback = null)
    {
        var builder = new MdkBuilder<MemoryStorageProvider>()
            .WithStorage(new MemoryStorageProvider())
            .WithConfig(MdkConfig.Default);

        if (callback != null)
            builder.WithCallback(callback);

        return builder.Build();
    }
}

// ================================================================
// Helper: Holds a user's identity and key material
// ================================================================

internal sealed class TestUser
{
    public byte[] Identity { get; }
    public byte[] SigningPrivateKey { get; }
    public byte[] SigningPublicKey { get; }

    public TestUser(string name)
    {
        var cs = new CipherSuite0x0001();
        Identity = System.Text.Encoding.UTF8.GetBytes(name);
        (SigningPrivateKey, SigningPublicKey) = cs.GenerateSignatureKeyPair();
    }
}

// ================================================================
// Helper: Generates a key package + keeps the private keys
// ================================================================

internal sealed class KeyPackageBundle
{
    public byte[] KeyPackageBytes { get; }
    public byte[] InitPrivateKey { get; }
    public byte[] HpkePrivateKey { get; }

    public KeyPackageBundle(TestUser user)
    {
        var cs = new CipherSuite0x0001();
        var kp = MlsGroup.CreateKeyPackage(
            cs, user.Identity, user.SigningPrivateKey, user.SigningPublicKey,
            out var initPriv, out var hpkePriv);

        KeyPackageBytes = TlsCodec.Serialize(writer => kp.WriteTo(writer));
        InitPrivateKey = initPriv;
        HpkePrivateKey = hpkePriv;
    }
}

// ================================================================
// Two-Client Group Creation and Message Exchange
// ================================================================

public class TwoClientGroupTests
{
    [Fact]
    public async Task Alice_Creates_Group_And_Gets_It_Back()
    {
        var mdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var result = await mdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Test Group", new[] { "wss://relay.example.com" });

        Assert.NotNull(result);
        Assert.NotNull(result.Group);
        Assert.Equal("Test Group", result.Group.Name);
        Assert.Equal(GroupState.Active, result.Group.State);
        Assert.Equal(0UL, result.Group.Epoch);
        Assert.NotEmpty(result.KeyPackageBytes);

        // Retrieve group from storage
        var fetched = await mdk.GetGroupAsync(result.Group.Id.Value);
        Assert.NotNull(fetched);
        Assert.Equal(result.Group.Name, fetched!.Name);
    }

    [Fact]
    public async Task Alice_Creates_Group_And_Relays_Are_Stored()
    {
        var mdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var result = await mdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Relay Group", new[] { "wss://relay1.example.com", "wss://relay2.example.com" });

        var relays = await mdk.GetRelaysAsync(result.Group.Id.Value);
        Assert.Equal(2, relays.Count);
    }

    [Fact]
    public async Task GetGroups_ReturnsAllActive()
    {
        var mdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        await mdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Group A", Array.Empty<string>());
        await mdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Group B", Array.Empty<string>());

        var groups = await mdk.GetGroupsAsync(GroupState.Active);
        Assert.Equal(2, groups.Count);
    }

    [Fact]
    public async Task Alice_Adds_Bob_Via_AddMembersAsync()
    {
        var aliceMdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await aliceMdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Two-Person Group", new[] { "wss://relay.example.com" });

        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        var addResult = await aliceMdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        Assert.NotNull(addResult);
        Assert.Equal(1UL, addResult.Group.Epoch);
        Assert.NotNull(addResult.WelcomeBytes);
        Assert.NotEmpty(addResult.CommitMessageBytes);
        Assert.Single(addResult.AddedIdentities);
        Assert.Empty(addResult.RemovedIdentities);
    }

    [Fact]
    public async Task Alice_Gets_Members_After_Adding_Bob()
    {
        var aliceMdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await aliceMdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Members Group", Array.Empty<string>());

        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        await aliceMdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        var members = await aliceMdk.GetMembersAsync(groupResult.Group.Id.Value);
        Assert.Equal(2, members.Count);
    }

    [Fact]
    public async Task AddMembers_ForUnknownGroup_ThrowsGroupNotFound()
    {
        var mdk = MdkFactory.Create();
        var fakeGroupId = new byte[16];
        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        await Assert.ThrowsAsync<GroupNotFoundException>(() =>
            mdk.AddMembersAsync(fakeGroupId, new[] { bobKpBundle.KeyPackageBytes }));
    }

    [Fact]
    public async Task GetMembers_ForUnknownGroup_ThrowsGroupNotFound()
    {
        var mdk = MdkFactory.Create();
        var fakeGroupId = new byte[16];

        await Assert.ThrowsAsync<GroupNotFoundException>(() =>
            mdk.GetMembersAsync(fakeGroupId));
    }
}

// ================================================================
// Welcome Processing Tests
// ================================================================

public class WelcomeProcessingTests
{
    [Fact]
    public async Task Bob_Previews_And_Accepts_Welcome()
    {
        // Alice creates group and adds Bob
        var aliceMdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await aliceMdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Welcome Test", Array.Empty<string>());

        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        var addResult = await aliceMdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        // Bob previews the welcome on his own Mdk instance
        var bobMdk = MdkFactory.Create();
        var preview = await bobMdk.PreviewWelcomeAsync(
            addResult.WelcomeBytes!,
            bobKpBundle.KeyPackageBytes,
            bobKpBundle.InitPrivateKey,
            bobKpBundle.HpkePrivateKey,
            bob.SigningPrivateKey);

        Assert.NotNull(preview);
        Assert.NotEmpty(preview.WelcomeId);
        Assert.NotEmpty(preview.GroupId);
        Assert.True(preview.MemberIdentities.Length >= 2,
            "Preview should show at least 2 members (alice + bob)");

        // Bob accepts the welcome
        var joinedGroup = await bobMdk.AcceptWelcomeAsync(
            preview.WelcomeId,
            bobKpBundle.KeyPackageBytes,
            bobKpBundle.InitPrivateKey,
            bobKpBundle.HpkePrivateKey,
            bob.SigningPrivateKey);

        Assert.NotNull(joinedGroup);
        Assert.Equal(GroupState.Active, joinedGroup.State);
        Assert.Equal(1UL, joinedGroup.Epoch);
    }

    [Fact]
    public async Task Bob_Declines_Welcome()
    {
        var aliceMdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await aliceMdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Decline Test", Array.Empty<string>());

        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        var addResult = await aliceMdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        var bobMdk = MdkFactory.Create();
        var preview = await bobMdk.PreviewWelcomeAsync(
            addResult.WelcomeBytes!,
            bobKpBundle.KeyPackageBytes,
            bobKpBundle.InitPrivateKey,
            bobKpBundle.HpkePrivateKey,
            bob.SigningPrivateKey);

        // Decline
        await bobMdk.DeclineWelcomeAsync(preview.WelcomeId);

        // Verify the welcome state changed
        var welcomeRecord = await bobMdk.GetWelcomeAsync(preview.WelcomeId);
        Assert.NotNull(welcomeRecord);
        Assert.Equal(WelcomeState.Declined, welcomeRecord!.State);
    }

    [Fact]
    public async Task AcceptWelcome_WithInvalidId_Throws()
    {
        var mdk = MdkFactory.Create();

        await Assert.ThrowsAsync<WelcomeProcessingException>(() =>
            mdk.AcceptWelcomeAsync(
                "nonexistent-welcome-id",
                new byte[32], new byte[32], new byte[32], new byte[32]));
    }

    [Fact]
    public async Task DeclineWelcome_WithInvalidId_Throws()
    {
        var mdk = MdkFactory.Create();

        await Assert.ThrowsAsync<WelcomeProcessingException>(() =>
            mdk.DeclineWelcomeAsync("nonexistent-welcome-id"));
    }

    [Fact]
    public async Task PendingWelcomes_AreReturned()
    {
        var aliceMdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await aliceMdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Pending Welcomes Test", Array.Empty<string>());

        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        var addResult = await aliceMdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        var bobMdk = MdkFactory.Create();
        await bobMdk.PreviewWelcomeAsync(
            addResult.WelcomeBytes!,
            bobKpBundle.KeyPackageBytes,
            bobKpBundle.InitPrivateKey,
            bobKpBundle.HpkePrivateKey,
            bob.SigningPrivateKey);

        var pending = await bobMdk.GetPendingWelcomesAsync();
        Assert.Single(pending);
        Assert.Equal(WelcomeState.Pending, pending[0].State);
    }
}

// ================================================================
// End-to-End Message Exchange Tests
// ================================================================

public class MessageExchangeTests
{
    /// <summary>
    /// Sets up Alice + Bob in the same group. Alice has an Mdk with the group created,
    /// Bob has a separate Mdk that joined via Welcome.
    /// Returns (aliceMdk, bobMdk, groupIdBytes).
    /// </summary>
    private static async Task<(Mdk<MemoryStorageProvider> aliceMdk,
        Mdk<MemoryStorageProvider> bobMdk, byte[] groupId)> SetupTwoMemberGroup()
    {
        var aliceMdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await aliceMdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Message Test", Array.Empty<string>());

        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        var addResult = await aliceMdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        var bobMdk = MdkFactory.Create();
        var preview = await bobMdk.PreviewWelcomeAsync(
            addResult.WelcomeBytes!,
            bobKpBundle.KeyPackageBytes,
            bobKpBundle.InitPrivateKey,
            bobKpBundle.HpkePrivateKey,
            bob.SigningPrivateKey);

        await bobMdk.AcceptWelcomeAsync(
            preview.WelcomeId,
            bobKpBundle.KeyPackageBytes,
            bobKpBundle.InitPrivateKey,
            bobKpBundle.HpkePrivateKey,
            bob.SigningPrivateKey);

        return (aliceMdk, bobMdk, groupResult.Group.Id.Value);
    }

    [Fact]
    public async Task Alice_Sends_Message_Bob_Processes()
    {
        var (aliceMdk, bobMdk, groupId) = await SetupTwoMemberGroup();

        // Alice encrypts a message
        var plaintext = "Hello Bob!"u8.ToArray();
        var ciphertext = await aliceMdk.CreateMessageAsync(groupId, plaintext);

        Assert.NotNull(ciphertext);
        Assert.NotEmpty(ciphertext);

        // Bob processes the message
        var result = await bobMdk.ProcessMessageAsync(
            groupId, ciphertext, "evt_alice_msg_1");

        Assert.IsType<ApplicationMessageResult>(result);
        var appResult = (ApplicationMessageResult)result;
        Assert.Equal(plaintext, appResult.Message.Content);
        Assert.Equal(MessageState.Delivered, appResult.Message.State);
    }

    [Fact]
    public async Task Bob_Sends_Message_Alice_Processes()
    {
        var (aliceMdk, bobMdk, groupId) = await SetupTwoMemberGroup();

        // Bob encrypts a message
        var plaintext = "Hello Alice!"u8.ToArray();
        var ciphertext = await bobMdk.CreateMessageAsync(groupId, plaintext);

        // Alice processes the message
        var result = await aliceMdk.ProcessMessageAsync(
            groupId, ciphertext, "evt_bob_msg_1");

        Assert.IsType<ApplicationMessageResult>(result);
        var appResult = (ApplicationMessageResult)result;
        Assert.Equal(plaintext, appResult.Message.Content);
    }

    [Fact]
    public async Task Bidirectional_Message_Exchange()
    {
        var (aliceMdk, bobMdk, groupId) = await SetupTwoMemberGroup();

        // Alice sends to Bob
        var msg1 = "Message from Alice"u8.ToArray();
        var enc1 = await aliceMdk.CreateMessageAsync(groupId, msg1);
        var result1 = await bobMdk.ProcessMessageAsync(groupId, enc1, "evt_1");
        Assert.IsType<ApplicationMessageResult>(result1);
        Assert.Equal(msg1, ((ApplicationMessageResult)result1).Message.Content);

        // Bob sends to Alice
        var msg2 = "Reply from Bob"u8.ToArray();
        var enc2 = await bobMdk.CreateMessageAsync(groupId, msg2);
        var result2 = await aliceMdk.ProcessMessageAsync(groupId, enc2, "evt_2");
        Assert.IsType<ApplicationMessageResult>(result2);
        Assert.Equal(msg2, ((ApplicationMessageResult)result2).Message.Content);

        // Alice sends again
        var msg3 = "Second from Alice"u8.ToArray();
        var enc3 = await aliceMdk.CreateMessageAsync(groupId, msg3);
        var result3 = await bobMdk.ProcessMessageAsync(groupId, enc3, "evt_3");
        Assert.IsType<ApplicationMessageResult>(result3);
        Assert.Equal(msg3, ((ApplicationMessageResult)result3).Message.Content);
    }

    [Fact]
    public async Task Multiple_Sequential_Messages_AllDecrypt()
    {
        var (aliceMdk, bobMdk, groupId) = await SetupTwoMemberGroup();

        for (int i = 0; i < 10; i++)
        {
            var text = System.Text.Encoding.UTF8.GetBytes($"Sequential message {i}");
            var encrypted = await aliceMdk.CreateMessageAsync(groupId, text);
            var result = await bobMdk.ProcessMessageAsync(
                groupId, encrypted, $"evt_seq_{i}");

            Assert.IsType<ApplicationMessageResult>(result);
            Assert.Equal(text, ((ApplicationMessageResult)result).Message.Content);
        }
    }

    [Fact]
    public async Task CreateMessage_ForUnknownGroup_ThrowsGroupNotFound()
    {
        var mdk = MdkFactory.Create();
        var fakeGroupId = new byte[16];

        await Assert.ThrowsAsync<GroupNotFoundException>(() =>
            mdk.CreateMessageAsync(fakeGroupId, "test"u8.ToArray()));
    }

    [Fact]
    public async Task ProcessMessage_ForUnknownGroup_ThrowsGroupNotFound()
    {
        var mdk = MdkFactory.Create();
        var fakeGroupId = new byte[16];

        await Assert.ThrowsAsync<GroupNotFoundException>(() =>
            mdk.ProcessMessageAsync(fakeGroupId, new byte[] { 1, 2, 3 }, "evt_1"));
    }

    [Fact]
    public async Task DuplicateMessage_Throws()
    {
        var (aliceMdk, bobMdk, groupId) = await SetupTwoMemberGroup();

        var plaintext = "Hello"u8.ToArray();
        var encrypted = await aliceMdk.CreateMessageAsync(groupId, plaintext);

        // First processing succeeds
        await bobMdk.ProcessMessageAsync(groupId, encrypted, "evt_dup_1");

        // Second processing with same event ID throws
        await Assert.ThrowsAsync<DuplicateMessageException>(() =>
            bobMdk.ProcessMessageAsync(groupId, encrypted, "evt_dup_1"));
    }

    [Fact]
    public async Task Messages_Are_Persisted_In_Storage()
    {
        var (aliceMdk, bobMdk, groupId) = await SetupTwoMemberGroup();

        var plaintext = "Persisted message"u8.ToArray();
        await aliceMdk.CreateMessageAsync(groupId, plaintext);

        // Alice's storage should have the sent message
        var aliceMessages = await aliceMdk.GetMessagesAsync(groupId);
        Assert.Single(aliceMessages);
        Assert.Equal(plaintext, aliceMessages[0].Content);
    }

    [Fact]
    public async Task GetLastMessage_ReturnsLatest()
    {
        var (aliceMdk, _, groupId) = await SetupTwoMemberGroup();

        await aliceMdk.CreateMessageAsync(groupId, "First"u8.ToArray());
        await aliceMdk.CreateMessageAsync(groupId, "Second"u8.ToArray());
        await aliceMdk.CreateMessageAsync(groupId, "Third"u8.ToArray());

        var last = await aliceMdk.GetLastMessageAsync(groupId);
        Assert.NotNull(last);
        Assert.Equal("Third"u8.ToArray(), last!.Content);
    }
}

// ================================================================
// Self-Update Tests
// ================================================================

public class SelfUpdateTests
{
    [Fact]
    public async Task SelfUpdate_AdvancesEpoch()
    {
        var mdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await mdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Self Update Group", Array.Empty<string>());

        Assert.Equal(0UL, groupResult.Group.Epoch);

        var updateResult = await mdk.SelfUpdateAsync(groupResult.Group.Id.Value);

        Assert.NotNull(updateResult);
        Assert.Equal(1UL, updateResult.Group.Epoch);
        Assert.NotEmpty(updateResult.CommitMessageBytes);
        Assert.Null(updateResult.WelcomeBytes);
        Assert.Empty(updateResult.AddedIdentities);
        Assert.Empty(updateResult.RemovedIdentities);
    }

    [Fact]
    public async Task SelfUpdate_ForUnknownGroup_ThrowsGroupNotFound()
    {
        var mdk = MdkFactory.Create();

        await Assert.ThrowsAsync<GroupNotFoundException>(() =>
            mdk.SelfUpdateAsync(new byte[16]));
    }
}

// ================================================================
// Remove Members Tests
// ================================================================

public class RemoveMembersTests
{
    [Fact]
    public async Task Alice_Removes_Bob()
    {
        var aliceMdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await aliceMdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Remove Test", Array.Empty<string>());

        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        await aliceMdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        // Before removal: 2 members
        var membersBefore = await aliceMdk.GetMembersAsync(groupResult.Group.Id.Value);
        Assert.Equal(2, membersBefore.Count);

        // Remove Bob (leaf index 1)
        var removeResult = await aliceMdk.RemoveMembersAsync(
            groupResult.Group.Id.Value, new uint[] { 1 });

        Assert.NotNull(removeResult);
        Assert.Equal(2UL, removeResult.Group.Epoch);
        Assert.NotEmpty(removeResult.CommitMessageBytes);
        Assert.Single(removeResult.RemovedIdentities);
        Assert.Empty(removeResult.AddedIdentities);
    }

    [Fact]
    public async Task RemoveMembers_ForUnknownGroup_ThrowsGroupNotFound()
    {
        var mdk = MdkFactory.Create();

        await Assert.ThrowsAsync<GroupNotFoundException>(() =>
            mdk.RemoveMembersAsync(new byte[16], new uint[] { 1 }));
    }
}

// ================================================================
// Callback Tests
// ================================================================

public class CallbackTests
{
    private sealed class TrackingCallback : IMdkCallback
    {
        public List<(byte[] groupId, ulong fromEpoch, ulong toEpoch)> Rollbacks { get; } = new();
        public List<(byte[] groupId, ulong newEpoch)> EpochAdvances { get; } = new();
        public List<(byte[] groupId, byte[] identity)> MembersAdded { get; } = new();
        public List<(byte[] groupId, byte[] identity)> MembersRemoved { get; } = new();

        public Task OnRollbackAsync(byte[] groupId, ulong fromEpoch, ulong toEpoch, CancellationToken ct)
        {
            Rollbacks.Add((groupId, fromEpoch, toEpoch));
            return Task.CompletedTask;
        }

        public Task OnEpochAdvanceAsync(byte[] groupId, ulong newEpoch, CancellationToken ct)
        {
            EpochAdvances.Add((groupId, newEpoch));
            return Task.CompletedTask;
        }

        public Task OnMemberAddedAsync(byte[] groupId, byte[] memberIdentity, CancellationToken ct)
        {
            MembersAdded.Add((groupId, memberIdentity));
            return Task.CompletedTask;
        }

        public Task OnMemberRemovedAsync(byte[] groupId, byte[] memberIdentity, CancellationToken ct)
        {
            MembersRemoved.Add((groupId, memberIdentity));
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task AddMembers_Invokes_EpochAdvance_And_MemberAdded_Callbacks()
    {
        var callback = new TrackingCallback();
        var mdk = new MdkBuilder<MemoryStorageProvider>()
            .WithStorage(new MemoryStorageProvider())
            .WithConfig(MdkConfig.Default)
            .WithCallback(callback)
            .Build();

        var alice = new TestUser("alice");
        var groupResult = await mdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Callback Group", Array.Empty<string>());

        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        await mdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        Assert.Single(callback.EpochAdvances);
        Assert.Equal(1UL, callback.EpochAdvances[0].newEpoch);

        Assert.Single(callback.MembersAdded);
    }

    [Fact]
    public async Task RemoveMembers_Invokes_EpochAdvance_And_MemberRemoved_Callbacks()
    {
        var callback = new TrackingCallback();
        var mdk = new MdkBuilder<MemoryStorageProvider>()
            .WithStorage(new MemoryStorageProvider())
            .WithConfig(MdkConfig.Default)
            .WithCallback(callback)
            .Build();

        var alice = new TestUser("alice");
        var groupResult = await mdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Callback Remove", Array.Empty<string>());

        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        await mdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        callback.EpochAdvances.Clear();
        callback.MembersAdded.Clear();

        await mdk.RemoveMembersAsync(
            groupResult.Group.Id.Value, new uint[] { 1 });

        Assert.Single(callback.EpochAdvances);
        Assert.Equal(2UL, callback.EpochAdvances[0].newEpoch);

        Assert.Single(callback.MembersRemoved);
    }

    [Fact]
    public async Task SelfUpdate_Invokes_EpochAdvance_Callback()
    {
        var callback = new TrackingCallback();
        var mdk = new MdkBuilder<MemoryStorageProvider>()
            .WithStorage(new MemoryStorageProvider())
            .WithConfig(MdkConfig.Default)
            .WithCallback(callback)
            .Build();

        var alice = new TestUser("alice");
        var groupResult = await mdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Self-Update Callback", Array.Empty<string>());

        await mdk.SelfUpdateAsync(groupResult.Group.Id.Value);

        Assert.Single(callback.EpochAdvances);
        Assert.Equal(1UL, callback.EpochAdvances[0].newEpoch);
    }
}

// ================================================================
// Key Package API Tests
// ================================================================

public class KeyPackageApiTests
{
    [Fact]
    public void CreateKeyPackage_ReturnsValidBytesAndTags()
    {
        var mdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var (kpBytes, tags) = mdk.CreateKeyPackage(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            new[] { "wss://relay.example.com" });

        Assert.NotEmpty(kpBytes);
        Assert.NotNull(tags);
        Assert.NotEmpty(tags);
    }

    [Fact]
    public void CreateKeyPackage_BytesCanBeDeserialized()
    {
        var mdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var (kpBytes, _) = mdk.CreateKeyPackage(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            Array.Empty<string>());

        // Should be deserializable
        var reader = new TlsReader(kpBytes);
        var kp = KeyPackage.ReadFrom(reader);
        Assert.NotNull(kp);
        Assert.Equal((ushort)0x0001, kp.CipherSuite);
    }
}

// ================================================================
// Full End-to-End Lifecycle Test
// ================================================================

public class FullLifecycleTests
{
    [Fact]
    public async Task Complete_Group_Lifecycle_Create_Add_Message_Remove()
    {
        // Step 1: Alice creates a group
        var aliceMdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await aliceMdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Full Lifecycle Group", new[] { "wss://relay.example.com" });

        Assert.Equal(0UL, groupResult.Group.Epoch);

        // Step 2: Alice adds Bob
        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        var addResult = await aliceMdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        Assert.Equal(1UL, addResult.Group.Epoch);
        Assert.NotNull(addResult.WelcomeBytes);

        // Step 3: Bob joins via Welcome
        var bobMdk = MdkFactory.Create();
        var preview = await bobMdk.PreviewWelcomeAsync(
            addResult.WelcomeBytes!,
            bobKpBundle.KeyPackageBytes,
            bobKpBundle.InitPrivateKey,
            bobKpBundle.HpkePrivateKey,
            bob.SigningPrivateKey);

        var bobGroup = await bobMdk.AcceptWelcomeAsync(
            preview.WelcomeId,
            bobKpBundle.KeyPackageBytes,
            bobKpBundle.InitPrivateKey,
            bobKpBundle.HpkePrivateKey,
            bob.SigningPrivateKey);

        Assert.Equal(1UL, bobGroup.Epoch);

        // Step 4: Alice sends a message, Bob decrypts
        var msg1 = "Hello from Alice!"u8.ToArray();
        var enc1 = await aliceMdk.CreateMessageAsync(groupResult.Group.Id.Value, msg1);
        var result1 = await bobMdk.ProcessMessageAsync(
            bobGroup.Id.Value, enc1, "evt_lifecycle_1");

        Assert.IsType<ApplicationMessageResult>(result1);
        Assert.Equal(msg1, ((ApplicationMessageResult)result1).Message.Content);

        // Step 5: Bob sends a message, Alice decrypts
        var msg2 = "Hello from Bob!"u8.ToArray();
        var enc2 = await bobMdk.CreateMessageAsync(bobGroup.Id.Value, msg2);
        var result2 = await aliceMdk.ProcessMessageAsync(
            groupResult.Group.Id.Value, enc2, "evt_lifecycle_2");

        Assert.IsType<ApplicationMessageResult>(result2);
        Assert.Equal(msg2, ((ApplicationMessageResult)result2).Message.Content);

        // Step 6: Alice removes Bob
        var removeResult = await aliceMdk.RemoveMembersAsync(
            groupResult.Group.Id.Value, new uint[] { 1 });

        Assert.Equal(2UL, removeResult.Group.Epoch);
        Assert.Single(removeResult.RemovedIdentities);

        // Step 7: After removal, group still has Alice as a member
        var membersAfterRemoval = await aliceMdk.GetMembersAsync(groupResult.Group.Id.Value);
        Assert.Single(membersAfterRemoval);
    }

    [Fact]
    public async Task Three_Member_Group_Lifecycle()
    {
        // Alice creates group
        var aliceMdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await aliceMdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Three Members", Array.Empty<string>());

        // Alice adds Bob and Carol at the same time
        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);
        var carol = new TestUser("carol");
        var carolKpBundle = new KeyPackageBundle(carol);

        var addResult = await aliceMdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes, carolKpBundle.KeyPackageBytes });

        Assert.Equal(1UL, addResult.Group.Epoch);
        Assert.Equal(2, addResult.AddedIdentities.Length);
        Assert.NotNull(addResult.WelcomeBytes);

        // Verify all three members exist
        var members = await aliceMdk.GetMembersAsync(groupResult.Group.Id.Value);
        Assert.Equal(3, members.Count);
    }

    [Fact]
    public async Task Messages_After_SelfUpdate_Still_Decrypt()
    {
        // Setup two-member group
        var aliceMdk = MdkFactory.Create();
        var alice = new TestUser("alice");

        var groupResult = await aliceMdk.CreateGroupAsync(
            alice.Identity, alice.SigningPrivateKey, alice.SigningPublicKey,
            "Post-Update Messages", Array.Empty<string>());

        var bob = new TestUser("bob");
        var bobKpBundle = new KeyPackageBundle(bob);

        var addResult = await aliceMdk.AddMembersAsync(
            groupResult.Group.Id.Value,
            new[] { bobKpBundle.KeyPackageBytes });

        // Bob joins
        var bobMdk = MdkFactory.Create();
        var preview = await bobMdk.PreviewWelcomeAsync(
            addResult.WelcomeBytes!,
            bobKpBundle.KeyPackageBytes,
            bobKpBundle.InitPrivateKey,
            bobKpBundle.HpkePrivateKey,
            bob.SigningPrivateKey);

        var bobGroup = await bobMdk.AcceptWelcomeAsync(
            preview.WelcomeId,
            bobKpBundle.KeyPackageBytes,
            bobKpBundle.InitPrivateKey,
            bobKpBundle.HpkePrivateKey,
            bob.SigningPrivateKey);

        // Alice performs a self-update
        var updateResult = await aliceMdk.SelfUpdateAsync(groupResult.Group.Id.Value);
        Assert.Equal(2UL, updateResult.Group.Epoch);

        // Bob processes the commit from Alice's self-update
        var commitResult = await bobMdk.ProcessMessageAsync(
            bobGroup.Id.Value,
            updateResult.CommitMessageBytes,
            "evt_self_update_commit");

        Assert.IsType<CommitResult>(commitResult);
        Assert.Equal(2UL, ((CommitResult)commitResult).UpdatedGroup.Epoch);

        // Now both are at epoch 2 - Alice sends a message
        var msg = "After self-update!"u8.ToArray();
        var enc = await aliceMdk.CreateMessageAsync(groupResult.Group.Id.Value, msg);
        var msgResult = await bobMdk.ProcessMessageAsync(
            bobGroup.Id.Value, enc, "evt_post_update_msg");

        Assert.IsType<ApplicationMessageResult>(msgResult);
        Assert.Equal(msg, ((ApplicationMessageResult)msgResult).Message.Content);
    }
}
