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

namespace MarmotCs.Core.Tests;

// ================================================================
// MdkConfig Tests
// ================================================================

public class MdkConfigTests
{
    [Fact]
    public void Default_HasExpectedValues()
    {
        var config = MdkConfig.Default;
        Assert.Equal(TimeSpan.FromDays(7), config.MaxEventAge);
        Assert.Equal(5, config.OutOfOrderTolerance);
        Assert.Equal(1000, config.MaxForwardDistance);
        Assert.Equal(5, config.MaxSnapshotsPerGroup);
        Assert.Equal((ushort)0x0001, config.CipherSuite);
    }

    [Fact]
    public void CanBeCustomized()
    {
        var config = new MdkConfig
        {
            MaxEventAge = TimeSpan.FromHours(1),
            OutOfOrderTolerance = 10,
            MaxForwardDistance = 500,
            MaxSnapshotsPerGroup = 3,
            CipherSuite = 0x0001
        };

        Assert.Equal(TimeSpan.FromHours(1), config.MaxEventAge);
        Assert.Equal(10, config.OutOfOrderTolerance);
        Assert.Equal(500, config.MaxForwardDistance);
        Assert.Equal(3, config.MaxSnapshotsPerGroup);
    }
}

// ================================================================
// MdkBuilder Tests
// ================================================================

public class MdkBuilderTests
{
    [Fact]
    public void Build_WithoutStorage_Throws()
    {
        var builder = new MdkBuilder<MemoryStorageProvider>();
        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    [Fact]
    public void Build_WithStorage_Succeeds()
    {
        var builder = new MdkBuilder<MemoryStorageProvider>()
            .WithStorage(new MemoryStorageProvider());

        // Build should not throw
        var mdk = builder.Build();
        Assert.NotNull(mdk);
    }

    [Fact]
    public void Build_WithAllOptions_Succeeds()
    {
        var builder = new MdkBuilder<MemoryStorageProvider>()
            .WithStorage(new MemoryStorageProvider())
            .WithConfig(new MdkConfig { MaxSnapshotsPerGroup = 10 });

        var mdk = builder.Build();
        Assert.NotNull(mdk);
    }
}

// ================================================================
// MdkException Tests
// ================================================================

public class MdkExceptionTests
{
    [Fact]
    public void MdkException_HasMessage()
    {
        var ex = new MdkException("test error");
        Assert.Equal("test error", ex.Message);
    }

    [Fact]
    public void MdkException_WithInner_ChainsException()
    {
        var inner = new InvalidOperationException("inner");
        var ex = new MdkException("outer", inner);
        Assert.Equal("outer", ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void GroupNotFoundException_IncludesGroupId()
    {
        var groupId = new byte[] { 1, 2, 3 };
        var ex = new GroupNotFoundException(groupId);
        Assert.Equal(groupId, ex.GroupId);
        Assert.Contains("010203", ex.Message);
    }

    [Fact]
    public void InvalidMessageException_HasMessage()
    {
        var ex = new InvalidMessageException("bad message");
        Assert.Equal("bad message", ex.Message);
    }

    [Fact]
    public void WelcomeProcessingException_HasMessage()
    {
        var ex = new WelcomeProcessingException("welcome failed");
        Assert.Equal("welcome failed", ex.Message);
    }

    [Fact]
    public void CommitException_HasMessage()
    {
        var ex = new CommitException("commit failed");
        Assert.Equal("commit failed", ex.Message);
    }

    [Fact]
    public void DuplicateMessageException_IncludesEventId()
    {
        var ex = new DuplicateMessageException("evt123");
        Assert.Equal("evt123", ex.EventId);
        Assert.Contains("evt123", ex.Message);
    }

    [Fact]
    public void StaleEpochException_IncludesEpochs()
    {
        var ex = new StaleEpochException(3, 10);
        Assert.Equal(3UL, ex.MessageEpoch);
        Assert.Equal(10UL, ex.CurrentEpoch);
        Assert.Contains("3", ex.Message);
        Assert.Contains("10", ex.Message);
    }
}

// ================================================================
// Result Types Tests
// ================================================================

public class ResultTypeTests
{
    [Fact]
    public void GroupResult_ContainsExpectedFields()
    {
        var group = new Group(
            new MlsGroupId(new byte[16]),
            GroupState.Active, "Test", null, null, 0, null,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        var result = new GroupResult(group, new byte[] { 1, 2, 3 });
        Assert.Same(group, result.Group);
        Assert.Equal(new byte[] { 1, 2, 3 }, result.KeyPackageBytes);
    }

    [Fact]
    public void ApplicationMessageResult_IsMessageProcessingResult()
    {
        var msg = new Message("id", new MlsGroupId(new byte[16]),
            new byte[] { 1 }, new byte[] { 2 }, 0, MessageState.Sent, DateTimeOffset.UtcNow);
        var result = new ApplicationMessageResult(msg);
        Assert.IsAssignableFrom<MessageProcessingResult>(result);
        Assert.Same(msg, result.Message);
    }

    [Fact]
    public void CommitResult_IsMessageProcessingResult()
    {
        var group = new Group(
            new MlsGroupId(new byte[16]),
            GroupState.Active, "T", null, null, 1, null,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        var result = new CommitResult(group);
        Assert.IsAssignableFrom<MessageProcessingResult>(result);
        Assert.Equal(1UL, result.UpdatedGroup.Epoch);
    }

    [Fact]
    public void UnprocessableResult_HasReason()
    {
        var result = new UnprocessableResult("epoch too old");
        Assert.Equal("epoch too old", result.Reason);
    }

    [Fact]
    public void WelcomePreview_ContainsAllFields()
    {
        var preview = new WelcomePreview(
            "w1", new byte[] { 1, 2, 3 }, "Group Name",
            new[] { "abc123", "def456" }, "sender_pub");

        Assert.Equal("w1", preview.WelcomeId);
        Assert.Equal(new byte[] { 1, 2, 3 }, preview.GroupId);
        Assert.Equal("Group Name", preview.GroupName);
        Assert.Equal(2, preview.MemberIdentities.Length);
        Assert.Equal("sender_pub", preview.SenderNostrPubkey);
    }
}

// ================================================================
// EpochSnapshotManager Tests
// ================================================================

public class EpochSnapshotManagerTests
{
    [Fact]
    public async Task CreateSnapshot_ReturnsNonEmptyId()
    {
        var storage = new MemoryStorageProvider();
        var manager = new EpochSnapshotManager(storage, 5);

        var groupId = new MlsGroupId(new byte[16]);
        await storage.Groups.SaveGroupAsync(new Group(
            groupId, GroupState.Active, "Test", null, null, 0, null,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        var snapId = await manager.CreateSnapshotAsync(groupId);
        Assert.NotNull(snapId);
        Assert.NotEmpty(snapId);
    }

    [Fact]
    public async Task RollbackAndRelease_WorkCorrectly()
    {
        var storage = new MemoryStorageProvider();
        var manager = new EpochSnapshotManager(storage, 5);

        var groupId = new MlsGroupId(new byte[16]);
        await storage.Groups.SaveGroupAsync(new Group(
            groupId, GroupState.Active, "Before", null, null, 0, null,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        var snapId = await manager.CreateSnapshotAsync(groupId);

        // Modify
        await storage.Groups.UpdateGroupAsync(new Group(
            groupId, GroupState.Active, "After", null, null, 5, null,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));

        // Rollback
        await manager.RollbackAsync(snapId);
        var loaded = await storage.Groups.GetGroupAsync(groupId);
        Assert.Equal("Before", loaded!.Name);
    }
}

// ================================================================
// Core Group Lifecycle Tests (using MlsGroup directly as Core API)
// ================================================================

public class CoreGroupLifecycleTests
{
    private readonly ICipherSuite _cs = new CipherSuite0x0001();

    [Fact]
    public void CreateGroup_ProducesValidGroupState()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var group = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), sigPriv, sigPub);

        Assert.Equal(0UL, group.Epoch);
        Assert.NotEmpty(group.GroupId);
        Assert.Equal(1u, group.Tree.LeafCount);

        var members = group.GetMembers();
        Assert.Single(members);
        Assert.Equal("alice"u8.ToArray(), members[0].identity);
    }

    [Fact]
    public void AddMembers_ViaCommit_ProducesWelcome()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var group = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out _, out _);

        var proposals = group.ProposeAdd(new[] { bobKp });
        var (commitMsg, welcome) = group.Commit(proposals);

        Assert.NotNull(commitMsg);
        Assert.NotNull(welcome);

        group.MergePendingCommit();

        Assert.Equal(1UL, group.Epoch);
        Assert.Equal(2u, group.Tree.LeafCount);
        Assert.Equal(2, group.GetMembers().Count);
    }

    [Fact]
    public void CreateMessage_ProducesEncryptedOutput()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var group = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), sigPriv, sigPub);

        // Need at least 2 members for meaningful message exchange,
        // but we can test encryption on a single-member group too
        var encrypted = group.EncryptApplicationMessage("test message"u8.ToArray());
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted.GroupId);
        Assert.Equal(group.Epoch, encrypted.Epoch);
    }

    [Fact]
    public void ProcessMessage_RoundTrips()
    {
        // Setup two-member group
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var aliceGroup = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        var proposals = aliceGroup.ProposeAdd(new[] { bobKp });
        var (_, welcome) = aliceGroup.Commit(proposals);
        aliceGroup.MergePendingCommit();

        var bobGroup = MlsGroup.ProcessWelcome(
            _cs, welcome!, bobKp, bobInitPriv, bobHpkePriv, bobSigPriv);

        // Alice sends
        var plaintext = "Hello from Alice"u8.ToArray();
        var encrypted = aliceGroup.EncryptApplicationMessage(plaintext);

        // Bob receives
        var (decrypted, sender) = bobGroup.DecryptApplicationMessage(encrypted);
        Assert.Equal(plaintext, decrypted);
        Assert.Equal(0u, sender);
    }

    [Fact]
    public void MultipleMessages_InSequence_AllDecrypt()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var aliceGroup = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);

        aliceGroup.Commit(aliceGroup.ProposeAdd(new[] { bobKp }));
        var welcome = aliceGroup.Commit(aliceGroup.ProposeAdd(new[] { bobKp })).welcome;

        // Re-create properly
        aliceGroup = MlsGroup.CreateGroup(_cs, "alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out bobInitPriv, out bobHpkePriv);

        var (_, w2) = aliceGroup.Commit(aliceGroup.ProposeAdd(new[] { bobKp }));
        aliceGroup.MergePendingCommit();

        var bobGroup = MlsGroup.ProcessWelcome(
            _cs, w2!, bobKp, bobInitPriv, bobHpkePriv, bobSigPriv);

        // Send multiple messages
        for (int i = 0; i < 5; i++)
        {
            var msg = System.Text.Encoding.UTF8.GetBytes($"Message {i}");
            var enc = aliceGroup.EncryptApplicationMessage(msg);
            var (dec, _) = bobGroup.DecryptApplicationMessage(enc);
            Assert.Equal(msg, dec);
        }
    }
}
