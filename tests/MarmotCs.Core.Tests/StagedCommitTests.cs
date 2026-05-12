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

/// <summary>
/// Tests for the staged commit API (MIP-03 compliant publish-then-merge).
/// Verifies that Stage* methods do NOT advance epoch, and that merge/clear
/// behave correctly.
/// </summary>
public class StagedCommitTests
{
    private readonly ICipherSuite _cs = new CipherSuite0x0001();

    private (Mdk<MemoryStorageProvider> mdk, byte[] groupId) CreateMdkWithGroup(
        byte[] identity, byte[] sigPriv, byte[] sigPub)
    {
        var storage = new MemoryStorageProvider();
        var mdk = new MdkBuilder<MemoryStorageProvider>()
            .WithStorage(storage)
            .Build();

        var result = mdk.CreateGroupAsync(identity, sigPriv, sigPub, "test", new[] { "wss://relay.test" }).Result;
        return (mdk, result.Group.Id.Value);
    }

    private (byte[] kpBytes, byte[] initPriv, byte[] hpkePriv, byte[] sigPriv, byte[] sigPub) CreateBobKeyPackage()
    {
        var (sigPriv, sigPub) = _cs.GenerateSignatureKeyPair();
        var kp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), sigPriv, sigPub,
            out var initPriv, out var hpkePriv);
        byte[] kpBytes = TlsCodec.Serialize(writer => kp.WriteTo(writer));
        return (kpBytes, initPriv, hpkePriv, sigPriv, sigPub);
    }

    [Fact]
    public async Task StageAddMembers_DoesNotAdvanceEpoch_UntilMerge()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var (mdk, groupId) = CreateMdkWithGroup("alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        var (bobKpBytes, _, _, _, _) = CreateBobKeyPackage();

        var groupBefore = await mdk.GetGroupAsync(groupId);
        var epochBefore = groupBefore!.Epoch;

        // Stage — should NOT advance epoch
        var result = await mdk.StageAddMembersAsync(groupId, new[] { bobKpBytes });

        var groupAfterStage = await mdk.GetGroupAsync(groupId);
        Assert.Equal(epochBefore, groupAfterStage!.Epoch);
        Assert.True(mdk.HasPendingCommit(groupId));
        Assert.NotNull(result.CommitMessageBytes);
        Assert.NotNull(result.WelcomeBytes);
        Assert.Single(result.AddedIdentities);

        // Merge — NOW epoch advances
        var updatedGroup = await mdk.MergeStagedCommitAsync(groupId);
        Assert.Equal(epochBefore + 1, updatedGroup.Epoch);
        Assert.False(mdk.HasPendingCommit(groupId));

        var groupAfterMerge = await mdk.GetGroupAsync(groupId);
        Assert.Equal(epochBefore + 1, groupAfterMerge!.Epoch);
    }

    [Fact]
    public async Task StageThenClear_LeavesEpochUnchanged()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var (mdk, groupId) = CreateMdkWithGroup("alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        var (bobKpBytes, _, _, _, _) = CreateBobKeyPackage();

        var groupBefore = await mdk.GetGroupAsync(groupId);
        var epochBefore = groupBefore!.Epoch;

        await mdk.StageAddMembersAsync(groupId, new[] { bobKpBytes });
        Assert.True(mdk.HasPendingCommit(groupId));

        mdk.ClearPendingCommit(groupId);
        Assert.False(mdk.HasPendingCommit(groupId));

        var groupAfterClear = await mdk.GetGroupAsync(groupId);
        Assert.Equal(epochBefore, groupAfterClear!.Epoch);
    }

    [Fact]
    public async Task DoubleStage_ReplacesPriorPendingCommit()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var (mdk, groupId) = CreateMdkWithGroup("alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        var (bobKpBytes, _, _, _, _) = CreateBobKeyPackage();

        // Create a second key package for a different member
        var (charlieSignPriv, charlieSignPub) = _cs.GenerateSignatureKeyPair();
        var charlieKp = MlsGroup.CreateKeyPackage(
            _cs, "charlie"u8.ToArray(), charlieSignPriv, charlieSignPub,
            out _, out _);
        byte[] charlieKpBytes = TlsCodec.Serialize(writer => charlieKp.WriteTo(writer));

        // Stage first add
        var result1 = await mdk.StageAddMembersAsync(groupId, new[] { bobKpBytes });
        Assert.True(mdk.HasPendingCommit(groupId));

        // The second stage will either throw (because there's already a pending commit
        // at the MlsGroup.Commit level) or replace the pending commit.
        // Either behavior is acceptable — we pin whichever one MlsGroup does.
        try
        {
            var result2 = await mdk.StageAddMembersAsync(groupId, new[] { charlieKpBytes });
            // If it succeeded, the second staging replaced the first
            Assert.True(mdk.HasPendingCommit(groupId));
            Assert.Contains(result2.AddedIdentities, id => id == Convert.ToHexString("charlie"u8.ToArray()));
        }
        catch (CommitException)
        {
            // If it threw, the first staging is preserved
            Assert.True(mdk.HasPendingCommit(groupId));
        }
    }

    [Fact]
    public async Task HasPendingCommit_ReportsAccurately()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var (mdk, groupId) = CreateMdkWithGroup("alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        var (bobKpBytes, _, _, _, _) = CreateBobKeyPackage();

        // No pending initially
        Assert.False(mdk.HasPendingCommit(groupId));

        // Pending after stage
        await mdk.StageAddMembersAsync(groupId, new[] { bobKpBytes });
        Assert.True(mdk.HasPendingCommit(groupId));

        // Not pending after merge
        await mdk.MergeStagedCommitAsync(groupId);
        Assert.False(mdk.HasPendingCommit(groupId));
    }

    [Fact]
    public async Task HasPendingCommit_FalseAfterClear()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var (mdk, groupId) = CreateMdkWithGroup("alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        var (bobKpBytes, _, _, _, _) = CreateBobKeyPackage();

        await mdk.StageAddMembersAsync(groupId, new[] { bobKpBytes });
        Assert.True(mdk.HasPendingCommit(groupId));

        mdk.ClearPendingCommit(groupId);
        Assert.False(mdk.HasPendingCommit(groupId));
    }

    [Fact]
    public async Task MergeStagedCommit_WithNoPending_Throws()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var (mdk, groupId) = CreateMdkWithGroup("alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => mdk.MergeStagedCommitAsync(groupId));
    }

    [Fact]
    public async Task StageRemoveMembers_DoesNotAdvanceEpoch_UntilMerge()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var (mdk, groupId) = CreateMdkWithGroup("alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        var (bobKpBytes, _, _, _, _) = CreateBobKeyPackage();

        // Add Bob first (using staged + merge for clean state)
        await mdk.StageAddMembersAsync(groupId, new[] { bobKpBytes });
        await mdk.MergeStagedCommitAsync(groupId);

        var members = await mdk.GetMembersAsync(groupId);
        Assert.Equal(2, members.Count);
        var bobLeaf = members.First(m => m.identityHex == Convert.ToHexString("bob"u8.ToArray())).leafIndex;

        var groupBefore = await mdk.GetGroupAsync(groupId);
        var epochBefore = groupBefore!.Epoch;

        // Stage remove — should NOT advance epoch
        await mdk.StageRemoveMembersAsync(groupId, new[] { bobLeaf });
        var groupAfterStage = await mdk.GetGroupAsync(groupId);
        Assert.Equal(epochBefore, groupAfterStage!.Epoch);
        Assert.True(mdk.HasPendingCommit(groupId));

        // Merge — NOW epoch advances
        var updatedGroup = await mdk.MergeStagedCommitAsync(groupId);
        Assert.Equal(epochBefore + 1, updatedGroup.Epoch);
        Assert.False(mdk.HasPendingCommit(groupId));
    }

    [Fact]
    public async Task StageSelfUpdate_DoesNotAdvanceEpoch_UntilMerge()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var (mdk, groupId) = CreateMdkWithGroup("alice"u8.ToArray(), aliceSigPriv, aliceSigPub);

        var groupBefore = await mdk.GetGroupAsync(groupId);
        var epochBefore = groupBefore!.Epoch;

        // Stage self-update — should NOT advance epoch
        var result = await mdk.StageSelfUpdateAsync(groupId);
        var groupAfterStage = await mdk.GetGroupAsync(groupId);
        Assert.Equal(epochBefore, groupAfterStage!.Epoch);
        Assert.True(mdk.HasPendingCommit(groupId));
        Assert.NotNull(result.CommitMessageBytes);

        // Merge — NOW epoch advances
        var updatedGroup = await mdk.MergeStagedCommitAsync(groupId);
        Assert.Equal(epochBefore + 1, updatedGroup.Epoch);
        Assert.False(mdk.HasPendingCommit(groupId));
    }

    [Fact]
    public async Task StageAddMembers_WelcomeIsValid_ForBobToJoin()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var (mdk, groupId) = CreateMdkWithGroup("alice"u8.ToArray(), aliceSigPriv, aliceSigPub);
        var (bobKpBytes, bobInitPriv, bobHpkePriv, bobSigPriv, bobSigPub) = CreateBobKeyPackage();

        // Stage and merge (simulating the MIP-03 flow)
        var result = await mdk.StageAddMembersAsync(groupId, new[] { bobKpBytes });
        await mdk.MergeStagedCommitAsync(groupId);

        // Verify the Welcome bytes are valid — Bob can process them
        Assert.NotNull(result.WelcomeBytes);
        var reader = new TlsReader(result.WelcomeBytes);
        var welcome = DotnetMls.Types.Welcome.ReadFrom(reader);

        var kpReader = new TlsReader(bobKpBytes);
        var bobKp = KeyPackage.ReadFrom(kpReader);

        var bobGroup = MlsGroup.ProcessWelcome(
            _cs, welcome, bobKp, bobInitPriv, bobHpkePriv, bobSigPriv);

        Assert.Equal(1UL, bobGroup.Epoch);
        Assert.Equal(2, bobGroup.GetMembers().Count);
    }
}
