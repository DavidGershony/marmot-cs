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
/// Tests for ProcessIncomingCommitAsync and MIP-03 tiebreaker resolution.
/// Verifies that when a pending (staged) commit races with an incoming commit
/// at the same epoch, the tiebreaker picks the winner correctly.
/// </summary>
public class TiebreakerTests
{
    private readonly ICipherSuite _cs = new CipherSuite0x0001();

    /// <summary>
    /// Sets up a two-member group (Alice + Bob) using two separate Mdk instances,
    /// both at the same epoch, so we can create racing commits.
    /// Returns Alice's Mdk/groupId and the raw MlsGroup for Bob (for crafting incoming commits).
    /// </summary>
    private async Task<(Mdk<MemoryStorageProvider> aliceMdk, byte[] groupId, MlsGroup bobGroup)> SetupTwoMemberGroup()
    {
        var (aliceSigPriv, aliceSigPub) = _cs.GenerateSignatureKeyPair();
        var aliceIdentity = "alice"u8.ToArray();

        var storage = new MemoryStorageProvider();
        var aliceMdk = new MdkBuilder<MemoryStorageProvider>()
            .WithStorage(storage)
            .Build();

        // Alice creates group
        var createResult = await aliceMdk.CreateGroupAsync(
            aliceIdentity, aliceSigPriv, aliceSigPub, "test", new[] { "wss://relay.test" });
        var groupId = createResult.Group.Id.Value;

        // Create Bob's key package
        var (bobSigPriv, bobSigPub) = _cs.GenerateSignatureKeyPair();
        var bobKp = MlsGroup.CreateKeyPackage(
            _cs, "bob"u8.ToArray(), bobSigPriv, bobSigPub,
            out var bobInitPriv, out var bobHpkePriv);
        byte[] bobKpBytes = TlsCodec.Serialize(writer => bobKp.WriteTo(writer));

        // Alice adds Bob (stage + merge)
        var addResult = await aliceMdk.StageAddMembersAsync(groupId, new[] { bobKpBytes });
        await aliceMdk.MergeStagedCommitAsync(groupId);

        // Bob joins via Welcome
        var reader = new TlsReader(addResult.WelcomeBytes!);
        var welcome = DotnetMls.Types.Welcome.ReadFrom(reader);
        var bobGroup = MlsGroup.ProcessWelcome(
            _cs, welcome, bobKp, bobInitPriv, bobHpkePriv, bobSigPriv);

        // Both are now at epoch 1
        return (aliceMdk, groupId, bobGroup);
    }

    /// <summary>
    /// Creates a self-update commit from Bob's MlsGroup, serialized as bytes.
    /// </summary>
    private byte[] CreateBobCommit(MlsGroup bobGroup)
    {
        var (proposal, _) = bobGroup.ProposeSelfUpdate();
        var (commitMsg, _) = bobGroup.Commit(new List<Proposal> { proposal });
        var mlsMessage = new MlsMessage(WireFormat.MlsPrivateMessage, commitMsg);
        return TlsCodec.Serialize(writer => mlsMessage.WriteTo(writer));
    }

    [Fact]
    public async Task OursWins_DiscardIncoming()
    {
        var (aliceMdk, groupId, bobGroup) = await SetupTwoMemberGroup();

        // Alice stages a self-update with an earlier timestamp
        var earlierTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var laterTime = new DateTimeOffset(2026, 1, 1, 0, 0, 1, TimeSpan.Zero);

        await aliceMdk.StageSelfUpdateAsync(groupId,
            intendedEventId: "aaaa", intendedCreatedAt: earlierTime);

        // Bob creates an incoming commit with a later timestamp
        byte[] bobCommitBytes = CreateBobCommit(bobGroup);

        // Process incoming — ours wins (earlier timestamp)
        var result = await aliceMdk.ProcessIncomingCommitAsync(
            groupId, bobCommitBytes, "bbbb", laterTime);

        Assert.IsType<RaceWonResult>(result);
        var won = (RaceWonResult)result;
        Assert.Equal("bbbb", won.DiscardedEventId);

        // Pending commit should still be there
        Assert.True(aliceMdk.HasPendingCommit(groupId));
    }

    [Fact]
    public async Task IncomingWins_ClearsPending_ProcessesIncoming()
    {
        var (aliceMdk, groupId, bobGroup) = await SetupTwoMemberGroup();

        // Alice stages with a later timestamp
        var earlierTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var laterTime = new DateTimeOffset(2026, 1, 1, 0, 0, 1, TimeSpan.Zero);

        await aliceMdk.StageSelfUpdateAsync(groupId,
            intendedEventId: "zzzz", intendedCreatedAt: laterTime);

        // Bob creates an incoming commit with an earlier timestamp
        byte[] bobCommitBytes = CreateBobCommit(bobGroup);

        // Process incoming — incoming wins (earlier timestamp)
        var ex = await Assert.ThrowsAsync<RaceLostException>(
            () => aliceMdk.ProcessIncomingCommitAsync(
                groupId, bobCommitBytes, "aaaa", earlierTime));

        Assert.Equal("aaaa", ex.WinnerEventId);
        // The incoming commit was processed, epoch advanced
        Assert.Equal(2UL, ex.NewEpoch);

        // Pending commit should be cleared
        Assert.False(aliceMdk.HasPendingCommit(groupId));

        // Group epoch should reflect the incoming commit
        var group = await aliceMdk.GetGroupAsync(groupId);
        Assert.Equal(2UL, group!.Epoch);
    }

    [Fact]
    public async Task EqualTimestamp_LexSmallerIdWins()
    {
        var (aliceMdk, groupId, bobGroup) = await SetupTwoMemberGroup();

        var sameTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        // Alice stages with a lex-larger event ID
        await aliceMdk.StageSelfUpdateAsync(groupId,
            intendedEventId: "ffff", intendedCreatedAt: sameTime);

        // Bob's incoming commit has lex-smaller event ID — it should win
        byte[] bobCommitBytes = CreateBobCommit(bobGroup);

        var ex = await Assert.ThrowsAsync<RaceLostException>(
            () => aliceMdk.ProcessIncomingCommitAsync(
                groupId, bobCommitBytes, "aaaa", sameTime));

        Assert.Equal("aaaa", ex.WinnerEventId);
        Assert.False(aliceMdk.HasPendingCommit(groupId));
    }

    [Fact]
    public async Task EqualTimestamp_LexLargerIdLoses()
    {
        var (aliceMdk, groupId, bobGroup) = await SetupTwoMemberGroup();

        var sameTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        // Alice stages with a lex-smaller event ID
        await aliceMdk.StageSelfUpdateAsync(groupId,
            intendedEventId: "aaaa", intendedCreatedAt: sameTime);

        // Bob's incoming commit has a lex-larger event ID — it should lose
        byte[] bobCommitBytes = CreateBobCommit(bobGroup);

        var result = await aliceMdk.ProcessIncomingCommitAsync(
            groupId, bobCommitBytes, "ffff", sameTime);

        Assert.IsType<RaceWonResult>(result);
        Assert.True(aliceMdk.HasPendingCommit(groupId));
    }

    [Fact]
    public async Task IdenticalTimestampAndId_DeterministicallyOneWins()
    {
        var (aliceMdk, groupId, bobGroup) = await SetupTwoMemberGroup();

        var sameTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var sameId = "abcd1234";

        // Stage with same id and timestamp as the incoming
        await aliceMdk.StageSelfUpdateAsync(groupId,
            intendedEventId: sameId, intendedCreatedAt: sameTime);

        byte[] bobCommitBytes = CreateBobCommit(bobGroup);

        // When both entries have identical id and timestamp, CommitRaceResolver returns
        // the first entry (our pending). But since winner == incomingEventId (they share
        // the same id), the code takes the "incoming wins" path. This is deterministic:
        // identical ids means both are "the winner", so processing the incoming is correct.
        var ex = await Assert.ThrowsAsync<RaceLostException>(
            () => aliceMdk.ProcessIncomingCommitAsync(
                groupId, bobCommitBytes, sameId, sameTime));

        Assert.Equal(sameId, ex.WinnerEventId);
        Assert.False(aliceMdk.HasPendingCommit(groupId));
    }

    [Fact]
    public async Task NoPending_ProcessesCommitDirectly()
    {
        var (aliceMdk, groupId, bobGroup) = await SetupTwoMemberGroup();

        // No staged commit — just process Bob's incoming commit directly
        byte[] bobCommitBytes = CreateBobCommit(bobGroup);

        var result = await aliceMdk.ProcessIncomingCommitAsync(
            groupId, bobCommitBytes, "evt1", DateTimeOffset.UtcNow);

        Assert.IsType<CommitResult>(result);
        var commitResult = (CommitResult)result;
        Assert.Equal(2UL, commitResult.UpdatedGroup.Epoch);
        Assert.False(aliceMdk.HasPendingCommit(groupId));
    }

    [Fact]
    public async Task PendingWithoutMetadata_ProcessesCommitDirectly()
    {
        var (aliceMdk, groupId, bobGroup) = await SetupTwoMemberGroup();

        // Stage without metadata (intendedEventId/CreatedAt not provided)
        await aliceMdk.StageSelfUpdateAsync(groupId);

        // Since no metadata was stored, tiebreaker can't run — treat as no-pending path
        byte[] bobCommitBytes = CreateBobCommit(bobGroup);

        // This should process the incoming commit directly, clearing the pending
        // (since ProcessCommit on MlsGroup with a pending commit will process the incoming one)
        var result = await aliceMdk.ProcessIncomingCommitAsync(
            groupId, bobCommitBytes, "evt1", DateTimeOffset.UtcNow);

        Assert.IsType<CommitResult>(result);
    }
}
