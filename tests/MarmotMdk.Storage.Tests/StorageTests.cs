using MarmotMdk.Storage.Abstractions;
using MarmotMdk.Storage.Memory;
using MarmotMdk.Storage.Sqlite;
using Xunit;

namespace MarmotMdk.Storage.Tests;

// ================================================================
// Shared test base for all storage providers
// ================================================================

public abstract class StorageProviderTestBase : IAsyncDisposable
{
    protected abstract IMdkStorageProvider CreateProvider();

    private IMdkStorageProvider? _provider;
    protected IMdkStorageProvider Provider => _provider ??= CreateProvider();

    public virtual ValueTask DisposeAsync()
    {
        if (_provider is IDisposable disposable)
            disposable.Dispose();
        return ValueTask.CompletedTask;
    }

    private static MlsGroupId MakeGroupId(byte id = 1)
    {
        var bytes = new byte[16];
        bytes[0] = id;
        return new MlsGroupId(bytes);
    }

    private static Group MakeGroup(MlsGroupId id, string name = "Test Group", GroupState state = GroupState.Active)
    {
        return new Group(
            Id: id,
            State: state,
            Name: name,
            Image: null,
            GroupData: new byte[] { 1, 2, 3 },
            Epoch: 0,
            SelfUpdate: null,
            CreatedAt: DateTimeOffset.UtcNow,
            UpdatedAt: DateTimeOffset.UtcNow);
    }

    private static Message MakeMessage(string id, MlsGroupId groupId, ulong epoch = 0)
    {
        return new Message(
            Id: id,
            GroupId: groupId,
            SenderIdentity: new byte[] { 0xAA },
            Content: "Hello"u8.ToArray(),
            Epoch: epoch,
            State: MessageState.Sent,
            CreatedAt: DateTimeOffset.UtcNow);
    }

    private static Welcome MakeWelcome(string id, MlsGroupId groupId, WelcomeState state = WelcomeState.Pending)
    {
        return new Welcome(
            Id: id,
            GroupId: groupId,
            WelcomeData: new byte[] { 10, 20, 30 },
            State: state,
            GroupData: null,
            SenderNostrPubkey: "abc123",
            CreatedAt: DateTimeOffset.UtcNow);
    }

    // ---- Group storage tests ----

    [Fact]
    public async Task SaveAndGetGroup_RoundTrips()
    {
        var groupId = MakeGroupId(1);
        var group = MakeGroup(groupId, "My Group");

        await Provider.Groups.SaveGroupAsync(group);
        var loaded = await Provider.Groups.GetGroupAsync(groupId);

        Assert.NotNull(loaded);
        Assert.Equal("My Group", loaded!.Name);
        Assert.Equal(GroupState.Active, loaded.State);
    }

    [Fact]
    public async Task GetGroup_NonExistent_ReturnsNull()
    {
        var result = await Provider.Groups.GetGroupAsync(MakeGroupId(99));
        Assert.Null(result);
    }

    [Fact]
    public async Task UpdateGroup_ModifiesExistingGroup()
    {
        var groupId = MakeGroupId(2);
        var group = MakeGroup(groupId, "Original");
        await Provider.Groups.SaveGroupAsync(group);

        var updated = group with { Name = "Updated", Epoch = 5 };
        await Provider.Groups.UpdateGroupAsync(updated);

        var loaded = await Provider.Groups.GetGroupAsync(groupId);
        Assert.NotNull(loaded);
        Assert.Equal("Updated", loaded!.Name);
        Assert.Equal(5UL, loaded.Epoch);
    }

    [Fact]
    public async Task DeleteGroup_RemovesGroup()
    {
        var groupId = MakeGroupId(3);
        await Provider.Groups.SaveGroupAsync(MakeGroup(groupId));
        await Provider.Groups.DeleteGroupAsync(groupId);
        Assert.Null(await Provider.Groups.GetGroupAsync(groupId));
    }

    [Fact]
    public async Task GetGroups_FiltersByState()
    {
        var gid1 = MakeGroupId(10);
        var gid2 = MakeGroupId(11);
        await Provider.Groups.SaveGroupAsync(MakeGroup(gid1, "Active", GroupState.Active));
        await Provider.Groups.SaveGroupAsync(MakeGroup(gid2, "Inactive", GroupState.Inactive));

        var activeGroups = await Provider.Groups.GetGroupsAsync(GroupState.Active);
        Assert.Contains(activeGroups, g => g.Name == "Active");
        Assert.DoesNotContain(activeGroups, g => g.Name == "Inactive");
    }

    [Fact]
    public async Task GetGroups_NoFilter_ReturnsAll()
    {
        var gid1 = MakeGroupId(20);
        var gid2 = MakeGroupId(21);
        await Provider.Groups.SaveGroupAsync(MakeGroup(gid1, "G1"));
        await Provider.Groups.SaveGroupAsync(MakeGroup(gid2, "G2"));

        var allGroups = await Provider.Groups.GetGroupsAsync();
        Assert.True(allGroups.Count >= 2);
    }

    // ---- GroupRelay tests ----

    [Fact]
    public async Task SaveAndGetGroupRelays_RoundTrips()
    {
        var gid = MakeGroupId(30);
        await Provider.Groups.SaveGroupAsync(MakeGroup(gid));
        await Provider.Groups.SaveGroupRelayAsync(new GroupRelay(gid, "wss://relay1.test"));
        await Provider.Groups.SaveGroupRelayAsync(new GroupRelay(gid, "wss://relay2.test"));

        var relays = await Provider.Groups.GetGroupRelaysAsync(gid);
        Assert.Equal(2, relays.Count);
        Assert.Contains(relays, r => r.RelayUrl == "wss://relay1.test");
        Assert.Contains(relays, r => r.RelayUrl == "wss://relay2.test");
    }

    [Fact]
    public async Task SaveGroupRelay_DuplicateUrl_NotDuplicated()
    {
        var gid = MakeGroupId(31);
        await Provider.Groups.SaveGroupAsync(MakeGroup(gid));
        await Provider.Groups.SaveGroupRelayAsync(new GroupRelay(gid, "wss://relay.test"));
        await Provider.Groups.SaveGroupRelayAsync(new GroupRelay(gid, "wss://relay.test"));

        var relays = await Provider.Groups.GetGroupRelaysAsync(gid);
        Assert.Single(relays);
    }

    [Fact]
    public async Task DeleteGroupRelays_RemovesAll()
    {
        var gid = MakeGroupId(32);
        await Provider.Groups.SaveGroupAsync(MakeGroup(gid));
        await Provider.Groups.SaveGroupRelayAsync(new GroupRelay(gid, "wss://relay.test"));
        await Provider.Groups.DeleteGroupRelaysAsync(gid);

        var relays = await Provider.Groups.GetGroupRelaysAsync(gid);
        Assert.Empty(relays);
    }

    // ---- ExporterSecret tests ----

    [Fact]
    public async Task SaveAndGetExporterSecret_RoundTrips()
    {
        var gid = MakeGroupId(40);
        var secret = new GroupExporterSecret(gid, 5, new byte[] { 0xDE, 0xAD });
        await Provider.Groups.SaveExporterSecretAsync(secret);

        var loaded = await Provider.Groups.GetExporterSecretAsync(gid, 5);
        Assert.NotNull(loaded);
        Assert.Equal(new byte[] { 0xDE, 0xAD }, loaded!.Secret);
    }

    [Fact]
    public async Task GetExporterSecret_NonExistent_ReturnsNull()
    {
        var result = await Provider.Groups.GetExporterSecretAsync(MakeGroupId(99), 0);
        Assert.Null(result);
    }

    // ---- Message storage tests ----

    [Fact]
    public async Task SaveAndGetMessage_RoundTrips()
    {
        var gid = MakeGroupId(50);
        var msg = MakeMessage("msg1", gid);
        await Provider.Messages.SaveMessageAsync(msg);

        var loaded = await Provider.Messages.GetMessageAsync("msg1");
        Assert.NotNull(loaded);
        Assert.Equal("msg1", loaded!.Id);
    }

    [Fact]
    public async Task GetMessage_NonExistent_ReturnsNull()
    {
        Assert.Null(await Provider.Messages.GetMessageAsync("nonexistent"));
    }

    [Fact]
    public async Task GetMessages_OrderedByCreatedAt()
    {
        var gid = MakeGroupId(51);
        var now = DateTimeOffset.UtcNow;

        await Provider.Messages.SaveMessageAsync(new Message(
            "m1", gid, new byte[] { 1 }, "first"u8.ToArray(), 0, MessageState.Sent, now));
        await Provider.Messages.SaveMessageAsync(new Message(
            "m2", gid, new byte[] { 1 }, "second"u8.ToArray(), 0, MessageState.Sent, now.AddSeconds(1)));

        var messages = await Provider.Messages.GetMessagesAsync(gid, order: MessageSortOrder.Ascending);
        Assert.Equal(2, messages.Count);
        Assert.Equal("m1", messages[0].Id);
        Assert.Equal("m2", messages[1].Id);

        var desc = await Provider.Messages.GetMessagesAsync(gid, order: MessageSortOrder.Descending);
        Assert.Equal("m2", desc[0].Id);
        Assert.Equal("m1", desc[1].Id);
    }

    [Fact]
    public async Task GetMessages_WithPagination()
    {
        var gid = MakeGroupId(52);
        var now = DateTimeOffset.UtcNow;
        for (int i = 0; i < 5; i++)
        {
            await Provider.Messages.SaveMessageAsync(new Message(
                $"pm{i}", gid, new byte[] { 1 }, new byte[] { (byte)i }, 0, MessageState.Sent, now.AddSeconds(i)));
        }

        var page = await Provider.Messages.GetMessagesAsync(gid, new Pagination(Limit: 2, Offset: 1));
        Assert.Equal(2, page.Count);
    }

    [Fact]
    public async Task GetLastMessage_ReturnsLatest()
    {
        var gid = MakeGroupId(53);
        var now = DateTimeOffset.UtcNow;
        await Provider.Messages.SaveMessageAsync(new Message(
            "lm1", gid, new byte[] { 1 }, "first"u8.ToArray(), 0, MessageState.Sent, now));
        await Provider.Messages.SaveMessageAsync(new Message(
            "lm2", gid, new byte[] { 1 }, "second"u8.ToArray(), 0, MessageState.Sent, now.AddSeconds(5)));

        var last = await Provider.Messages.GetLastMessageAsync(gid);
        Assert.NotNull(last);
        Assert.Equal("lm2", last!.Id);
    }

    [Fact]
    public async Task GetLastMessage_EmptyGroup_ReturnsNull()
    {
        Assert.Null(await Provider.Messages.GetLastMessageAsync(MakeGroupId(99)));
    }

    [Fact]
    public async Task SaveAndGetProcessedMessage_RoundTrips()
    {
        var gid = MakeGroupId(54);
        var pm = new ProcessedMessage("evt1", gid, ProcessedMessageState.Completed, DateTimeOffset.UtcNow);
        await Provider.Messages.SaveProcessedMessageAsync(pm);

        var loaded = await Provider.Messages.GetProcessedMessageAsync("evt1");
        Assert.NotNull(loaded);
        Assert.Equal(ProcessedMessageState.Completed, loaded!.State);
    }

    [Fact]
    public async Task InvalidateMessagesAfterEpoch_RemovesCorrectMessages()
    {
        var gid = MakeGroupId(55);
        var now = DateTimeOffset.UtcNow;
        await Provider.Messages.SaveMessageAsync(new Message(
            "ie1", gid, new byte[] { 1 }, "e0"u8.ToArray(), 0, MessageState.Sent, now));
        await Provider.Messages.SaveMessageAsync(new Message(
            "ie2", gid, new byte[] { 1 }, "e1"u8.ToArray(), 1, MessageState.Sent, now.AddSeconds(1)));
        await Provider.Messages.SaveMessageAsync(new Message(
            "ie3", gid, new byte[] { 1 }, "e2"u8.ToArray(), 2, MessageState.Sent, now.AddSeconds(2)));

        await Provider.Messages.InvalidateMessagesAfterEpochAsync(gid, 1);

        var remaining = await Provider.Messages.GetMessagesAsync(gid);
        Assert.Equal(2, remaining.Count);
        Assert.All(remaining, m => Assert.True(m.Epoch <= 1));
    }

    // ---- Welcome storage tests ----

    [Fact]
    public async Task SaveAndGetWelcome_RoundTrips()
    {
        var gid = MakeGroupId(60);
        var w = MakeWelcome("w1", gid);
        await Provider.Welcomes.SaveWelcomeAsync(w);

        var loaded = await Provider.Welcomes.GetWelcomeAsync("w1");
        Assert.NotNull(loaded);
        Assert.Equal("w1", loaded!.Id);
        Assert.Equal(WelcomeState.Pending, loaded.State);
    }

    [Fact]
    public async Task GetWelcome_NonExistent_ReturnsNull()
    {
        Assert.Null(await Provider.Welcomes.GetWelcomeAsync("nonexistent"));
    }

    [Fact]
    public async Task GetPendingWelcomes_ReturnsOnlyPending()
    {
        var gid = MakeGroupId(61);
        await Provider.Welcomes.SaveWelcomeAsync(MakeWelcome("pw1", gid, WelcomeState.Pending));
        await Provider.Welcomes.SaveWelcomeAsync(MakeWelcome("pw2", gid, WelcomeState.Accepted));
        await Provider.Welcomes.SaveWelcomeAsync(MakeWelcome("pw3", gid, WelcomeState.Pending));

        var pending = await Provider.Welcomes.GetPendingWelcomesAsync();
        Assert.All(pending, w => Assert.Equal(WelcomeState.Pending, w.State));
        Assert.True(pending.Count >= 2);
    }

    [Fact]
    public async Task UpdateWelcome_ModifiesState()
    {
        var gid = MakeGroupId(62);
        var w = MakeWelcome("uw1", gid, WelcomeState.Pending);
        await Provider.Welcomes.SaveWelcomeAsync(w);

        var updated = w with { State = WelcomeState.Accepted };
        await Provider.Welcomes.UpdateWelcomeAsync(updated);

        var loaded = await Provider.Welcomes.GetWelcomeAsync("uw1");
        Assert.Equal(WelcomeState.Accepted, loaded!.State);
    }

    [Fact]
    public async Task SaveAndGetProcessedWelcome_RoundTrips()
    {
        var pw = new ProcessedWelcome("pwel1", ProcessedWelcomeState.Completed, DateTimeOffset.UtcNow);
        await Provider.Welcomes.SaveProcessedWelcomeAsync(pw);

        var loaded = await Provider.Welcomes.GetProcessedWelcomeAsync("pwel1");
        Assert.NotNull(loaded);
        Assert.Equal(ProcessedWelcomeState.Completed, loaded!.State);
    }

    // ---- Snapshot tests ----

    [Fact]
    public async Task Snapshot_CreateAndRollback_RestoresState()
    {
        var gid = MakeGroupId(70);
        var group = MakeGroup(gid, "Before Snapshot");
        await Provider.Groups.SaveGroupAsync(group);

        // Create snapshot
        var snapId = await Provider.CreateSnapshotAsync(gid);

        // Modify state
        var modified = group with { Name = "After Snapshot", Epoch = 10 };
        await Provider.Groups.UpdateGroupAsync(modified);

        // Verify modification
        var check = await Provider.Groups.GetGroupAsync(gid);
        Assert.Equal("After Snapshot", check!.Name);

        // Rollback
        await Provider.RollbackToSnapshotAsync(snapId);

        // Verify rollback
        var restored = await Provider.Groups.GetGroupAsync(gid);
        Assert.Equal("Before Snapshot", restored!.Name);
        Assert.Equal(0UL, restored.Epoch);
    }

    [Fact]
    public async Task Snapshot_Release_DoesNotModifyState()
    {
        var gid = MakeGroupId(71);
        await Provider.Groups.SaveGroupAsync(MakeGroup(gid, "Test"));

        var snapId = await Provider.CreateSnapshotAsync(gid);

        // Modify state
        await Provider.Groups.UpdateGroupAsync(MakeGroup(gid, "Modified") with { Epoch = 5 });

        // Release snapshot (does NOT rollback)
        await Provider.ReleaseSnapshotAsync(snapId);

        // State should still be modified
        var loaded = await Provider.Groups.GetGroupAsync(gid);
        Assert.Equal("Modified", loaded!.Name);
    }

    [Fact]
    public async Task Snapshot_MessagesAreRestoredOnRollback()
    {
        var gid = MakeGroupId(72);
        await Provider.Groups.SaveGroupAsync(MakeGroup(gid));

        var now = DateTimeOffset.UtcNow;
        await Provider.Messages.SaveMessageAsync(new Message(
            "snap_m1", gid, new byte[] { 1 }, "pre-snap"u8.ToArray(), 0, MessageState.Sent, now));

        var snapId = await Provider.CreateSnapshotAsync(gid);

        // Add more messages after snapshot
        await Provider.Messages.SaveMessageAsync(new Message(
            "snap_m2", gid, new byte[] { 1 }, "post-snap"u8.ToArray(), 1, MessageState.Sent, now.AddSeconds(1)));

        // Rollback
        await Provider.RollbackToSnapshotAsync(snapId);

        // Only pre-snapshot message should exist
        var messages = await Provider.Messages.GetMessagesAsync(gid);
        Assert.Single(messages);
        Assert.Equal("snap_m1", messages[0].Id);
    }
}

// ================================================================
// MemoryStorageProvider tests
// ================================================================

public class MemoryStorageProviderTests : StorageProviderTestBase
{
    protected override IMdkStorageProvider CreateProvider() => new MemoryStorageProvider();
}

// ================================================================
// SqliteStorageProvider tests (in-memory SQLite)
// ================================================================

public class SqliteStorageProviderTests : StorageProviderTestBase
{
    private SqliteStorageProvider? _sqliteProvider;

    protected override IMdkStorageProvider CreateProvider()
    {
        _sqliteProvider = new SqliteStorageProvider("Data Source=:memory:");
        return _sqliteProvider;
    }

    public override ValueTask DisposeAsync()
    {
        _sqliteProvider?.Dispose();
        return ValueTask.CompletedTask;
    }
}
