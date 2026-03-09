using System.Collections.Concurrent;
using MarmotCs.Storage.Abstractions;

namespace MarmotCs.Storage.Memory;

/// <summary>
/// In-memory implementation of <see cref="IMdkStorageProvider"/> using
/// <see cref="ConcurrentDictionary{TKey,TValue}"/> for thread-safe storage.
/// Suitable for tests and short-lived processes where persistence is not required.
/// </summary>
public sealed class MemoryStorageProvider : IMdkStorageProvider, IGroupStorage, IMessageStorage, IWelcomeStorage
{
    // ── Group storage ──────────────────────────────────────────────────
    private readonly ConcurrentDictionary<string, Group> _groups = new();
    private readonly ConcurrentDictionary<string, List<GroupRelay>> _groupRelays = new();
    private readonly ConcurrentDictionary<string, Dictionary<ulong, GroupExporterSecret>> _exporterSecrets = new();

    // ── Message storage ────────────────────────────────────────────────
    private readonly ConcurrentDictionary<string, Message> _messages = new();
    private readonly ConcurrentDictionary<string, List<Message>> _messagesByGroup = new();
    private readonly ConcurrentDictionary<string, ProcessedMessage> _processedMessages = new();

    // ── Welcome storage ────────────────────────────────────────────────
    private readonly ConcurrentDictionary<string, Welcome> _welcomes = new();
    private readonly ConcurrentDictionary<string, ProcessedWelcome> _processedWelcomes = new();

    // ── Snapshots ──────────────────────────────────────────────────────
    private readonly ConcurrentDictionary<string, Snapshot> _snapshots = new();

    // Synchronisation lock for operations that touch multiple dictionaries.
    private readonly object _lock = new();

    // ── IMdkStorageProvider ────────────────────────────────────────────
    public IGroupStorage Groups => this;
    public IMessageStorage Messages => this;
    public IWelcomeStorage Welcomes => this;

    // ================================================================
    // IGroupStorage
    // ================================================================

    Task IGroupStorage.SaveGroupAsync(Group group, CancellationToken ct)
    {
        var key = GroupKey(group.Id);
        _groups[key] = group;
        return Task.CompletedTask;
    }

    Task<Group?> IGroupStorage.GetGroupAsync(MlsGroupId id, CancellationToken ct)
    {
        _groups.TryGetValue(GroupKey(id), out var group);
        return Task.FromResult(group);
    }

    Task<IReadOnlyList<Group>> IGroupStorage.GetGroupsAsync(GroupState? state, CancellationToken ct)
    {
        IEnumerable<Group> query = _groups.Values;
        if (state.HasValue)
            query = query.Where(g => g.State == state.Value);
        IReadOnlyList<Group> result = query.ToList().AsReadOnly();
        return Task.FromResult(result);
    }

    Task IGroupStorage.UpdateGroupAsync(Group group, CancellationToken ct)
    {
        var key = GroupKey(group.Id);
        _groups[key] = group;
        return Task.CompletedTask;
    }

    Task IGroupStorage.DeleteGroupAsync(MlsGroupId id, CancellationToken ct)
    {
        var key = GroupKey(id);
        _groups.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    Task IGroupStorage.SaveGroupRelayAsync(GroupRelay relay, CancellationToken ct)
    {
        var key = GroupKey(relay.GroupId);
        lock (_lock)
        {
            var list = _groupRelays.GetOrAdd(key, _ => new List<GroupRelay>());
            if (!list.Any(r => r.RelayUrl == relay.RelayUrl))
                list.Add(relay);
        }
        return Task.CompletedTask;
    }

    Task<IReadOnlyList<GroupRelay>> IGroupStorage.GetGroupRelaysAsync(MlsGroupId groupId, CancellationToken ct)
    {
        IReadOnlyList<GroupRelay> result = _groupRelays.TryGetValue(GroupKey(groupId), out var list)
            ? list.ToList().AsReadOnly()
            : Array.Empty<GroupRelay>();
        return Task.FromResult(result);
    }

    Task IGroupStorage.DeleteGroupRelaysAsync(MlsGroupId groupId, CancellationToken ct)
    {
        _groupRelays.TryRemove(GroupKey(groupId), out _);
        return Task.CompletedTask;
    }

    Task IGroupStorage.SaveExporterSecretAsync(GroupExporterSecret secret, CancellationToken ct)
    {
        var key = GroupKey(secret.GroupId);
        lock (_lock)
        {
            var dict = _exporterSecrets.GetOrAdd(key, _ => new Dictionary<ulong, GroupExporterSecret>());
            dict[secret.Epoch] = secret;
        }
        return Task.CompletedTask;
    }

    Task<GroupExporterSecret?> IGroupStorage.GetExporterSecretAsync(MlsGroupId groupId, ulong epoch, CancellationToken ct)
    {
        GroupExporterSecret? result = null;
        if (_exporterSecrets.TryGetValue(GroupKey(groupId), out var dict))
            dict.TryGetValue(epoch, out result);
        return Task.FromResult(result);
    }

    // ================================================================
    // IMessageStorage
    // ================================================================

    Task IMessageStorage.SaveMessageAsync(Message message, CancellationToken ct)
    {
        _messages[message.Id] = message;
        var gKey = GroupKey(message.GroupId);
        lock (_lock)
        {
            var list = _messagesByGroup.GetOrAdd(gKey, _ => new List<Message>());
            list.Add(message);
        }
        return Task.CompletedTask;
    }

    Task<Message?> IMessageStorage.GetMessageAsync(string id, CancellationToken ct)
    {
        _messages.TryGetValue(id, out var msg);
        return Task.FromResult(msg);
    }

    Task<IReadOnlyList<Message>> IMessageStorage.GetMessagesAsync(
        MlsGroupId groupId,
        Pagination? pagination,
        MessageSortOrder order,
        CancellationToken ct)
    {
        var gKey = GroupKey(groupId);
        if (!_messagesByGroup.TryGetValue(gKey, out var list))
        {
            IReadOnlyList<Message> empty = Array.Empty<Message>();
            return Task.FromResult(empty);
        }

        IEnumerable<Message> query;
        lock (_lock)
        {
            query = order == MessageSortOrder.Ascending
                ? list.OrderBy(m => m.CreatedAt).ToList()
                : list.OrderByDescending(m => m.CreatedAt).ToList();
        }

        var paging = pagination ?? new Pagination();
        IReadOnlyList<Message> result = query
            .Skip(paging.Offset)
            .Take(paging.Limit)
            .ToList()
            .AsReadOnly();
        return Task.FromResult(result);
    }

    Task<Message?> IMessageStorage.GetLastMessageAsync(MlsGroupId groupId, CancellationToken ct)
    {
        Message? result = null;
        if (_messagesByGroup.TryGetValue(GroupKey(groupId), out var list))
        {
            lock (_lock)
            {
                result = list.OrderByDescending(m => m.CreatedAt).FirstOrDefault();
            }
        }
        return Task.FromResult(result);
    }

    Task IMessageStorage.SaveProcessedMessageAsync(ProcessedMessage processed, CancellationToken ct)
    {
        _processedMessages[processed.EventId] = processed;
        return Task.CompletedTask;
    }

    Task<ProcessedMessage?> IMessageStorage.GetProcessedMessageAsync(string eventId, CancellationToken ct)
    {
        _processedMessages.TryGetValue(eventId, out var pm);
        return Task.FromResult(pm);
    }

    Task IMessageStorage.InvalidateMessagesAfterEpochAsync(MlsGroupId groupId, ulong epoch, CancellationToken ct)
    {
        var gKey = GroupKey(groupId);
        lock (_lock)
        {
            if (_messagesByGroup.TryGetValue(gKey, out var list))
            {
                var toRemove = list.Where(m => m.Epoch > epoch).ToList();
                foreach (var msg in toRemove)
                {
                    list.Remove(msg);
                    _messages.TryRemove(msg.Id, out _);
                }
            }
        }
        return Task.CompletedTask;
    }

    // ================================================================
    // IWelcomeStorage
    // ================================================================

    Task IWelcomeStorage.SaveWelcomeAsync(Welcome welcome, CancellationToken ct)
    {
        _welcomes[welcome.Id] = welcome;
        return Task.CompletedTask;
    }

    Task<Welcome?> IWelcomeStorage.GetWelcomeAsync(string id, CancellationToken ct)
    {
        _welcomes.TryGetValue(id, out var w);
        return Task.FromResult(w);
    }

    Task<IReadOnlyList<Welcome>> IWelcomeStorage.GetPendingWelcomesAsync(CancellationToken ct)
    {
        IReadOnlyList<Welcome> result = _welcomes.Values
            .Where(w => w.State == WelcomeState.Pending)
            .ToList()
            .AsReadOnly();
        return Task.FromResult(result);
    }

    Task IWelcomeStorage.UpdateWelcomeAsync(Welcome welcome, CancellationToken ct)
    {
        _welcomes[welcome.Id] = welcome;
        return Task.CompletedTask;
    }

    Task IWelcomeStorage.SaveProcessedWelcomeAsync(ProcessedWelcome processed, CancellationToken ct)
    {
        _processedWelcomes[processed.EventId] = processed;
        return Task.CompletedTask;
    }

    Task<ProcessedWelcome?> IWelcomeStorage.GetProcessedWelcomeAsync(string eventId, CancellationToken ct)
    {
        _processedWelcomes.TryGetValue(eventId, out var pw);
        return Task.FromResult(pw);
    }

    // ================================================================
    // Snapshot operations
    // ================================================================

    public Task<string> CreateSnapshotAsync(MlsGroupId groupId, CancellationToken ct = default)
    {
        var snapshotId = Guid.NewGuid().ToString("N");
        var gKey = GroupKey(groupId);

        lock (_lock)
        {
            var snap = new Snapshot
            {
                GroupId = groupId,
                CreatedAt = DateTimeOffset.UtcNow,
            };

            // Snapshot the group itself
            if (_groups.TryGetValue(gKey, out var group))
                snap.Group = group;

            // Snapshot relays
            if (_groupRelays.TryGetValue(gKey, out var relays))
                snap.Relays = new List<GroupRelay>(relays);

            // Snapshot exporter secrets
            if (_exporterSecrets.TryGetValue(gKey, out var secrets))
                snap.ExporterSecrets = new Dictionary<ulong, GroupExporterSecret>(secrets);

            // Snapshot messages for this group
            if (_messagesByGroup.TryGetValue(gKey, out var msgs))
            {
                snap.Messages = new List<Message>(msgs);
                snap.MessageIds = msgs.Select(m => m.Id).ToList();
            }

            // Snapshot processed messages that reference this group
            snap.ProcessedMessages = _processedMessages.Values
                .Where(pm => GroupKey(pm.GroupId) == gKey)
                .ToList();

            // Snapshot welcomes for this group
            snap.Welcomes = _welcomes.Values
                .Where(w => GroupKey(w.GroupId) == gKey)
                .ToList();

            // Snapshot processed welcomes (we store all since they aren't group-keyed;
            // however for correctness we only snapshot those that correspond to our
            // group welcomes)
            var welcomeEventIds = snap.Welcomes
                .Select(w => w.Id)
                .ToHashSet();
            // ProcessedWelcome has EventId which corresponds to a welcome event, not necessarily the Welcome.Id.
            // We snapshot all processed welcomes to avoid data loss.
            snap.ProcessedWelcomes = _processedWelcomes.Values.ToList();

            _snapshots[snapshotId] = snap;
        }

        return Task.FromResult(snapshotId);
    }

    public Task RollbackToSnapshotAsync(string snapshotId, CancellationToken ct = default)
    {
        if (!_snapshots.TryGetValue(snapshotId, out var snap))
            throw new KeyNotFoundException($"Snapshot '{snapshotId}' not found.");

        var gKey = GroupKey(snap.GroupId);

        lock (_lock)
        {
            // Restore group
            if (snap.Group is not null)
                _groups[gKey] = snap.Group;
            else
                _groups.TryRemove(gKey, out _);

            // Restore relays
            if (snap.Relays is not null)
                _groupRelays[gKey] = new List<GroupRelay>(snap.Relays);
            else
                _groupRelays.TryRemove(gKey, out _);

            // Restore exporter secrets
            if (snap.ExporterSecrets is not null)
                _exporterSecrets[gKey] = new Dictionary<ulong, GroupExporterSecret>(snap.ExporterSecrets);
            else
                _exporterSecrets.TryRemove(gKey, out _);

            // Remove current messages for this group from the flat index
            if (_messagesByGroup.TryGetValue(gKey, out var currentMsgs))
            {
                foreach (var m in currentMsgs)
                    _messages.TryRemove(m.Id, out _);
            }

            // Restore messages
            if (snap.Messages is not null)
            {
                var restored = new List<Message>(snap.Messages);
                _messagesByGroup[gKey] = restored;
                foreach (var m in restored)
                    _messages[m.Id] = m;
            }
            else
            {
                _messagesByGroup.TryRemove(gKey, out _);
            }

            // Restore processed messages for this group
            // First remove existing ones for this group
            var pmToRemove = _processedMessages.Values
                .Where(pm => GroupKey(pm.GroupId) == gKey)
                .Select(pm => pm.EventId)
                .ToList();
            foreach (var eid in pmToRemove)
                _processedMessages.TryRemove(eid, out _);

            if (snap.ProcessedMessages is not null)
            {
                foreach (var pm in snap.ProcessedMessages)
                    _processedMessages[pm.EventId] = pm;
            }

            // Remove current welcomes for this group
            var welToRemove = _welcomes.Values
                .Where(w => GroupKey(w.GroupId) == gKey)
                .Select(w => w.Id)
                .ToList();
            foreach (var wid in welToRemove)
                _welcomes.TryRemove(wid, out _);

            // Restore welcomes
            if (snap.Welcomes is not null)
            {
                foreach (var w in snap.Welcomes)
                    _welcomes[w.Id] = w;
            }

            // Restore processed welcomes (full replacement)
            _processedWelcomes.Clear();
            if (snap.ProcessedWelcomes is not null)
            {
                foreach (var pw in snap.ProcessedWelcomes)
                    _processedWelcomes[pw.EventId] = pw;
            }
        }

        return Task.CompletedTask;
    }

    public Task ReleaseSnapshotAsync(string snapshotId, CancellationToken ct = default)
    {
        _snapshots.TryRemove(snapshotId, out _);
        return Task.CompletedTask;
    }

    public Task PruneSnapshotsAsync(MlsGroupId groupId, int keepCount, CancellationToken ct = default)
    {
        var gKey = GroupKey(groupId);
        var groupSnapshots = _snapshots
            .Where(kv => GroupKey(kv.Value.GroupId) == gKey)
            .OrderByDescending(kv => kv.Value.CreatedAt)
            .Skip(keepCount)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var id in groupSnapshots)
            _snapshots.TryRemove(id, out _);

        return Task.CompletedTask;
    }

    // ================================================================
    // Helpers
    // ================================================================

    private static string GroupKey(MlsGroupId id) => Convert.ToHexString(id.Value);

    // ================================================================
    // Snapshot data holder
    // ================================================================

    private sealed class Snapshot
    {
        public MlsGroupId GroupId { get; init; }
        public DateTimeOffset CreatedAt { get; init; }
        public Group? Group { get; set; }
        public List<GroupRelay>? Relays { get; set; }
        public Dictionary<ulong, GroupExporterSecret>? ExporterSecrets { get; set; }
        public List<Message>? Messages { get; set; }
        public List<string>? MessageIds { get; set; }
        public List<ProcessedMessage>? ProcessedMessages { get; set; }
        public List<Welcome>? Welcomes { get; set; }
        public List<ProcessedWelcome>? ProcessedWelcomes { get; set; }
    }
}
