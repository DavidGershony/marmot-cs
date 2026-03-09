namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Storage operations for messages and processed message tracking.
/// </summary>
public interface IMessageStorage
{
    Task SaveMessageAsync(Message message, CancellationToken ct = default);

    Task<Message?> GetMessageAsync(string id, CancellationToken ct = default);

    Task<IReadOnlyList<Message>> GetMessagesAsync(
        MlsGroupId groupId,
        Pagination? pagination = null,
        MessageSortOrder order = MessageSortOrder.Ascending,
        CancellationToken ct = default);

    Task<Message?> GetLastMessageAsync(MlsGroupId groupId, CancellationToken ct = default);

    Task SaveProcessedMessageAsync(ProcessedMessage processed, CancellationToken ct = default);

    Task<ProcessedMessage?> GetProcessedMessageAsync(string eventId, CancellationToken ct = default);

    Task InvalidateMessagesAfterEpochAsync(MlsGroupId groupId, ulong epoch, CancellationToken ct = default);
}
