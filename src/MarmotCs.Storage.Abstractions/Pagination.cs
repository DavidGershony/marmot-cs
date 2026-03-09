namespace MarmotCs.Storage.Abstractions;

/// <summary>
/// Pagination parameters for list queries.
/// </summary>
public sealed record Pagination(
    int Limit = 50,
    int Offset = 0);
