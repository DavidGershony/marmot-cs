namespace MarmotMdk.Storage.Abstractions;

/// <summary>
/// Stores an MLS exporter secret for a group at a specific epoch.
/// </summary>
public sealed record GroupExporterSecret(
    MlsGroupId GroupId,
    ulong Epoch,
    byte[] Secret);
