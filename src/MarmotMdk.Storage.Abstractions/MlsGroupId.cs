namespace MarmotMdk.Storage.Abstractions;

/// <summary>
/// Value wrapper for an MLS group identifier.
/// </summary>
public readonly record struct MlsGroupId(byte[] Value)
{
    public bool Equals(MlsGroupId other) =>
        Value.AsSpan().SequenceEqual(other.Value.AsSpan());

    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var b in Value)
            hash.Add(b);
        return hash.ToHashCode();
    }

    public override string ToString() => Convert.ToHexString(Value);
}
