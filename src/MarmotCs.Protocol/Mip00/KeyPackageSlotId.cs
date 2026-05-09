using System.Security.Cryptography;

namespace MarmotCs.Protocol.Mip00;

/// <summary>
/// Helper for generating and validating MIP-00 KeyPackage slot identifiers (the <c>d</c> tag value
/// of a kind 30443 addressable event).
/// </summary>
/// <remarks>
/// Per MIP-00:
/// <list type="bullet">
///   <item>A slot ID is a cryptographically random 32-byte hex string.</item>
///   <item>It is generated <b>once</b>, the first time the client publishes a KeyPackage for a given slot.</item>
///   <item>On rotation (e.g. after joining a group, or proactive refresh) the client publishes a new
///         kind 30443 event with the <b>same</b> <c>d</c> tag value, so the relay replaces the previous
///         KeyPackage in place.</item>
///   <item>A client MAY use multiple slot IDs (one per device / one per long-lived purpose) but each
///         slot must keep its own stable <c>d</c> tag.</item>
/// </list>
/// Generating a fresh slot ID on every publish defeats the addressable-event semantics: the relay
/// will accumulate one live KeyPackage per publish instead of replacing the previous one, leaving
/// stale KeyPackages whose private init keys the client no longer holds.
/// </remarks>
public static class KeyPackageSlotId
{
    /// <summary>
    /// Generates a new cryptographically random 32-byte slot ID, encoded as 64-character lowercase hex.
    /// Call this <b>once</b> per slot and persist the result for reuse on every rotation.
    /// </summary>
    public static string GenerateNew()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
