# Security Audit — marmot-cs

**Started:** 2026-04-10  
**Status:** FIXED  
**Branch:** master (up to date)

## Scope
Full security analysis of the marmot-cs solution covering:
- [x] Source code review (OWASP Top 10, crypto misuse, input validation)
- [x] NuGet dependency audit (known CVEs) — **0 vulnerabilities found**
- [x] Cryptographic implementation review
- [x] Storage layer review
- [x] Test coverage of security-sensitive paths
- [x] NIP-44 vector tests — **134/134 passing**

---

## Findings

### CRITICAL — Thread Safety in Core State Machine
- **File:** `src/MarmotCs.Core/Mdk.cs` (class-wide)
- **Issue:** `Mdk<TStorage>` is not thread-safe but manages mutable `_groups` dictionary and private keys used from potentially concurrent callers (UI threads, background event processing). Simultaneous `AddMembersAsync`/`ProcessMessageAsync` on the same group can corrupt MLS state, cause out-of-order epoch transitions, or lose messages.
- **Fix:** Add per-group locking via `ConcurrentDictionary` or `SemaphoreSlim` keyed by group ID. At minimum, document the single-threaded contract prominently.

### HIGH — Sensitive Keys in Managed Heap Without Cleanup
- **Files:** `src/MarmotCs.Core/Mdk.cs` (~L41-42), `src/MarmotCs.Protocol/Crypto/ExporterSecretKeyDerivation.cs`, `src/MarmotCs.Protocol/Crypto/GroupEventEncryption.cs`, `src/MarmotCs.Core/Mip03Crypto.cs`
- **Issue:** Signing and HPKE private keys, exporter secrets, and derived ChaCha20 keys are stored as `byte[]` on the managed heap. They are never zeroed after use and persist until GC collects them. Memory dumps or process inspection can recover these secrets.
- **Fix:** Use `CryptographicOperations.ZeroMemory()` on sensitive buffers after use. Consider a `SecretKey` wrapper implementing `IDisposable`. Use `Span<byte>`-based APIs where possible to keep secrets on the stack.

### HIGH — Duplicate MIP-03 Encryption Implementations
- **Files:** `src/MarmotCs.Core/Mip03Crypto.cs` vs `src/MarmotCs.Protocol/Crypto/GroupEventEncryption.cs`
- **Issue:** Two separate implementations of MIP-03 ChaCha20-Poly1305 encryption exist. `Mip03Crypto` uses the exporter secret directly as the key; `GroupEventEncryption` also performs ChaCha20-Poly1305 but with a different wire format (Base64 vs raw bytes). If one is updated (e.g., key derivation change) and the other forgotten, decryption failures or security regressions will occur.
- **Fix:** Consolidate into a single implementation in `MarmotCs.Protocol` and have `Mdk.cs` call it.

### MEDIUM — Silent Identity Validation Failure
- **File:** `src/MarmotCs.Core/Mdk.cs` (~L78-92) — `CreateGroupAsync`
- **Issue:** When a 64-char identity string fails hex conversion, it silently defaults to `Array.Empty<byte>()`. This creates a group with no valid admin pubkey in the NostrGroupData extension, making the group unmanageable.
- **Fix:** Throw `ArgumentException` on invalid identity format instead of silently degrading.

### MEDIUM — Swallowed Exceptions Hide Corrupt Data
- **File:** `src/MarmotCs.Core/Mdk.cs` (~L428) — `GetNostrGroupData`
- **Issue:** Catches all `Exception` types and returns `null`. Corrupted extension data or malicious payloads are silently ignored. This can hide protocol attacks or bugs that corrupt the group context.
- **Fix:** Catch specific exceptions (e.g., `FormatException`, `ArgumentException`), log the error, then return `null`.

### MEDIUM — Double Base64 Encoding in NIP-59
- **File:** `src/MarmotCs.Protocol/Nip59/GiftWrap.cs` (~L45-48)
- **Issue:** Content is Base64-encoded before NIP-44 encryption, which already produces Base64 output. This inflates message size ~33% unnecessarily and creates a non-standard wire format that other NIP-59 implementations may not expect.
- **Fix:** Pass raw bytes directly to encryption; only Base64-encode at the outermost layer.

### LOW — Floating NuGet Version for DotnetMls
- **File:** `src/MarmotCs.Core/MarmotCs.Core.csproj`, `src/MarmotCs.Protocol/MarmotCs.Protocol.csproj`
- **Issue:** `DotnetMls` is pinned to `0.1.*-*` which resolves to any alpha. A build could silently pull in a new alpha with breaking changes or regressions in the MLS implementation.
- **Fix:** Pin to specific version `0.1.0-alpha.16`.

### LOW — Guid.NewGuid() for Internal Message IDs
- **File:** `src/MarmotCs.Core/Mdk.cs` (~L518)
- **Issue:** Message IDs use `Guid.NewGuid()`. While sufficient for internal storage, GUIDs are not cryptographically random on all runtimes. If these IDs are ever surfaced externally, they could be predictable.
- **Fix:** No immediate action needed. Document that these are internal-only identifiers.

### INFORMATIONAL — NIP-44 Timing in Unpadding
- **File:** `src/MarmotCs.Protocol/Nip44/Nip44Encryption.cs` (~L173)
- **Issue:** `UnpadMessage` performs multiple branches and throws different exceptions based on padding content. While MAC verification (which gates access to this code) uses `FixedTimeEquals`, the unpadding itself is not constant-time.
- **Impact:** Extremely difficult to exploit over Nostr relays. Low practical risk.

---

## Dependency Audit Summary

| Package | Version | Vulnerable? |
|---------|---------|-------------|
| DotnetMls | 0.1.0-alpha.16 | No |
| BouncyCastle.Cryptography | 2.5.1 | No |
| NBitcoin.Secp256k1 | 3.1.5/3.1.6 | No |
| Nostr.Client | 2.1.0 | No |
| Microsoft.Data.Sqlite | 8.0.11 | No |
| Newtonsoft.Json | 13.0.1/13.0.4 | No |
| All test packages | Various | No |

**`dotnet list package --vulnerable` returned 0 findings.**

---

## What's Working Well
- ChaCha20-Poly1305 AEAD used correctly for group event encryption
- HKDF key derivation with proper labels and context binding
- NIP-44 passes all 134 official test vectors
- Constant-time MAC comparison (`FixedTimeEquals`) in NIP-44
- BouncyCastle AEAD handles tag verification internally for MIP-03
- No injection vulnerabilities (no SQL, no command execution, no deserialization of untrusted types)
- No hardcoded keys, nonces, or salts found
- Random nonces generated via `System.Security.Cryptography.RandomNumberGenerator` (CSPRNG)
