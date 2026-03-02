## Plan: Extract MLS Code to dotnetMls Subfolder

Copy the `MarmotMdk.Mls` and `MarmotMdk.Mls.Crypto` projects (plus their tests) into a new `dotnetMls/` subfolder with renamed namespaces (`MarmotMdk.Mls.*` → `DotnetMls.*`), a new solution file, and NuGet packaging metadata. The existing marmut-mdk code stays untouched.

### Steps

1. **Create folder structure** under `dotnetMls/`:
   ```
   dotnetMls/
   ├── DotnetMls.sln
   ├── src/
   │   ├── DotnetMls/           (← from MarmotMdk.Mls)
   │   │   ├── Codec/
   │   │   ├── Group/
   │   │   ├── KeySchedule/
   │   │   ├── Message/
   │   │   ├── Tree/
   │   │   └── Types/
   │   └── DotnetMls.Crypto/    (← from MarmotMdk.Mls.Crypto)
   └── tests/
       ├── DotnetMls.Tests/
       └── DotnetMls.Crypto.Tests/
   ```

2. **Create `DotnetMls.Crypto.csproj`** — same as [MarmotMdk.Mls.Crypto.csproj](src/MarmotMdk.Mls.Crypto/MarmotMdk.Mls.Crypto.csproj) but with NuGet package metadata (`PackageId`, `Version`, `Description`, `Authors`, `License`, `RepositoryUrl`). Keep the `BouncyCastle.Cryptography` dependency.

3. **Create `DotnetMls.csproj`** — same as [MarmotMdk.Mls.csproj](src/MarmotMdk.Mls/MarmotMdk.Mls.csproj) but referencing `DotnetMls.Crypto.csproj` instead, plus NuGet package metadata.

4. **Copy all 10 Crypto source files** with namespace rename `MarmotMdk.Mls.Crypto` → `DotnetMls.Crypto`:
   - `ICipherSuite.cs`, `IHpke.cs`, `ISignatureScheme.cs`
   - `AesGcmProvider.cs`, `CipherSuite0x0001.cs`, `Ed25519Provider.cs`
   - `HkdfProvider.cs`, `HpkeX25519Aes128.cs`, `X25519Provider.cs`

5. **Copy all 38 MLS source files** with namespace/using renames (`MarmotMdk.Mls.*` → `DotnetMls.*`):
   - **Codec/** (5 files): `QuicVarint.cs`, `TlsCodec.cs`, `TlsDecodingException.cs`, `TlsReader.cs`, `TlsWriter.cs`
   - **Group/** (2 files): `MlsGroup.cs`, `MlsGroupConfig.cs`
   - **KeySchedule/** (3 files): `KeyScheduleEpoch.cs`, `SecretTree.cs`, `TranscriptHash.cs`
   - **Message/** (2 files): `MessageFraming.cs`, `SenderRatchet.cs`
   - **Tree/** (5 files): `ParentNode.cs`, `RatchetTree.cs`, `TreeKem.cs`, `TreeMath.cs`, `TreeNode.cs`
   - **Types/** (28 files): `Capabilities.cs`, `Commit.cs`, `ContentType.cs`, `Credential.cs`, `EncryptedGroupSecrets.cs`, `Extension.cs`, `FramedContent.cs`, `FramedContentAuthData.cs`, `GroupContext.cs`, `GroupInfo.cs`, `GroupSecrets.cs`, `HpkeCiphertext.cs`, `KeyPackage.cs`, `KeyPackageRef.cs`, `LeafNode.cs`, `LeafNodeSource.cs`, `Lifetime.cs`, `MlsMessage.cs`, `PrivateMessage.cs`, `Proposal.cs`, `ProposalOrRef.cs`, `ProposalType.cs`, `ProtocolVersion.cs`, `PublicMessage.cs`, `Sender.cs`, `SenderType.cs`, `UpdatePath.cs`, `UpdatePathNode.cs`, `Welcome.cs`, `WireFormat.cs`

6. **Copy test projects** with renamed references and namespaces:
   - `DotnetMls.Tests.csproj` referencing `DotnetMls.csproj` — copy [MlsTests.cs](tests/MarmotMdk.Mls.Tests/MlsTests.cs) with `MarmotMdk.Mls` → `DotnetMls` renames
   - `DotnetMls.Crypto.Tests.csproj` referencing `DotnetMls.Crypto.csproj` — copy [CryptoTests.cs](tests/MarmotMdk.Mls.Crypto.Tests/CryptoTests.cs) with namespace renames

7. **Create `DotnetMls.sln`** referencing all 4 projects with Debug/Release configurations.

### Namespace Rename Summary (find/replace per file)

| Original | Replacement |
|----------|-------------|
| `namespace MarmotMdk.Mls.Crypto` | `namespace DotnetMls.Crypto` |
| `namespace MarmotMdk.Mls.Codec` | `namespace DotnetMls.Codec` |
| `namespace MarmotMdk.Mls.Group` | `namespace DotnetMls.Group` |
| `namespace MarmotMdk.Mls.KeySchedule` | `namespace DotnetMls.KeySchedule` |
| `namespace MarmotMdk.Mls.Message` | `namespace DotnetMls.Message` |
| `namespace MarmotMdk.Mls.Tree` | `namespace DotnetMls.Tree` |
| `namespace MarmotMdk.Mls.Types` | `namespace DotnetMls.Types` |
| `using MarmotMdk.Mls.Crypto` | `using DotnetMls.Crypto` |
| `using MarmotMdk.Mls.Codec` | `using DotnetMls.Codec` |
| `using MarmotMdk.Mls.Group` | `using DotnetMls.Group` |
| `using MarmotMdk.Mls.KeySchedule` | `using DotnetMls.KeySchedule` |
| `using MarmotMdk.Mls.Message` | `using DotnetMls.Message` |
| `using MarmotMdk.Mls.Tree` | `using DotnetMls.Tree` |
| `using MarmotMdk.Mls.Types` | `using DotnetMls.Types` |

### Further Considerations

1. **NuGet metadata** — The `.csproj` files should include `<PackageId>DotnetMls</PackageId>`, `<Version>0.1.0-alpha.1</Version>`, `<Description>Pure C# implementation of the MLS protocol (RFC 9420)</Description>`, plus `<PackageLicenseExpression>`, `<Authors>`, and `<RepositoryUrl>`.
2. **README.md** — Add a `dotnetMls/README.md` describing the library as a standalone MLS RFC 9420 implementation, independent of Marmot/Nostr.
3. **.gitignore** — Add `dotnetMls/src/*/bin/`, `dotnetMls/src/*/obj/`, `dotnetMls/tests/*/bin/`, `dotnetMls/tests/*/obj/` entries (or rely on the root `.gitignore` if it already covers `bin/`/`obj/`).

