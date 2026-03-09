# Marmot CS (C#)

A C# implementation of the [Marmot Messaging Development Kit](https://github.com/DavidGershony/marmot-cs) — a secure group messaging library that combines [MLS (Message Layer Security, RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420) with the [Nostr](https://nostr.com/) decentralised network.

> **Status:** `0.1.0-alpha.1` — API and wire formats are not yet stable.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Packages](#packages)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [1. Build an `Mdk` instance](#1-build-an-mdk-instance)
  - [2. Create a group](#2-create-a-group)
  - [3. Add members](#3-add-members)
  - [4. Send a message](#4-send-a-message)
  - [5. Process a received message](#5-process-a-received-message)
  - [6. Accept a Welcome](#6-accept-a-welcome)
- [Configuration](#configuration)
- [Storage Backends](#storage-backends)
  - [In-Memory](#in-memory)
  - [SQLite](#sqlite)
  - [Custom backend](#custom-backend)
- [Callbacks](#callbacks)
- [Protocol Layer — Nostr / MIPs](#protocol-layer--nostr--mips)
- [Exception Hierarchy](#exception-hierarchy)
- [Building & Testing](#building--testing)
- [Thread Safety](#thread-safety)
- [License](#license)

---

## Overview

Marmot CS provides a high-level API for secure, end-to-end encrypted **group messaging**:

- **MLS (RFC 9420)** handles all cryptographic group state: key agreement, forward secrecy, post-compromise security, member additions/removals, and epoch management.
- **Nostr** is used as the transport and identity layer. Group events, key packages, and Welcome messages are published as Nostr events (kinds 443, 444, 445) using the Marmot Improvement Proposals (MIPs) defined in this library.
- **Pluggable storage** lets you persist group state in memory (for tests) or SQLite (for production).

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                MarmotCs.Core (Public API)               │
│          Mdk<TStorage>  ·  MdkBuilder  ·  MdkConfig     │
└──────────────────────┬──────────────────────────────────┘
                       │
         ┌─────────────┼─────────────────┐
         ▼             ▼                 ▼
  ┌─────────────┐ ┌──────────────┐ ┌────────────────────┐
  │  DotnetMls  │ │   Protocol   │ │ Storage.Abstractions│
  │ (RFC 9420   │ │ (Nostr NIPs  │ │  IMdkStorageProvider│
  │  state      │ │  + MIPs)     │ │  IGroupStorage …    │
  │  machine)   │ │              │ └─────────┬──────────┘
  └─────────────┘ └──────────────┘           │
                                    ┌────────┴───────────┐
                                    ▼                     ▼
                             Storage.Memory         Storage.Sqlite
                           (tests / ephemeral)   (production / WAL)
```

**Data flow (typical receive path):**

1. A Nostr event (kind 443/444/445) arrives from a relay.
2. The **Protocol** layer decodes and authenticates the event.
3. `Mdk.ProcessMessageAsync` / `AcceptWelcomeAsync` is called with the decoded bytes.
4. **DotnetMls** advances the MLS state machine.
5. The storage provider persists the new state; a snapshot is created for rollback safety.
6. Callbacks fire (`OnEpochAdvanceAsync`, `OnMemberAddedAsync`, …).

---

## Packages

| NuGet Package | Description |
|---|---|
| `MarmotCs.Core` | Main public API — `Mdk<TStorage>`, `MdkBuilder`, `MdkConfig` |
| `MarmotCs.Protocol` | Nostr event codecs (MIP-00 … MIP-03), NIP-44 / NIP-59 crypto |
| `MarmotCs.Storage.Abstractions` | Interfaces — reference when writing a custom backend |
| `MarmotCs.Storage.Memory` | Thread-safe in-memory storage (testing / short-lived) |
| `MarmotCs.Storage.Sqlite` | SQLite storage with WAL mode and auto-migration |

All packages target **net9.0** and are published to the [GitHub Packages registry](https://github.com/DavidGershony/marmot-cs/pkgs/nuget).

---

## Installation

> **Work in progress** — installation instructions will be added in a future release.

---

## Quick Start

### 1. Build an `Mdk` instance

```csharp
using MarmotCs.Core;
using MarmotCs.Storage.Memory;

var mdk = new MdkBuilder<MemoryStorageProvider>()
    .WithStorage(new MemoryStorageProvider())
    .WithConfig(MdkConfig.Default)
    .Build();
```

Using SQLite for production:

```csharp
using MarmotCs.Core;
using MarmotCs.Storage.Sqlite;

var mdk = new MdkBuilder<SqliteStorageProvider>()
    .WithStorage(new SqliteStorageProvider("marmot.db"))
    .WithConfig(MdkConfig.Default)
    .WithLogger(loggerFactory.CreateLogger<Mdk<SqliteStorageProvider>>())
    .Build();
```

### 2. Create a group

```csharp
// identity = Nostr public key bytes (32 bytes secp256k1)
var result = await mdk.CreateGroupAsync(
    identity:           aliceIdentity,
    signingPrivateKey:  aliceSigningPrivKey,
    signingPublicKey:   aliceSigningPubKey,
    groupName:          "My Group",
    relays:             ["wss://relay.example.com"]);

// result.Group   — persisted Group record
// result.KeyPackageBytes — serialised MLS key package to publish as a Nostr kind-443 event
```

### 3. Add members

Obtain Bob's serialised key package (a kind-443 Nostr event decoded via MIP-00), then:

```csharp
var updateResult = await mdk.AddMembersAsync(
    groupId:     result.Group.Id,
    keyPackages: [bobKeyPackageBytes]);

// updateResult.CommitBytes  — broadcast as a kind-445 Nostr event
// updateResult.Welcome      — send to Bob as a kind-444 Nostr event
```

### 4. Send a message

```csharp
var updateResult = await mdk.CreateMessageAsync(
    groupId: groupId,
    content: "Hello, group!");

// updateResult.CommitBytes — broadcast to the group relay
```

### 5. Process a received message

```csharp
// rawBytes = MLS ciphertext extracted from the Nostr event
var processingResult = await mdk.ProcessMessageAsync(groupId, rawBytes);

switch (processingResult)
{
    case ApplicationMessageResult msg:
        Console.WriteLine($"Message from {msg.SenderIdentityHex}: {msg.Content}");
        break;

    case CommitResult commit:
        Console.WriteLine($"Epoch advanced to {commit.NewEpoch}");
        break;

    case UnprocessableResult fail:
        Console.WriteLine($"Could not process: {fail.Reason}");
        break;
}
```

### 6. Accept a Welcome

```csharp
// welcomeBytes = MLS Welcome bytes from a kind-444 Nostr event
var preview = await mdk.PreviewWelcomeAsync(welcomeBytes);
Console.WriteLine($"Invited to: {preview.GroupName}");

var group = await mdk.AcceptWelcomeAsync(welcomeBytes, bobIdentity, bobSigningPrivKey, bobSigningPubKey);
```

---

## Configuration

```csharp
var config = new MdkConfig
{
    MaxEventAge          = TimeSpan.FromDays(7),   // ignore events older than this
    OutOfOrderTolerance  = 5,                      // buffered out-of-order messages per epoch
    MaxForwardDistance   = 1000,                   // DoS limit on ratchet advancement
    MaxSnapshotsPerGroup = 5,                      // rollback depth per group
    CipherSuite          = 0x0001,                 // only supported value (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
};
```

Use `MdkConfig.Default` for the default values shown above.

---

## Storage Backends

### In-Memory

`MemoryStorageProvider` stores all data in `ConcurrentDictionary` instances. Snapshots are deep copies. Data is lost when the process exits — ideal for tests and ephemeral sessions.

```csharp
var storage = new MemoryStorageProvider();
```

### SQLite

`SqliteStorageProvider` uses SQLite in WAL mode for concurrent reads. The schema is auto-migrated on first use. Snapshots use nested SQL transactions for atomic rollback.

```csharp
var storage = new SqliteStorageProvider("path/to/marmot.db");
```

### Custom backend

Implement `IMdkStorageProvider` (from `MarmotCs.Storage.Abstractions`) along with its sub-interfaces:

| Interface | Responsibility |
|---|---|
| `IGroupStorage` | CRUD for `Group`, `GroupRelay`, `GroupExporterSecret` |
| `IMessageStorage` | CRUD for `Message` |
| `IWelcomeStorage` | CRUD for `Welcome` |
| `IMdkStorageProvider` | Aggregates the above + snapshot/rollback lifecycle |

Key snapshot methods:

```csharp
Task<string> CreateSnapshotAsync(MlsGroupId groupId);
Task RollbackToSnapshotAsync(string snapshotId);
Task ReleaseSnapshotAsync(string snapshotId);
Task PruneSnapshotsAsync(MlsGroupId groupId, int keepCount);
```

---

## Callbacks

Implement `IMdkCallback` to receive group state change notifications:

```csharp
public class MyCallback : IMdkCallback
{
    public Task OnEpochAdvanceAsync(byte[] groupId, ulong newEpoch, CancellationToken ct = default)
    {
        Console.WriteLine($"Epoch → {newEpoch}");
        return Task.CompletedTask;
    }

    public Task OnMemberAddedAsync(byte[] groupId, byte[] memberIdentity, CancellationToken ct = default)
    {
        Console.WriteLine($"Member joined: {Convert.ToHexString(memberIdentity)}");
        return Task.CompletedTask;
    }

    public Task OnMemberRemovedAsync(byte[] groupId, byte[] memberIdentity, CancellationToken ct = default)
    {
        Console.WriteLine($"Member left: {Convert.ToHexString(memberIdentity)}");
        return Task.CompletedTask;
    }

    public Task OnRollbackAsync(byte[] groupId, ulong fromEpoch, ulong toEpoch, CancellationToken ct = default)
    {
        Console.WriteLine($"Rolled back from epoch {fromEpoch} → {toEpoch}");
        return Task.CompletedTask;
    }
}
```

Register via the builder:

```csharp
var mdk = new MdkBuilder<MemoryStorageProvider>()
    .WithStorage(new MemoryStorageProvider())
    .WithCallback(new MyCallback())
    .Build();
```

---

## Protocol Layer — Nostr / MIPs

The `MarmotCs.Protocol` project implements the Nostr wire format for Marmot group events.

| MIP | Nostr Kind | Purpose |
|---|---|---|
| **MIP-00** | 443 | Key package — publishable MLS credentials |
| **MIP-01** | Extension `0xF2EE` | Group metadata extension (name, description, image, admin keys, relays) |
| **MIP-02** | 444 | Welcome event — NIP-59 gift-wrapped for the recipient |
| **MIP-03** | 445 | Group commit event — broadcasts state transitions |

**Cryptography primitives:**

- **NIP-44 v2** — `secp256k1` ECDH → HKDF → ChaCha20-Poly1305 symmetric encryption.
- **NIP-59** — Gift wrapping: asymmetric seal for private relay delivery.
- **ExporterSecretKeyDerivation** — Derives per-epoch secrets from MLS exporter secrets for encrypting group metadata (e.g., group images).

---

## Exception Hierarchy

All library errors derive from `MdkException`:

| Exception | Thrown when |
|---|---|
| `GroupNotFoundException` | Requested group does not exist in storage |
| `InvalidMessageException` | Message fails authentication or decoding |
| `WelcomeProcessingException` | Welcome cannot be processed (wrong key, stale, etc.) |
| `CommitException` | Commit processing fails (e.g., invalid proposal) |
| `DuplicateMessageException` | Message has already been processed |
| `StaleEpochException` | Message belongs to an epoch that has already been superseded |

---

## Building & Testing

**Prerequisites:** [.NET 9 SDK](https://dotnet.microsoft.com/download)

The `DotnetMls` package is hosted on GitHub Packages. Set `GITHUB_TOKEN` to a personal access token with `read:packages` scope, then restore:

```bash
export GITHUB_TOKEN=<your_token>
dotnet restore
```

**Build:**

```bash
dotnet build --configuration Release
```

**Test:**

```bash
dotnet test --configuration Release
```

Test projects:

| Project | Scope |
|---|---|
| `MarmotCs.Protocol.Tests` | NIP-44 encryption, NIP-59 wrapping, MIP codecs |
| `MarmotCs.Storage.Tests` | `MemoryStorageProvider` and `SqliteStorageProvider` |
| `MarmotCs.Core.Tests` | Config defaults, builder validation |
| `MarmotCs.Integration.Tests` | End-to-end: group creation, messaging, Welcome flow, member management |

---

## Thread Safety

`Mdk<TStorage>` is **not thread-safe**. If you need to access an `Mdk` instance from multiple threads, provide your own external synchronization (e.g., `SemaphoreSlim` or `lock`).

---

## License

[MIT](LICENSE)
