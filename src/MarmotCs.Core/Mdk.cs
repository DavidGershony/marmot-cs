using DotnetMls.Codec;
using DotnetMls.Crypto;
using DotnetMls.Group;
using DotnetMls.Types;
using MarmotCs.Protocol.Mip00;
using MarmotCs.Protocol.Mip01;
using MarmotCs.Storage.Abstractions;
using MarmotCs.Core.Errors;
using MarmotCs.Core.Results;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MarmotCs.Core;

/// <summary>
/// The main public API for the Marmot CS.
///
/// Provides high-level operations for MLS group management, message encryption/decryption,
/// key package creation, Welcome processing, and member management. Wraps the low-level
/// MLS state machine with storage persistence, snapshot/rollback safety, and callback
/// notifications.
///
/// Thread safety: This class is NOT thread-safe. External synchronization is required
/// if accessed from multiple threads.
/// </summary>
/// <typeparam name="TStorage">The storage provider implementation type.</typeparam>
public sealed class Mdk<TStorage> where TStorage : IMdkStorageProvider
{
    private readonly TStorage _storage;
    private readonly MdkConfig _config;
    private readonly IMdkCallback? _callback;
    private readonly ILogger _logger;
    private readonly ICipherSuite _cipherSuite;
    private readonly EpochSnapshotManager _snapshots;

    // In-memory MLS group state cache (groupId hex -> MlsGroup)
    private readonly Dictionary<string, MlsGroup> _groups = new();

    // Signing key storage (in production, these would be in secure storage)
    private readonly Dictionary<string, byte[]> _signingPrivateKeys = new();
    private readonly Dictionary<string, byte[]> _hpkePrivateKeys = new();

    internal Mdk(TStorage storage, MdkConfig config, IMdkCallback? callback, ILogger? logger)
    {
        _storage = storage;
        _config = config;
        _callback = callback;
        _logger = logger ?? NullLogger.Instance;
        _cipherSuite = config.CipherSuite == 0x0001
            ? new CipherSuite0x0001()
            : throw new ArgumentException($"Unsupported cipher suite: 0x{config.CipherSuite:X4}");
        _snapshots = new EpochSnapshotManager(storage, config.MaxSnapshotsPerGroup);
    }

    // ====== Groups ======

    /// <summary>
    /// Creates a new MLS group with the caller as the sole member.
    /// Persists the group and its relays to storage, and returns a key package for publishing.
    /// </summary>
    /// <param name="identity">The creator's identity bytes (typically a Nostr public key).</param>
    /// <param name="signingPrivateKey">The creator's Ed25519 private signing key.</param>
    /// <param name="signingPublicKey">The creator's Ed25519 public signing key.</param>
    /// <param name="groupName">A human-readable name for the group.</param>
    /// <param name="relays">Nostr relay URLs for the group.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The created group record and a serialized key package for publishing.</returns>
    public async Task<GroupResult> CreateGroupAsync(
        byte[] identity,
        byte[] signingPrivateKey,
        byte[] signingPublicKey,
        string groupName,
        string[] relays,
        CancellationToken ct = default)
    {
        var mlsGroupConfig = new MlsGroupConfig
        {
            OutOfOrderTolerance = _config.OutOfOrderTolerance,
            MaxForwardDistance = _config.MaxForwardDistance
        };

        // Include NostrGroupData extension so the group name is transmitted in Welcomes
        var groupDataExt = NostrGroupDataExtension.ToExtension(new NostrGroupData
        {
            Name = groupName,
            Relays = relays
        });

        var mlsGroup = MlsGroup.CreateGroup(
            _cipherSuite, identity, signingPrivateKey, signingPublicKey,
            extensions: new[] { groupDataExt }, config: mlsGroupConfig);

        string groupIdHex = Convert.ToHexString(mlsGroup.GroupId);
        _groups[groupIdHex] = mlsGroup;
        _signingPrivateKeys[groupIdHex] = signingPrivateKey;

        var now = DateTimeOffset.UtcNow;
        var groupId = new MlsGroupId(mlsGroup.GroupId);

        var group = new Group(
            Id: groupId,
            State: GroupState.Active,
            Name: groupName,
            Image: null,
            GroupData: null,
            Epoch: mlsGroup.Epoch,
            SelfUpdate: null,
            CreatedAt: now,
            UpdatedAt: now);

        await _storage.Groups.SaveGroupAsync(group, ct);

        foreach (var relay in relays)
        {
            await _storage.Groups.SaveGroupRelayAsync(new GroupRelay(groupId, relay), ct);
        }

        // Create a key package for publishing
        var keyPackage = MlsGroup.CreateKeyPackage(
            _cipherSuite, identity, signingPrivateKey, signingPublicKey,
            out var initPriv, out var hpkePriv);
        _hpkePrivateKeys[groupIdHex] = hpkePriv;

        byte[] kpBytes = TlsCodec.Serialize(writer => keyPackage.WriteTo(writer));

        _logger.LogInformation("Created group {GroupId} with name '{GroupName}'", groupIdHex, groupName);

        return new GroupResult(group, kpBytes);
    }

    /// <summary>
    /// Retrieves a group by its identifier from storage.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The group record, or null if not found.</returns>
    public async Task<Group?> GetGroupAsync(byte[] groupId, CancellationToken ct = default)
    {
        return await _storage.Groups.GetGroupAsync(new MlsGroupId(groupId), ct);
    }

    /// <summary>
    /// Retrieves all groups, optionally filtered by state.
    /// </summary>
    /// <param name="state">Optional state filter.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A list of matching group records.</returns>
    public async Task<IReadOnlyList<Group>> GetGroupsAsync(
        GroupState? state = null, CancellationToken ct = default)
    {
        return await _storage.Groups.GetGroupsAsync(state, ct);
    }

    /// <summary>
    /// Returns the current members of the group from the in-memory MLS state.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A list of (leafIndex, identityHex) tuples.</returns>
    /// <exception cref="GroupNotFoundException">Thrown when the group is not loaded.</exception>
    public Task<List<(uint leafIndex, string identityHex)>> GetMembersAsync(
        byte[] groupId, CancellationToken ct = default)
    {
        string hex = Convert.ToHexString(groupId);
        if (!_groups.TryGetValue(hex, out var mlsGroup))
            throw new GroupNotFoundException(groupId);

        var result = mlsGroup.GetMembers()
            .Select(m => (m.leafIndex, Convert.ToHexString(m.identity)))
            .ToList();

        return Task.FromResult(result);
    }

    // ====== Members ======

    /// <summary>
    /// Adds members to the group by their key packages.
    /// Creates add proposals, commits them, and produces a Welcome for new members.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <param name="keyPackageBytesList">Serialized key packages of members to add.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The update result including commit bytes and welcome bytes.</returns>
    /// <exception cref="GroupNotFoundException">Thrown when the group is not loaded.</exception>
    /// <exception cref="CommitException">Thrown when the commit operation fails.</exception>
    public async Task<UpdateGroupResult> AddMembersAsync(
        byte[] groupId,
        byte[][] keyPackageBytesList,
        CancellationToken ct = default)
    {
        string hex = Convert.ToHexString(groupId);
        if (!_groups.TryGetValue(hex, out var mlsGroup))
            throw new GroupNotFoundException(groupId);

        var gid = new MlsGroupId(groupId);
        var snapshotId = await _snapshots.CreateSnapshotAsync(gid, ct);

        try
        {
            // Parse key packages
            var keyPackages = keyPackageBytesList.Select(bytes =>
            {
                var reader = new TlsReader(bytes);
                return KeyPackage.ReadFrom(reader);
            }).ToArray();

            // Create add proposals
            var proposals = mlsGroup.ProposeAdd(keyPackages);

            // Commit
            var (commitMsg, welcome) = mlsGroup.Commit(proposals);
            mlsGroup.MergePendingCommit();

            // Serialize
            byte[] commitBytes = TlsCodec.Serialize(writer => commitMsg.WriteTo(writer));
            byte[]? welcomeBytes = welcome != null
                ? TlsCodec.Serialize(writer => welcome.WriteTo(writer))
                : null;

            // Extract added identities
            var addedIdentities = keyPackages
                .Select(kp => kp.LeafNode.Credential is BasicCredential bc
                    ? Convert.ToHexString(bc.Identity)
                    : "")
                .Where(s => s.Length > 0)
                .ToArray();

            // Update storage
            var existingGroup = await _storage.Groups.GetGroupAsync(gid, ct);
            if (existingGroup == null)
                throw new GroupNotFoundException(groupId);

            var updatedGroup = existingGroup with
            {
                Epoch = mlsGroup.Epoch,
                UpdatedAt = DateTimeOffset.UtcNow
            };
            await _storage.Groups.UpdateGroupAsync(updatedGroup, ct);

            // Notify callback
            if (_callback != null)
            {
                await _callback.OnEpochAdvanceAsync(groupId, mlsGroup.Epoch, ct);
                foreach (var id in addedIdentities)
                {
                    await _callback.OnMemberAddedAsync(groupId, Convert.FromHexString(id), ct);
                }
            }

            await _snapshots.ReleaseAsync(snapshotId, ct);

            _logger.LogInformation(
                "Added {Count} members to group {GroupId}, epoch now {Epoch}",
                addedIdentities.Length, hex, mlsGroup.Epoch);

            return new UpdateGroupResult(
                updatedGroup, commitBytes, welcomeBytes,
                addedIdentities, Array.Empty<string>());
        }
        catch (Exception ex) when (ex is not MdkException)
        {
            _logger.LogError(ex, "Failed to add members to group {GroupId}", hex);
            await _snapshots.RollbackAsync(snapshotId, ct);
            throw new CommitException("Failed to add members", ex);
        }
    }

    /// <summary>
    /// Removes members from the group by their leaf indices.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <param name="leafIndices">The leaf indices of members to remove.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The update result including commit bytes.</returns>
    /// <exception cref="GroupNotFoundException">Thrown when the group is not loaded.</exception>
    /// <exception cref="CommitException">Thrown when the commit operation fails.</exception>
    public async Task<UpdateGroupResult> RemoveMembersAsync(
        byte[] groupId,
        uint[] leafIndices,
        CancellationToken ct = default)
    {
        string hex = Convert.ToHexString(groupId);
        if (!_groups.TryGetValue(hex, out var mlsGroup))
            throw new GroupNotFoundException(groupId);

        var gid = new MlsGroupId(groupId);
        var snapshotId = await _snapshots.CreateSnapshotAsync(gid, ct);

        try
        {
            // Get identities before removal
            var members = mlsGroup.GetMembers();
            var removedIdentities = new List<string>();
            foreach (var idx in leafIndices)
            {
                var member = members.FirstOrDefault(m => m.leafIndex == idx);
                if (member.identity != null)
                    removedIdentities.Add(Convert.ToHexString(member.identity));
            }

            // Create remove proposals and commit
            var proposals = leafIndices
                .Select(idx => mlsGroup.ProposeRemove(idx))
                .ToList();
            var (commitMsg, welcome) = mlsGroup.Commit(proposals);
            mlsGroup.MergePendingCommit();

            byte[] commitBytes = TlsCodec.Serialize(writer => commitMsg.WriteTo(writer));

            // Update storage
            var existingGroup = await _storage.Groups.GetGroupAsync(gid, ct);
            if (existingGroup == null)
                throw new GroupNotFoundException(groupId);

            var updatedGroup = existingGroup with
            {
                Epoch = mlsGroup.Epoch,
                UpdatedAt = DateTimeOffset.UtcNow
            };
            await _storage.Groups.UpdateGroupAsync(updatedGroup, ct);

            // Notify callback
            if (_callback != null)
            {
                await _callback.OnEpochAdvanceAsync(groupId, mlsGroup.Epoch, ct);
                foreach (var id in removedIdentities)
                {
                    await _callback.OnMemberRemovedAsync(groupId, Convert.FromHexString(id), ct);
                }
            }

            await _snapshots.ReleaseAsync(snapshotId, ct);

            _logger.LogInformation(
                "Removed {Count} members from group {GroupId}, epoch now {Epoch}",
                removedIdentities.Count, hex, mlsGroup.Epoch);

            return new UpdateGroupResult(
                updatedGroup, commitBytes, null,
                Array.Empty<string>(), removedIdentities.ToArray());
        }
        catch (Exception ex) when (ex is not MdkException)
        {
            _logger.LogError(ex, "Failed to remove members from group {GroupId}", hex);
            await _snapshots.RollbackAsync(snapshotId, ct);
            throw new CommitException("Failed to remove members", ex);
        }
    }

    // ====== MIP-03 Crypto ======

    /// <summary>
    /// Returns the MIP-03 exporter secret for the given group.
    /// This is <c>MLS-Exporter("marmot", "group-event", 32)</c> from the current epoch.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <returns>The 32-byte exporter secret.</returns>
    /// <exception cref="GroupNotFoundException">Thrown when the group is not loaded.</exception>
    public byte[] GetExporterSecret(byte[] groupId)
    {
        string hex = Convert.ToHexString(groupId);
        if (!_groups.TryGetValue(hex, out var mlsGroup))
            throw new GroupNotFoundException(groupId);

        return mlsGroup.ExportSecret(
            Mip03Crypto.ExporterLabel,
            Mip03Crypto.ExporterContext,
            Mip03Crypto.ExporterLength);
    }

    // ====== Messages ======

    /// <summary>
    /// Encrypts a plaintext message for the group as an MLS PrivateMessage.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <param name="plaintext">The plaintext message bytes.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The serialized PrivateMessage bytes ready for transmission.</returns>
    /// <exception cref="GroupNotFoundException">Thrown when the group is not loaded.</exception>
    public async Task<byte[]> CreateMessageAsync(
        byte[] groupId,
        byte[] plaintext,
        CancellationToken ct = default)
    {
        string hex = Convert.ToHexString(groupId);
        if (!_groups.TryGetValue(hex, out var mlsGroup))
            throw new GroupNotFoundException(groupId);

        var privateMsg = mlsGroup.EncryptApplicationMessage(plaintext);
        byte[] msgBytes = TlsCodec.Serialize(writer => privateMsg.WriteTo(writer));

        // Determine sender identity
        var members = mlsGroup.GetMembers();
        var self = members.FirstOrDefault(m => m.leafIndex == mlsGroup.MyLeafIndex);
        byte[] senderIdentity = self.identity ?? Array.Empty<byte>();

        // Save to storage
        var gid = new MlsGroupId(groupId);
        var message = new Message(
            Id: Guid.NewGuid().ToString(),
            GroupId: gid,
            SenderIdentity: senderIdentity,
            Content: plaintext,
            Epoch: mlsGroup.Epoch,
            State: MessageState.Pending,
            CreatedAt: DateTimeOffset.UtcNow);

        await _storage.Messages.SaveMessageAsync(message, ct);

        return msgBytes;
    }

    /// <summary>
    /// Processes a received MLS message (application message or commit).
    /// Handles decryption, commit processing, deduplication, and storage.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <param name="messageBytes">The serialized MLS message bytes.</param>
    /// <param name="eventId">The Nostr event ID for deduplication.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The processing result.</returns>
    /// <exception cref="GroupNotFoundException">Thrown when the group is not loaded.</exception>
    /// <exception cref="DuplicateMessageException">Thrown when the event has already been processed.</exception>
    public async Task<MessageProcessingResult> ProcessMessageAsync(
        byte[] groupId,
        byte[] messageBytes,
        string eventId,
        CancellationToken ct = default)
    {
        string hex = Convert.ToHexString(groupId);
        if (!_groups.TryGetValue(hex, out var mlsGroup))
            throw new GroupNotFoundException(groupId);

        var gid = new MlsGroupId(groupId);

        // Check for duplicates
        var existing = await _storage.Messages.GetProcessedMessageAsync(eventId, ct);
        if (existing != null)
            throw new DuplicateMessageException(eventId);

        try
        {
            // Parse message: either wrapped in MLSMessage envelope or raw TLS bytes
            PrivateMessage? privateMsg = null;
            PublicMessage? publicMsg = null;

            if (messageBytes.Length >= 4 && messageBytes[0] == 0x00 && messageBytes[1] == 0x01)
            {
                // MLSMessage envelope — the wire_format tells us the type directly
                var envReader = new TlsReader(messageBytes);
                var mlsMsg = MlsMessage.ReadFrom(envReader);
                switch (mlsMsg.Body)
                {
                    case PrivateMessage pm:
                        privateMsg = pm;
                        break;
                    case PublicMessage pub:
                        publicMsg = pub;
                        break;
                    default:
                        return new UnprocessableResult(
                            $"Unsupported MLSMessage wire format: {mlsMsg.WireFormat}");
                }
            }
            else
            {
                // Raw TLS bytes — try PrivateMessage first, fall back to PublicMessage
                try
                {
                    var reader = new TlsReader(messageBytes);
                    privateMsg = PrivateMessage.ReadFrom(reader);
                }
                catch (Exception parseEx)
                {
                    _logger.LogDebug(parseEx, "Not a PrivateMessage, trying PublicMessage");
                    var reader = new TlsReader(messageBytes);
                    publicMsg = PublicMessage.ReadFrom(reader);
                }
            }

            // Process based on parsed type
            if (privateMsg != null)
            {
                var (plaintext, senderLeaf) = mlsGroup.DecryptApplicationMessage(privateMsg);

                var members = mlsGroup.GetMembers();
                var senderMember = members.FirstOrDefault(m => m.leafIndex == senderLeaf);
                byte[] senderIdentity = senderMember.identity ?? Array.Empty<byte>();

                var message = new Message(
                    Id: Guid.NewGuid().ToString(),
                    GroupId: gid,
                    SenderIdentity: senderIdentity,
                    Content: plaintext,
                    Epoch: mlsGroup.Epoch,
                    State: MessageState.Delivered,
                    CreatedAt: DateTimeOffset.UtcNow);

                await _storage.Messages.SaveMessageAsync(message, ct);
                await _storage.Messages.SaveProcessedMessageAsync(
                    new ProcessedMessage(eventId, gid, ProcessedMessageState.Completed, DateTimeOffset.UtcNow), ct);

                return new ApplicationMessageResult(message);
            }

            if (publicMsg != null)
            {
                if (publicMsg.Content.ContentType == ContentType.Commit)
                {
                    var snapshotId = await _snapshots.CreateSnapshotAsync(gid, ct);
                    try
                    {
                        mlsGroup.ProcessCommit(publicMsg);

                        var existingGroup = await _storage.Groups.GetGroupAsync(gid, ct);
                        if (existingGroup != null)
                        {
                            var updatedGroup = existingGroup with
                            {
                                Epoch = mlsGroup.Epoch,
                                UpdatedAt = DateTimeOffset.UtcNow
                            };
                            await _storage.Groups.UpdateGroupAsync(updatedGroup, ct);
                        }

                        await _storage.Messages.SaveProcessedMessageAsync(
                            new ProcessedMessage(eventId, gid, ProcessedMessageState.Completed, DateTimeOffset.UtcNow), ct);

                        if (_callback != null)
                            await _callback.OnEpochAdvanceAsync(groupId, mlsGroup.Epoch, ct);

                        await _snapshots.ReleaseAsync(snapshotId, ct);

                        var group = await _storage.Groups.GetGroupAsync(gid, ct);
                        return new CommitResult(group!);
                    }
                    catch (Exception commitEx)
                    {
                        _logger.LogWarning(commitEx, "Commit processing failed for group {GroupId}, rolling back", hex);
                        await _snapshots.RollbackAsync(snapshotId, ct);
                        throw;
                    }
                }

                return new UnprocessableResult(
                    $"PublicMessage with unsupported ContentType: {publicMsg.Content.ContentType}");
            }

            return new UnprocessableResult("Could not parse message as PrivateMessage or PublicMessage");
        }
        catch (DuplicateMessageException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to process message {EventId} for group {GroupId}", eventId, hex);

            await _storage.Messages.SaveProcessedMessageAsync(
                new ProcessedMessage(eventId, gid, ProcessedMessageState.Failed, DateTimeOffset.UtcNow), ct);

            return new UnprocessableResult(ex.Message);
        }
    }

    /// <summary>
    /// Retrieves a message by its identifier from storage.
    /// </summary>
    public async Task<Message?> GetMessageAsync(string id, CancellationToken ct = default)
        => await _storage.Messages.GetMessageAsync(id, ct);

    /// <summary>
    /// Retrieves messages for a group with optional pagination and sorting.
    /// </summary>
    public async Task<IReadOnlyList<Message>> GetMessagesAsync(
        byte[] groupId,
        Pagination? pagination = null,
        MessageSortOrder order = MessageSortOrder.Ascending,
        CancellationToken ct = default)
        => await _storage.Messages.GetMessagesAsync(new MlsGroupId(groupId), pagination, order, ct);

    /// <summary>
    /// Retrieves the last message in a group.
    /// </summary>
    public async Task<Message?> GetLastMessageAsync(byte[] groupId, CancellationToken ct = default)
        => await _storage.Messages.GetLastMessageAsync(new MlsGroupId(groupId), ct);

    // ====== Key Packages ======

    /// <summary>
    /// Creates a new MLS key package for publishing to Nostr relays (kind 443).
    /// </summary>
    /// <param name="identity">The member's identity bytes.</param>
    /// <param name="signingPrivateKey">The member's Ed25519 private signing key.</param>
    /// <param name="signingPublicKey">The member's Ed25519 public signing key.</param>
    /// <param name="relays">Relay URLs for key package discovery.</param>
    /// <returns>The serialized key package bytes and Nostr event tags.</returns>
    public (byte[] keyPackageBytes, string[][] tags) CreateKeyPackage(
        byte[] identity,
        byte[] signingPrivateKey,
        byte[] signingPublicKey,
        string[] relays)
    {
        var keyPackage = MlsGroup.CreateKeyPackage(
            _cipherSuite, identity, signingPrivateKey, signingPublicKey,
            out var initPriv, out var hpkePriv);

        byte[] kpBytes = TlsCodec.Serialize(writer => keyPackage.WriteTo(writer));

        var (content, tags) = KeyPackageEventBuilder.BuildKeyPackageEvent(
            kpBytes, Convert.ToHexString(identity), relays);

        // Note: In production, initPriv and hpkePriv should be persisted securely
        // for later Welcome processing.

        return (kpBytes, tags);
    }

    /// <summary>
    /// Parses a received Nostr kind 443 key package event.
    /// </summary>
    /// <param name="content">The base64-encoded event content.</param>
    /// <param name="tags">The event tags.</param>
    /// <returns>The parsed key package bytes, KeyPackageRef hex, and relay URLs.</returns>
    public (byte[] keyPackageBytes, string keyPackageRefHex, string[] relays) ParseKeyPackageEvent(
        string content, string[][] tags)
    {
        return KeyPackageEventParser.ParseKeyPackageEvent(content, tags);
    }

    // ====== Welcomes ======

    /// <summary>
    /// Previews a Welcome message without fully joining the group.
    /// Decrypts the Welcome to extract group metadata and member list,
    /// and stores the Welcome for later acceptance.
    /// </summary>
    /// <param name="welcomeBytes">The serialized MLS Welcome bytes.</param>
    /// <param name="myKeyPackageBytes">The serialized key package that was used when being added.</param>
    /// <param name="myInitPrivateKey">The init HPKE private key from CreateKeyPackage.</param>
    /// <param name="myHpkePrivateKey">The leaf HPKE private key from CreateKeyPackage.</param>
    /// <param name="mySigningPrivateKey">The member's private signing key.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A preview of the Welcome with group info and member list.</returns>
    public async Task<WelcomePreview> PreviewWelcomeAsync(
        byte[] welcomeBytes,
        byte[] myKeyPackageBytes,
        byte[] myInitPrivateKey,
        byte[] myHpkePrivateKey,
        byte[] mySigningPrivateKey,
        CancellationToken ct = default)
    {
        // Parse and decrypt to preview without keeping the group state
        var reader = new TlsReader(welcomeBytes);
        var welcome = DotnetMls.Types.Welcome.ReadFrom(reader);

        var kpReader = new TlsReader(myKeyPackageBytes);
        var myKeyPackage = KeyPackage.ReadFrom(kpReader);

        // Process to get group info
        var mlsGroup = MlsGroup.ProcessWelcome(
            _cipherSuite, welcome, myKeyPackage,
            myInitPrivateKey, myHpkePrivateKey, mySigningPrivateKey);

        var memberIdentities = mlsGroup.GetMembers()
            .Select(m => Convert.ToHexString(m.identity))
            .ToArray();

        // Try to get group name from extensions
        string groupName = "";
        foreach (var ext in mlsGroup.GroupContext.Extensions)
        {
            if (ext.ExtensionType == NostrGroupDataExtension.ExtensionType)
            {
                _logger.LogDebug("0xF2EE extension data ({Len} bytes): {Hex}",
                    ext.ExtensionData.Length,
                    Convert.ToHexString(ext.ExtensionData[..Math.Min(128, ext.ExtensionData.Length)]));
                try
                {
                    var ngd = NostrGroupDataExtension.FromExtension(ext);
                    groupName = ngd.Name;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to decode NostrGroupData from 0xF2EE extension ({Len} bytes)", ext.ExtensionData.Length);
                }
                break;
            }
        }

        var welcomeId = Guid.NewGuid().ToString();

        // Save welcome for later acceptance
        var gid = new MlsGroupId(mlsGroup.GroupId);
        var welcomeRecord = new Storage.Abstractions.Welcome(
            Id: welcomeId,
            GroupId: gid,
            WelcomeData: welcomeBytes,
            State: WelcomeState.Pending,
            GroupData: null,
            SenderNostrPubkey: null,
            CreatedAt: DateTimeOffset.UtcNow);

        await _storage.Welcomes.SaveWelcomeAsync(welcomeRecord, ct);

        return new WelcomePreview(welcomeId, mlsGroup.GroupId, groupName, memberIdentities, null);
    }

    /// <summary>
    /// Accepts a previously previewed Welcome, joining the group.
    /// Processes the Welcome to construct the MLS group state and persists to storage.
    /// </summary>
    /// <param name="welcomeId">The welcome identifier from PreviewWelcomeAsync.</param>
    /// <param name="myKeyPackageBytes">The serialized key package that was used when being added.</param>
    /// <param name="myInitPrivateKey">The init HPKE private key from CreateKeyPackage.</param>
    /// <param name="myHpkePrivateKey">The leaf HPKE private key from CreateKeyPackage.</param>
    /// <param name="mySigningPrivateKey">The member's private signing key.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The joined group record.</returns>
    /// <exception cref="WelcomeProcessingException">Thrown when the welcome is not found or processing fails.</exception>
    public async Task<Group> AcceptWelcomeAsync(
        string welcomeId,
        byte[] myKeyPackageBytes,
        byte[] myInitPrivateKey,
        byte[] myHpkePrivateKey,
        byte[] mySigningPrivateKey,
        CancellationToken ct = default)
    {
        var welcomeRecord = await _storage.Welcomes.GetWelcomeAsync(welcomeId, ct)
            ?? throw new WelcomeProcessingException($"Welcome {welcomeId} not found");

        var reader = new TlsReader(welcomeRecord.WelcomeData);
        var welcome = DotnetMls.Types.Welcome.ReadFrom(reader);

        var kpReader = new TlsReader(myKeyPackageBytes);
        var myKeyPackage = KeyPackage.ReadFrom(kpReader);

        var mlsGroupConfig = new MlsGroupConfig
        {
            OutOfOrderTolerance = _config.OutOfOrderTolerance,
            MaxForwardDistance = _config.MaxForwardDistance
        };

        var mlsGroup = MlsGroup.ProcessWelcome(
            _cipherSuite, welcome, myKeyPackage,
            myInitPrivateKey, myHpkePrivateKey, mySigningPrivateKey, mlsGroupConfig);

        string hex = Convert.ToHexString(mlsGroup.GroupId);
        _groups[hex] = mlsGroup;
        _signingPrivateKeys[hex] = mySigningPrivateKey;
        _hpkePrivateKeys[hex] = myHpkePrivateKey;

        var gid = new MlsGroupId(mlsGroup.GroupId);
        var now = DateTimeOffset.UtcNow;

        // Try to get group name from extensions
        string groupName = "";
        foreach (var ext in mlsGroup.GroupContext.Extensions)
        {
            if (ext.ExtensionType == NostrGroupDataExtension.ExtensionType)
            {
                try
                {
                    var ngd = NostrGroupDataExtension.FromExtension(ext);
                    groupName = ngd.Name;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to decode NostrGroupData from 0xF2EE extension in AcceptWelcome");
                }
                break;
            }
        }

        var group = new Group(
            Id: gid,
            State: GroupState.Active,
            Name: groupName,
            Image: null,
            GroupData: null,
            Epoch: mlsGroup.Epoch,
            SelfUpdate: null,
            CreatedAt: now,
            UpdatedAt: now);

        await _storage.Groups.SaveGroupAsync(group, ct);

        // Update welcome state
        var updatedWelcome = welcomeRecord with { State = WelcomeState.Accepted };
        await _storage.Welcomes.UpdateWelcomeAsync(updatedWelcome, ct);

        _logger.LogInformation("Accepted welcome {WelcomeId}, joined group {GroupId}", welcomeId, hex);

        return group;
    }

    /// <summary>
    /// Declines a previously previewed Welcome.
    /// </summary>
    /// <param name="welcomeId">The welcome identifier from PreviewWelcomeAsync.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="WelcomeProcessingException">Thrown when the welcome is not found.</exception>
    public async Task DeclineWelcomeAsync(string welcomeId, CancellationToken ct = default)
    {
        var welcomeRecord = await _storage.Welcomes.GetWelcomeAsync(welcomeId, ct)
            ?? throw new WelcomeProcessingException($"Welcome {welcomeId} not found");

        var updated = welcomeRecord with { State = WelcomeState.Declined };
        await _storage.Welcomes.UpdateWelcomeAsync(updated, ct);
    }

    /// <summary>
    /// Retrieves a Welcome record by its identifier.
    /// </summary>
    public async Task<Storage.Abstractions.Welcome?> GetWelcomeAsync(
        string id, CancellationToken ct = default)
        => await _storage.Welcomes.GetWelcomeAsync(id, ct);

    /// <summary>
    /// Retrieves all pending Welcome records.
    /// </summary>
    public async Task<IReadOnlyList<Storage.Abstractions.Welcome>> GetPendingWelcomesAsync(
        CancellationToken ct = default)
        => await _storage.Welcomes.GetPendingWelcomesAsync(ct);

    // ====== Relays ======

    /// <summary>
    /// Retrieves the relay URLs associated with a group.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The list of group relay records.</returns>
    public async Task<IReadOnlyList<GroupRelay>> GetRelaysAsync(
        byte[] groupId, CancellationToken ct = default)
        => await _storage.Groups.GetGroupRelaysAsync(new MlsGroupId(groupId), ct);

    // ====== Self Update ======

    /// <summary>
    /// Performs a self-update commit to rotate the local member's key material.
    /// This provides forward secrecy by replacing the leaf's HPKE key pair.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The update result with commit bytes to publish.</returns>
    /// <exception cref="GroupNotFoundException">Thrown when the group is not loaded.</exception>
    /// <exception cref="CommitException">Thrown when the self-update fails.</exception>
    public async Task<UpdateGroupResult> SelfUpdateAsync(
        byte[] groupId, CancellationToken ct = default)
    {
        string hex = Convert.ToHexString(groupId);
        if (!_groups.TryGetValue(hex, out var mlsGroup))
            throw new GroupNotFoundException(groupId);

        var gid = new MlsGroupId(groupId);
        var snapshotId = await _snapshots.CreateSnapshotAsync(gid, ct);

        try
        {
            var (proposal, newHpkePriv) = mlsGroup.ProposeSelfUpdate();
            var (commitMsg, welcome) = mlsGroup.Commit(
                new List<Proposal> { proposal });
            mlsGroup.MergePendingCommit();
            _hpkePrivateKeys[hex] = newHpkePriv;

            byte[] commitBytes = TlsCodec.Serialize(writer => commitMsg.WriteTo(writer));

            var existingGroup = await _storage.Groups.GetGroupAsync(gid, ct);
            if (existingGroup == null)
                throw new GroupNotFoundException(groupId);

            var updatedGroup = existingGroup with
            {
                Epoch = mlsGroup.Epoch,
                SelfUpdate = new SelfUpdateState.CompletedAt(DateTimeOffset.UtcNow),
                UpdatedAt = DateTimeOffset.UtcNow
            };
            await _storage.Groups.UpdateGroupAsync(updatedGroup, ct);

            if (_callback != null)
                await _callback.OnEpochAdvanceAsync(groupId, mlsGroup.Epoch, ct);

            await _snapshots.ReleaseAsync(snapshotId, ct);

            _logger.LogInformation(
                "Self-updated in group {GroupId}, epoch now {Epoch}", hex, mlsGroup.Epoch);

            return new UpdateGroupResult(
                updatedGroup, commitBytes, null,
                Array.Empty<string>(), Array.Empty<string>());
        }
        catch (Exception ex) when (ex is not MdkException)
        {
            _logger.LogError(ex, "Failed to self-update in group {GroupId}", hex);
            await _snapshots.RollbackAsync(snapshotId, ct);
            throw new CommitException("Failed to self-update", ex);
        }
    }

    // ====== Group State Export/Import ======

    /// <summary>
    /// Exports the MLS group state for the specified group as a byte array for persistence.
    /// Includes the MlsGroup binary state plus Mdk-level signing/HPKE private keys.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <returns>The serialized group state bytes.</returns>
    /// <exception cref="GroupNotFoundException">Thrown when the group is not loaded.</exception>
    public byte[] ExportGroupState(byte[] groupId)
    {
        string hex = Convert.ToHexString(groupId);
        if (!_groups.TryGetValue(hex, out var mlsGroup))
            throw new GroupNotFoundException(groupId);

        byte[] groupState = mlsGroup.Export();

        // Wrap with Mdk-level keys
        return TlsCodec.Serialize(writer =>
        {
            writer.WriteUint8(1); // version
            writer.WriteOpaqueV(groupState);
            writer.WriteOpaqueV(_signingPrivateKeys.TryGetValue(hex, out var sk) ? sk : Array.Empty<byte>());
            writer.WriteOpaqueV(_hpkePrivateKeys.TryGetValue(hex, out var hk) ? hk : Array.Empty<byte>());
        });
    }

    /// <summary>
    /// Imports a previously exported MLS group state, restoring the group to the in-memory cache.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <param name="stateBytes">The serialized state bytes from ExportGroupState.</param>
    /// <exception cref="InvalidOperationException">Thrown when the state cannot be parsed.</exception>
    public void ImportGroupState(byte[] groupId, byte[] stateBytes)
    {
        var reader = new TlsReader(stateBytes);
        byte version = reader.ReadUint8();
        if (version != 1)
            throw new InvalidOperationException($"Unsupported Mdk group state version: {version}");

        byte[] groupState = reader.ReadOpaqueV();
        byte[] signingKey = reader.ReadOpaqueV();
        byte[] hpkeKey = reader.ReadOpaqueV();

        var mlsGroup = MlsGroup.Import(groupState, _cipherSuite);

        string hex = Convert.ToHexString(groupId);
        _groups[hex] = mlsGroup;
        if (signingKey.Length > 0)
            _signingPrivateKeys[hex] = signingKey;
        if (hpkeKey.Length > 0)
            _hpkePrivateKeys[hex] = hpkeKey;

        _logger.LogInformation("Imported group state for {GroupId}, epoch={Epoch}", hex, mlsGroup.Epoch);
    }

    // ====== Merge/Clear pending commit ======

    /// <summary>
    /// Merges a pending commit, transitioning the group to the new epoch.
    /// Call this after the commit has been confirmed by the relay.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <exception cref="GroupNotFoundException">Thrown when the group is not loaded.</exception>
    public void MergePendingCommit(byte[] groupId)
    {
        string hex = Convert.ToHexString(groupId);
        if (!_groups.TryGetValue(hex, out var mlsGroup))
            throw new GroupNotFoundException(groupId);

        mlsGroup.MergePendingCommit();
    }

    /// <summary>
    /// Clears a pending commit without applying it.
    /// Call this when a commit was rejected or superseded.
    /// </summary>
    /// <param name="groupId">The group identifier bytes.</param>
    /// <exception cref="GroupNotFoundException">Thrown when the group is not loaded.</exception>
    public void ClearPendingCommit(byte[] groupId)
    {
        string hex = Convert.ToHexString(groupId);
        if (!_groups.TryGetValue(hex, out var mlsGroup))
            throw new GroupNotFoundException(groupId);

        mlsGroup.ClearPendingCommit();
    }
}
