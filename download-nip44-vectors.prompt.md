# Download NIP-44 Test Vectors

Download the official NIP-44 v2 test vectors from the block-core/nostr-client repository and save them to `tests/nip44-vectors/nip44.vectors.json`.

## Steps

1. Fetch the file from:
   ```
   https://raw.githubusercontent.com/block-core/nostr-client/master/nip44.vectors.json
   ```

2. Save the raw JSON to `tests/nip44-vectors/nip44.vectors.json` (create the directory if it doesn't exist).

3. Verify the download succeeded by checking that the file exists and is valid JSON containing a `v2` top-level key with `valid` and `invalid` sub-keys.

## Expected structure

```json
{
  "v2": {
    "valid": {
      "get_conversation_key": [...],
      "get_message_keys": { "conversation_key": "...", "keys": [...] },
      "calc_padded_len": [[input, output], ...],
      "encrypt_decrypt": [...],
      "encrypt_decrypt_long_msg": [...]
    },
    "invalid": {
      "encrypt_msg_lengths": [...],
      "get_conversation_key": [...],
      "decrypt": [...]
    }
  }
}
```

## Source

- Repository: https://github.com/block-core/nostr-client
- Reference test implementation: https://github.com/block-core/nostr-client/blob/master/test/Nostr.Client.Tests/Nip44TestVectors.cs
- NIP-44 spec: https://github.com/nostr-protocol/nips/blob/master/44.md

The SHA256 checksum of the vectors file is published in the NIP-44 specification at:
`269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040`
