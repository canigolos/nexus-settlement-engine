# Crypto Services

Encryption, signing, verification, key derivation, and payload hash helpers.

## Memory budget

The `sealEnvelope` path is the primary allocation-sensitive crypto operation.
The table below documents the worst-case live bytes at each phase for a body
of **N** bytes and **A** attachments each ≤ **M** bytes.

| Phase                  | Peak live bytes       | Notes                              |
| ---------------------- | --------------------- | ---------------------------------- |
| Key generation         | ~0 (opaque CryptoKey) |                                    |
| Body encrypt           | N + (N+16) + 12       | plaintext + ciphertext + IV (pool) |
| After body encrypt     | N+16                  | plaintext zeroed via `clearSecret` |
| Content commitment     | N+16 + 32             | ciphertext + SHA-256 digest        |
| Per-attachment encrypt | M + (M+16)            | sequential, freed per iteration    |
| Base64 body ciphertext | N+16 + ⌈(N+16)/3⌉×~4  | ciphertext zeroed after encoding   |
| **Worst-case peak**    | **≈ 2N + 28**         | body only, no attachments          |

Previous peak was ≈ 3N + 48 (plaintext + ciphertext + base64 intermediate
binary string + hex helpers all alive simultaneously).

### Cancellation

`sealEnvelope` accepts an optional `AbortSignal`. When aborted, all internal
buffer references are released and the promise rejects. Callers should pass a
signal to avoid holding large buffers when a send is cancelled.

### Buffer pool

`memory.ts` exports a `BufferPool` (and a `sharedPool` singleton) for reusing
ArrayBuffers across sequential crypto operations. Pool buffers are zeroed on
release (best-effort secret erasure) and capped at 8 entries per size bucket
to bound total pooled memory.

### Hex / Base64 encoding

`memory.ts` provides lookup-table hex encoding (O(n), no intermediate string
concatenation) and direct base64 encoding (no intermediate binary string).
These replace the per-module ad-hoc helpers that used `out += ...` concatenation
(O(n²) for hex) and `String.fromCharCode` loops (2× peak for base64).

## Authenticated attachment metadata

`attachment-metadata.ts` canonicalizes and authenticates attachment filenames,
MIME media types, byte sizes, 0-based ordering (`index` and `total_count`),
plaintext SHA-256 digests (`content_hash`), and versioned encrypted-attachment
commitments (`v1:sha256:hex:<digest>`):

- **Per-attachment AEAD (`sealAttachment` / `openAttachment`)**: Binds each
  attachment's length-prefixed descriptor (`stealth-attachment-metadata-aad-v1`)
  as AES-256-GCM Additional Authenticated Data so filename/MIME tampering, size
  spoofing, descriptor substitution, and slot reordering fail closed.
- **Ordered manifest GMAC (`sealAttachmentSet` / `openAttachmentSet` /
  `authenticateAttachmentManifest` / `verifyAttachmentManifest`)**: Authenticates
  the full ordered descriptor array and encrypted commitments under
  `stealth-attachment-manifest-aad-v1` (including empty attachment sets and
  detached ciphertext storage).
- **Cryptographic identity vs. display normalization**: Raw wire `filename` and
  `content_type` values are authenticated verbatim without silent mutation.
  Callers normalize filenames for UI rendering or download dialogs via
  `normalizeFilenameForDisplay` (`normalizeAttachmentFilenameForDisplay` /
  `sanitizeFilenameForDisplay`), which strips path traversal segments, ASCII/C1
  controls, Unicode Bidi spoofing overrides (such as `U+202E` RLO), zero-width
  characters, trailing dots/spaces, and Windows reserved device stems.
