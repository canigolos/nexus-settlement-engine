/**
 * Authenticated attachment metadata and display-safe filename normalization (#50).
 *
 * Attachment filenames, MIME types, byte sizes, ordering indices, plaintext
 * SHA-256 hashes, and versioned encrypted-attachment commitments are treated as
 * protected metadata bound via domain-separated, length-prefixed Additional
 * Authenticated Data (AAD) under AES-256-GCM.
 *
 * Cryptographic identity vs. display normalization:
 * - Cryptographic canonicalization and AEAD verification operate on the exact
 *   raw UTF-8 strings carried on the wire (validating structural bounds and
 *   rejecting ill-formed lone surrogates so UTF-8 encoding is injective).
 *   Unsafe path segments, Unicode bidirectional overrides, or trailing dots are
 *   NEVER stripped inside cryptographic identity, preventing two distinct wire
 *   filenames from colliding on the same authentication tag.
 * - Display normalization (`normalizeFilenameForDisplay` /
 *   `sanitizeFilenameForDisplay`) is applied strictly before rendering or saving
 *   in the client UI.
 */

import { GCM_NONCE_BYTES, GCM_TAG_BYTES, joinTag, sealAead, openAead } from "./aead";
import { createCommitment } from "./commitment";
import { constantTimeEqual } from "./constant-time";
import { canonicalize } from "./jcs";
import {
  MAX_ATTACHMENTS,
  MAX_ATTACHMENT_BYTES,
  MAX_CONTENT_TYPE_BYTES,
  MAX_FILENAME_BYTES,
} from "./limits";
import { clearSecret, toBase64, toHex } from "./memory";

export const ATTACHMENT_METADATA_AAD_DOMAIN = "stealth-attachment-metadata-aad-v1" as const;
export const ATTACHMENT_MANIFEST_AAD_DOMAIN = "stealth-attachment-manifest-aad-v1" as const;
export const ATTACHMENT_MANIFEST_VERSION = "stealth-att-manifest.v1" as const;
export const ATTACHMENT_AEAD_ALGORITHM = "AES-256-GCM" as const;

/** Maximum character length emitted by display filename normalization. */
export const MAX_DISPLAY_FILENAME_LENGTH = 128;

/** Fallback filename returned when an input collapses to an empty/unsafe name. */
export const DEFAULT_DISPLAY_FILENAME = "unnamed_attachment" as const;

const SHA256_BYTES = 32;
const MIME_TYPE_REGEX =
  /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+(?:\s*;\s*[A-Za-z0-9!#$&^_.+-]+=(?:[A-Za-z0-9!#$&^_.+-]+|"(?:[^"\\]|\\.)*"))*$/;
const WINDOWS_RESERVED_BASENAME_REGEX =
  /^(?:con|prn|aux|nul|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])$/i;

export type AttachmentMetadataErrorCode =
  | "crypto_validation_error"
  | "crypto_integrity_error"
  | "crypto_commitment_error"
  | "crypto_decrypt_error";

/** Minimal non-secret error carrying a stable cryptographic error code. */
export class AttachmentMetadataError extends Error {
  readonly code: AttachmentMetadataErrorCode;

  constructor(code: AttachmentMetadataErrorCode, message: string) {
    super(message);
    this.name = "AttachmentMetadataError";
    this.code = code;
  }
}

export interface AttachmentDescriptor {
  filename: string;
  content_type: string;
  size_bytes: number;
  content_hash: string;
  /**
   * Optional versioned commitment (`v1:sha256:hex:<64-hex>`) over the encrypted
   * attachment bytes (`ciphertext || tag`).
   */
  encrypted_commitment?: string;
}

export interface AuthenticatedAttachmentDescriptor {
  readonly index: number;
  readonly total_count: number;
  readonly filename: string;
  readonly content_type: string;
  readonly size_bytes: number;
  readonly content_hash: string;
  readonly encrypted_commitment: string;
}

export interface AttachmentEncryptionMetadata {
  readonly algorithm: typeof ATTACHMENT_AEAD_ALGORITHM;
  /** 12-byte AES-GCM IV encoded as 24 lowercase hex characters. */
  readonly nonce: string;
  /** 16-byte AES-GCM authentication tag encoded as 32 lowercase hex characters. */
  readonly mac: string;
}

export interface AuthenticatedEncryptedAttachment {
  readonly descriptor: AuthenticatedAttachmentDescriptor;
  /** Base64-encoded ciphertext excluding the trailing 16-byte AES-GCM tag. */
  readonly ciphertext: string;
  readonly encryption_metadata: AttachmentEncryptionMetadata;
}

export interface AuthenticatedAttachmentManifest {
  readonly version: typeof ATTACHMENT_MANIFEST_VERSION;
  readonly algorithm: typeof ATTACHMENT_AEAD_ALGORITHM;
  readonly nonce: string;
  readonly mac: string;
  readonly descriptors: readonly AuthenticatedAttachmentDescriptor[];
}

export interface AuthenticatedAttachmentSet {
  readonly manifest: AuthenticatedAttachmentManifest;
  readonly attachments: readonly AuthenticatedEncryptedAttachment[];
}

export interface SealAttachmentInput {
  readonly filename: string;
  readonly content_type: string;
  readonly data: ArrayBuffer | Uint8Array;
  /** Declared byte size; if provided, must match `data.byteLength` exactly. */
  readonly size_bytes?: number;
  /** Declared SHA-256 plaintext hex digest; if provided, must match `SHA-256(data)`. */
  readonly content_hash?: string;
  /** 0-based position in an ordered attachment list (default: 0). */
  readonly index?: number;
  /** Total count of attachments in the ordered list (default: 1). */
  readonly total_count?: number;
  /** Optional 12-byte nonce override for deterministic vector tests. */
  readonly nonce?: Uint8Array;
  /** Optional caller context (e.g. envelope ID or header AAD) bound into AAD. */
  readonly context?: Uint8Array | string;
}

export interface OpenAttachmentOptions {
  /** Expected 0-based ordering index; mismatches fail closed. */
  readonly expectedIndex?: number;
  /** Expected total attachment count; mismatches fail closed. */
  readonly expectedTotalCount?: number;
  /** Optional caller context bound during sealing. */
  readonly context?: Uint8Array | string;
}

export interface OpenedAuthenticatedAttachment {
  readonly index: number;
  readonly total_count: number;
  /** Exact wire filename authenticated by AEAD (cryptographic identity). */
  readonly filename: string;
  /** Normalized filename safe for UI rendering and save dialogs. */
  readonly displayFilename: string;
  readonly content_type: string;
  readonly size_bytes: number;
  readonly content_hash: string;
  readonly encrypted_commitment: string;
  readonly bytes: Uint8Array<ArrayBuffer>;
}

export interface SealAttachmentSetOptions {
  /** Optional caller context bound to both per-attachment AAD and the manifest GMAC. */
  readonly context?: Uint8Array | string;
  /** Optional 12-byte manifest nonce override for deterministic testing. */
  readonly manifestNonce?: Uint8Array;
}

export interface OpenAttachmentSetOptions {
  /** Optional caller context bound during `sealAttachmentSet`. */
  readonly context?: Uint8Array | string;
}

const utf8Encoder = new TextEncoder();

function toArrayBufferBytes(view: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(view.byteLength));
  out.set(view);
  return out;
}

function toBytes(source: ArrayBuffer | Uint8Array): Uint8Array<ArrayBuffer> {
  if (source instanceof Uint8Array) {
    return toArrayBufferBytes(source);
  }
  if (source instanceof ArrayBuffer) {
    return toArrayBufferBytes(new Uint8Array(source));
  }
  throw new AttachmentMetadataError(
    "crypto_validation_error",
    "attachment data must be an ArrayBuffer or Uint8Array",
  );
}

function fromHexStrict(
  hex: string,
  expectedByteLength: number,
  fieldName: string,
): Uint8Array<ArrayBuffer> {
  if (typeof hex !== "string" || hex.length !== expectedByteLength * 2) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `invalid ${fieldName}: expected ${expectedByteLength * 2} hex characters`,
    );
  }
  const out = new Uint8Array(new ArrayBuffer(expectedByteLength));
  for (let i = 0; i < expectedByteLength; i += 1) {
    const hi = hex.charCodeAt(i * 2);
    const lo = hex.charCodeAt(i * 2 + 1);
    const hiVal = hexNibble(hi);
    const loVal = hexNibble(lo);
    if (hiVal < 0 || loVal < 0) {
      throw new AttachmentMetadataError(
        "crypto_validation_error",
        `invalid ${fieldName}: non-hex character encountered`,
      );
    }
    out[i] = (hiVal << 4) | loVal;
  }
  return out;
}

function hexNibble(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  return -1;
}

function fromBase64Strict(b64: string, fieldName: string): Uint8Array<ArrayBuffer> {
  if (typeof b64 !== "string") {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `invalid ${fieldName}: expected base64 string`,
    );
  }
  if (b64.length === 0) {
    return new Uint8Array(new ArrayBuffer(0));
  }
  if (b64.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `invalid ${fieldName}: malformed base64 encoding`,
    );
  }
  let binary: string;
  try {
    binary = atob(b64);
  } catch {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `invalid ${fieldName}: base64 decode failed`,
    );
  }
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function hasLoneSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 >= value.length) return true;
      const next = value.charCodeAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function hasAsciiControlChars(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

async function sha256Bytes(data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const buf = toArrayBufferBytes(data);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return toArrayBufferBytes(new Uint8Array(digest));
}

function encodeContextBytes(context?: Uint8Array | string): Uint8Array {
  if (context === undefined) {
    return new Uint8Array(0);
  }
  if (typeof context === "string") {
    if (hasLoneSurrogate(context)) {
      throw new AttachmentMetadataError(
        "crypto_validation_error",
        "context string contains an unpaired UTF-16 surrogate",
      );
    }
    return utf8Encoder.encode(context);
  }
  if (context instanceof Uint8Array) {
    return context;
  }
  throw new AttachmentMetadataError(
    "crypto_validation_error",
    "context must be a string or Uint8Array",
  );
}

/**
 * Validates raw filename bounds for cryptographic binding without mutating,
 * trimming, or normalizing the string.
 */
export function validateRawAttachmentFilename(filename: unknown): string {
  if (typeof filename !== "string" || filename.length === 0) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment filename must be a non-empty string",
    );
  }
  if (hasLoneSurrogate(filename)) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment filename contains an unpaired UTF-16 surrogate",
    );
  }
  const encoded = utf8Encoder.encode(filename);
  if (encoded.byteLength > MAX_FILENAME_BYTES) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `attachment filename exceeds ${MAX_FILENAME_BYTES} UTF-8 bytes`,
    );
  }
  return filename;
}

/**
 * Validates MIME media-type syntax and bounds without mutating casing or
 * parameters inside cryptographic identity.
 */
export function validateAttachmentMimeType(contentType: unknown): string {
  if (typeof contentType !== "string" || contentType.length === 0) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment content_type must be a non-empty string",
    );
  }
  if (hasLoneSurrogate(contentType) || hasAsciiControlChars(contentType)) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment content_type contains invalid control or surrogate characters",
    );
  }
  const encoded = utf8Encoder.encode(contentType);
  if (encoded.byteLength > MAX_CONTENT_TYPE_BYTES) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `attachment content_type exceeds ${MAX_CONTENT_TYPE_BYTES} UTF-8 bytes`,
    );
  }
  if (!MIME_TYPE_REGEX.test(contentType)) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment content_type must be a valid type/subtype media type",
    );
  }
  return contentType;
}

function validateAttachmentSizeBytes(sizeBytes: unknown): number {
  if (
    typeof sizeBytes !== "number" ||
    !Number.isInteger(sizeBytes) ||
    !Number.isSafeInteger(sizeBytes) ||
    sizeBytes < 0 ||
    sizeBytes > MAX_ATTACHMENT_BYTES
  ) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `attachment size_bytes must be an integer between 0 and ${MAX_ATTACHMENT_BYTES}`,
    );
  }
  return sizeBytes;
}

function parseCommitmentDigestBytes(commitment: unknown): {
  canonicalCommitment: string;
  digestBytes: Uint8Array<ArrayBuffer>;
} {
  if (typeof commitment !== "string" || commitment.length === 0) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "encrypted_commitment must be a non-empty string",
    );
  }
  const parts = commitment.split(":");
  if (parts.length !== 4) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "malformed encrypted_commitment format",
    );
  }
  const [version, algorithm, encoding, digestHex] = parts;
  if (version !== "v1" || algorithm !== "sha256" || encoding !== "hex") {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "unsupported encrypted_commitment version or algorithm",
    );
  }
  const digestBytes = fromHexStrict(digestHex, SHA256_BYTES, "encrypted_commitment digest");
  return {
    canonicalCommitment: `v1:sha256:hex:${toHex(digestBytes)}`,
    digestBytes,
  };
}

function validateOrderingBounds(
  index: unknown,
  totalCount: unknown,
): {
  index: number;
  total_count: number;
} {
  if (typeof index !== "number" || !Number.isInteger(index) || index < 0) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment index must be a non-negative integer",
    );
  }
  if (
    typeof totalCount !== "number" ||
    !Number.isInteger(totalCount) ||
    totalCount < 1 ||
    totalCount > MAX_ATTACHMENTS
  ) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `attachment total_count must be an integer between 1 and ${MAX_ATTACHMENTS}`,
    );
  }
  if (index >= totalCount) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment index must be strictly less than total_count",
    );
  }
  return { index, total_count: totalCount };
}

/**
 * Validates an {@link AttachmentDescriptor} without mutating `filename` or
 * `content_type`. Hex digests are validated as 32-byte SHA-256 values.
 */
export function validateAttachmentDescriptor(
  descriptor: AttachmentDescriptor,
): AttachmentDescriptor {
  if (!descriptor || typeof descriptor !== "object") {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment descriptor must be an object",
    );
  }
  const filename = validateRawAttachmentFilename(descriptor.filename);
  const content_type = validateAttachmentMimeType(descriptor.content_type);
  const size_bytes = validateAttachmentSizeBytes(descriptor.size_bytes);
  fromHexStrict(descriptor.content_hash, SHA256_BYTES, "content_hash");

  if (descriptor.encrypted_commitment !== undefined) {
    parseCommitmentDigestBytes(descriptor.encrypted_commitment);
    return {
      filename,
      content_type,
      size_bytes,
      content_hash: descriptor.content_hash,
      encrypted_commitment: descriptor.encrypted_commitment,
    };
  }

  return {
    filename,
    content_type,
    size_bytes,
    content_hash: descriptor.content_hash,
  };
}

/**
 * Projects an attachment descriptor for envelope ProtectedHeader JCS encoding.
 * Preserves exact wire compatibility with v1 `{ filename, content_type, size_bytes, content_hash }`
 * descriptors while binding `encrypted_commitment` whenever supplied.
 */
export function toProtectedHeaderAttachment(descriptor: AttachmentDescriptor): {
  filename: string;
  content_type: string;
  size_bytes: number;
  content_hash: string;
  encrypted_commitment?: string;
} {
  if (descriptor.encrypted_commitment !== undefined) {
    parseCommitmentDigestBytes(descriptor.encrypted_commitment);
    return {
      filename: descriptor.filename,
      content_type: descriptor.content_type,
      size_bytes: descriptor.size_bytes,
      content_hash: descriptor.content_hash,
      encrypted_commitment: descriptor.encrypted_commitment,
    };
  }
  return {
    filename: descriptor.filename,
    content_type: descriptor.content_type,
    size_bytes: descriptor.size_bytes,
    content_hash: descriptor.content_hash,
  };
}

/**
 * Binary writer emitting big-endian fixed-width integers and 4-byte
 * length-prefixed byte slices so field boundaries are injective and immune to
 * delimiter concatenation ambiguity.
 */
class CanonicalByteWriter {
  private readonly chunks: Uint8Array[] = [];
  private totalLength = 0;

  writeUint8(value: number): void {
    const b = new Uint8Array(1);
    b[0] = value & 0xff;
    this.chunks.push(b);
    this.totalLength += 1;
  }

  writeUint32BE(value: number): void {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, value >>> 0, false);
    this.chunks.push(buf);
    this.totalLength += 4;
  }

  writeUint64BE(value: number): void {
    const buf = new Uint8Array(8);
    new DataView(buf.buffer).setBigUint64(0, BigInt(value), false);
    this.chunks.push(buf);
    this.totalLength += 8;
  }

  writeLengthPrefixedBytes(bytes: Uint8Array): void {
    this.writeUint32BE(bytes.byteLength);
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    this.chunks.push(copy);
    this.totalLength += copy.byteLength;
  }

  writeLengthPrefixedUtf8(value: string): void {
    this.writeLengthPrefixedBytes(utf8Encoder.encode(value));
  }

  finish(): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(new ArrayBuffer(this.totalLength));
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return out;
  }
}

/**
 * Encodes a single attachment's protected metadata into domain-separated,
 * length-prefixed Additional Authenticated Data (AAD) bytes for AES-256-GCM.
 *
 * Binds:
 * - Domain tag (`stealth-attachment-metadata-aad-v1`)
 * - `index` (uint32 BE) and `total_count` (uint32 BE)
 * - Exact raw `filename` UTF-8 bytes (length-prefixed, un-sanitized)
 * - Exact raw `content_type` UTF-8 bytes (length-prefixed)
 * - `size_bytes` (uint64 BE)
 * - Decoded 32-byte `content_hash` digest
 * - Optional caller `context` (presence flag + length-prefixed bytes)
 */
export function encodeAttachmentDescriptorAad(
  descriptor: {
    index: number;
    total_count: number;
    filename: string;
    content_type: string;
    size_bytes: number;
    content_hash: string;
  },
  context?: Uint8Array | string,
): Uint8Array<ArrayBuffer> {
  const { index, total_count } = validateOrderingBounds(descriptor.index, descriptor.total_count);
  const filename = validateRawAttachmentFilename(descriptor.filename);
  const contentType = validateAttachmentMimeType(descriptor.content_type);
  const sizeBytes = validateAttachmentSizeBytes(descriptor.size_bytes);
  const contentHashBytes = fromHexStrict(descriptor.content_hash, SHA256_BYTES, "content_hash");
  const hasContext = context !== undefined;
  const contextBytes = encodeContextBytes(context);

  const writer = new CanonicalByteWriter();
  writer.writeLengthPrefixedUtf8(ATTACHMENT_METADATA_AAD_DOMAIN);
  writer.writeUint32BE(index);
  writer.writeUint32BE(total_count);
  writer.writeLengthPrefixedUtf8(filename);
  writer.writeLengthPrefixedUtf8(contentType);
  writer.writeUint64BE(sizeBytes);
  writer.writeLengthPrefixedBytes(contentHashBytes);
  writer.writeUint8(hasContext ? 1 : 0);
  if (hasContext) {
    writer.writeLengthPrefixedBytes(contextBytes);
  }
  return writer.finish();
}

/**
 * Encodes an ordered list of authenticated attachment descriptors (including
 * their versioned `encrypted_commitment` digests) into domain-separated,
 * length-prefixed bytes for manifest GMAC authentication.
 */
export function encodeAttachmentManifestAad(
  descriptors: readonly AuthenticatedAttachmentDescriptor[],
  context?: Uint8Array | string,
): Uint8Array<ArrayBuffer> {
  if (!Array.isArray(descriptors)) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment descriptors must be an array",
    );
  }
  if (descriptors.length > MAX_ATTACHMENTS) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `attachment count exceeds ${MAX_ATTACHMENTS}`,
    );
  }

  const totalCount = descriptors.length;
  const hasContext = context !== undefined;
  const contextBytes = encodeContextBytes(context);

  const writer = new CanonicalByteWriter();
  writer.writeLengthPrefixedUtf8(ATTACHMENT_MANIFEST_AAD_DOMAIN);
  writer.writeUint32BE(totalCount);

  for (let i = 0; i < totalCount; i += 1) {
    const entry = descriptors[i];
    if (!entry || typeof entry !== "object") {
      throw new AttachmentMetadataError(
        "crypto_validation_error",
        `attachment descriptor at position ${i} is missing`,
      );
    }
    const { index, total_count } = validateOrderingBounds(entry.index, entry.total_count);
    if (index !== i) {
      throw new AttachmentMetadataError(
        "crypto_integrity_error",
        `attachment descriptor index mismatch at position ${i}: received ${index}`,
      );
    }
    if (total_count !== totalCount) {
      throw new AttachmentMetadataError(
        "crypto_integrity_error",
        `attachment descriptor total_count mismatch at position ${i}: expected ${totalCount}, received ${total_count}`,
      );
    }
    const filename = validateRawAttachmentFilename(entry.filename);
    const contentType = validateAttachmentMimeType(entry.content_type);
    const sizeBytes = validateAttachmentSizeBytes(entry.size_bytes);
    const contentHashBytes = fromHexStrict(entry.content_hash, SHA256_BYTES, "content_hash");
    const { canonicalCommitment, digestBytes } = parseCommitmentDigestBytes(
      entry.encrypted_commitment,
    );

    writer.writeUint32BE(index);
    writer.writeUint32BE(total_count);
    writer.writeLengthPrefixedUtf8(filename);
    writer.writeLengthPrefixedUtf8(contentType);
    writer.writeUint64BE(sizeBytes);
    writer.writeLengthPrefixedBytes(contentHashBytes);
    writer.writeLengthPrefixedUtf8(canonicalCommitment);
    writer.writeLengthPrefixedBytes(digestBytes);
  }

  writer.writeUint8(hasContext ? 1 : 0);
  if (hasContext) {
    writer.writeLengthPrefixedBytes(contextBytes);
  }
  return writer.finish();
}

/**
 * Canonicalizes attachment descriptors for additional authenticated data (AAD)
 * using RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Strictly validates each descriptor and binds explicit 0-based `index`,
 * `total_count`, `filename`, `content_type`, `size_bytes`, `content_hash`, and
 * optional `encrypted_commitment` without mutating raw filenames or MIME types.
 */
export function canonicalizeAttachmentDescriptors(
  attachments: readonly AttachmentDescriptor[],
): Uint8Array<ArrayBuffer> {
  if (!Array.isArray(attachments)) {
    throw new AttachmentMetadataError("crypto_validation_error", "attachments must be an array");
  }
  if (attachments.length > MAX_ATTACHMENTS) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `attachments count exceeds ${MAX_ATTACHMENTS}`,
    );
  }

  const totalCount = attachments.length;
  const normalized = attachments.map((attachment, index) => {
    const validated = validateAttachmentDescriptor(attachment);
    const contentHashBytes = fromHexStrict(validated.content_hash, SHA256_BYTES, "content_hash");
    const base = {
      index,
      total_count: totalCount,
      filename: validated.filename,
      content_type: validated.content_type,
      size_bytes: validated.size_bytes,
      content_hash: toHex(contentHashBytes),
    };
    if (validated.encrypted_commitment !== undefined) {
      const { canonicalCommitment } = parseCommitmentDigestBytes(validated.encrypted_commitment);
      return {
        ...base,
        encrypted_commitment: canonicalCommitment,
      };
    }
    return base;
  });

  const canonicalString = canonicalize({
    domain: ATTACHMENT_MANIFEST_AAD_DOMAIN,
    total_count: totalCount,
    attachments: normalized,
  });
  return toArrayBufferBytes(utf8Encoder.encode(canonicalString));
}

async function verifyEncryptedAttachmentCommitment(
  commitment: string,
  sealedCiphertextWithTag: Uint8Array,
): Promise<void> {
  const { digestBytes: declaredDigestBytes } = parseCommitmentDigestBytes(commitment);
  const expectedDigestBytes = await sha256Bytes(sealedCiphertextWithTag);
  if (!constantTimeEqual(declaredDigestBytes, expectedDigestBytes)) {
    throw new AttachmentMetadataError(
      "crypto_commitment_error",
      "encrypted attachment commitment mismatch",
    );
  }
}

/**
 * Encrypts a single attachment with AES-256-GCM while binding its exact
 * protected descriptor (`index`, `total_count`, `filename`, `content_type`,
 * `size_bytes`, `content_hash`) as Additional Authenticated Data (AAD) and
 * computing a versioned SHA-256 commitment over `ciphertext || tag`.
 */
export async function sealAttachment(
  key: CryptoKey,
  input: SealAttachmentInput,
): Promise<AuthenticatedEncryptedAttachment> {
  if (!input || typeof input !== "object") {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment input must be an object",
    );
  }

  const filename = validateRawAttachmentFilename(input.filename);
  const contentType = validateAttachmentMimeType(input.content_type);
  const plaintext = toBytes(input.data);
  if (plaintext.byteLength > MAX_ATTACHMENT_BYTES) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `attachment plaintext exceeds ${MAX_ATTACHMENT_BYTES} bytes`,
    );
  }

  const sizeBytes =
    input.size_bytes !== undefined
      ? validateAttachmentSizeBytes(input.size_bytes)
      : plaintext.byteLength;
  if (sizeBytes !== plaintext.byteLength) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "declared size_bytes does not match attachment plaintext byte length",
    );
  }

  const index = input.index ?? 0;
  const totalCount = input.total_count ?? 1;
  validateOrderingBounds(index, totalCount);

  if (input.nonce !== undefined && input.nonce.byteLength !== GCM_NONCE_BYTES) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `attachment nonce must be ${GCM_NONCE_BYTES} bytes`,
    );
  }

  const computedHashBytes = await sha256Bytes(plaintext);
  if (input.content_hash !== undefined) {
    const declaredHashBytes = fromHexStrict(input.content_hash, SHA256_BYTES, "content_hash");
    if (!constantTimeEqual(computedHashBytes, declaredHashBytes)) {
      throw new AttachmentMetadataError(
        "crypto_commitment_error",
        "declared content_hash does not match attachment plaintext",
      );
    }
  }
  const contentHash = toHex(computedHashBytes);

  const aad = encodeAttachmentDescriptorAad(
    {
      index,
      total_count: totalCount,
      filename,
      content_type: contentType,
      size_bytes: sizeBytes,
      content_hash: contentHash,
    },
    input.context,
  );

  const sealed = await sealAead(key, plaintext, input.nonce, aad);
  clearSecret(plaintext);
  const combinedForCommitment = joinTag(sealed.ciphertext, sealed.tag);
  const encryptedCommitment = await createCommitment(combinedForCommitment);
  clearSecret(combinedForCommitment);

  const encodedCiphertext = toBase64(sealed.ciphertext);
  clearSecret(sealed.ciphertext);

  return {
    descriptor: {
      index,
      total_count: totalCount,
      filename,
      content_type: contentType,
      size_bytes: sizeBytes,
      content_hash: contentHash,
      encrypted_commitment: encryptedCommitment,
    },
    ciphertext: encodedCiphertext,
    encryption_metadata: {
      algorithm: ATTACHMENT_AEAD_ALGORITHM,
      nonce: toHex(sealed.nonce),
      mac: toHex(sealed.tag),
    },
  };
}

/**
 * Verifies an encrypted attachment's ordering, encrypted commitment, AEAD tag
 * over the protected metadata AAD, decrypted byte length, and plaintext
 * SHA-256 `content_hash`. Fails closed on any metadata mutation, descriptor
 * substitution, or reordering.
 */
export async function openAttachment(
  key: CryptoKey,
  attachment: AuthenticatedEncryptedAttachment,
  options?: OpenAttachmentOptions,
): Promise<OpenedAuthenticatedAttachment> {
  if (!attachment || typeof attachment !== "object") {
    throw new AttachmentMetadataError("crypto_validation_error", "attachment is missing");
  }
  const { descriptor, encryption_metadata: meta } = attachment;
  if (!descriptor || typeof descriptor !== "object") {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment descriptor is missing",
    );
  }
  if (!meta || typeof meta !== "object") {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment encryption_metadata is missing",
    );
  }
  if (meta.algorithm !== ATTACHMENT_AEAD_ALGORITHM) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "unsupported attachment encryption algorithm",
    );
  }

  const { index, total_count } = validateOrderingBounds(descriptor.index, descriptor.total_count);
  if (options?.expectedIndex !== undefined && index !== options.expectedIndex) {
    throw new AttachmentMetadataError(
      "crypto_integrity_error",
      `attachment ordering mismatch: expected index ${options.expectedIndex}, received ${index}`,
    );
  }
  if (options?.expectedTotalCount !== undefined && total_count !== options.expectedTotalCount) {
    throw new AttachmentMetadataError(
      "crypto_integrity_error",
      `attachment total_count mismatch: expected ${options.expectedTotalCount}, received ${total_count}`,
    );
  }

  const filename = validateRawAttachmentFilename(descriptor.filename);
  const contentType = validateAttachmentMimeType(descriptor.content_type);
  const sizeBytes = validateAttachmentSizeBytes(descriptor.size_bytes);
  const expectedContentHashBytes = fromHexStrict(
    descriptor.content_hash,
    SHA256_BYTES,
    "content_hash",
  );
  const nonceBytes = fromHexStrict(meta.nonce, GCM_NONCE_BYTES, "nonce");
  const tagBytes = fromHexStrict(meta.mac, GCM_TAG_BYTES, "mac");
  const ciphertextBytes = fromBase64Strict(attachment.ciphertext, "ciphertext");

  if (ciphertextBytes.byteLength !== sizeBytes) {
    throw new AttachmentMetadataError(
      "crypto_integrity_error",
      "attachment ciphertext length does not match authenticated size_bytes",
    );
  }

  const combinedWithTag = joinTag(ciphertextBytes, tagBytes);
  await verifyEncryptedAttachmentCommitment(descriptor.encrypted_commitment, combinedWithTag);

  const aad = encodeAttachmentDescriptorAad(
    {
      index,
      total_count,
      filename,
      content_type: contentType,
      size_bytes: sizeBytes,
      content_hash: descriptor.content_hash,
    },
    options?.context,
  );

  let decrypted: Uint8Array<ArrayBuffer>;
  try {
    const opened = await openAead(key, ciphertextBytes, tagBytes, nonceBytes, aad);
    decrypted = opened.plaintext;
  } catch {
    throw new AttachmentMetadataError(
      "crypto_decrypt_error",
      "attachment authentication or decryption failed",
    );
  }

  if (decrypted.byteLength !== sizeBytes) {
    throw new AttachmentMetadataError(
      "crypto_integrity_error",
      "decrypted attachment size does not match authenticated size_bytes",
    );
  }

  const actualContentHashBytes = await sha256Bytes(decrypted);
  if (!constantTimeEqual(actualContentHashBytes, expectedContentHashBytes)) {
    throw new AttachmentMetadataError(
      "crypto_commitment_error",
      "decrypted attachment plaintext failed content_hash verification",
    );
  }

  return {
    index,
    total_count,
    filename,
    displayFilename: normalizeFilenameForDisplay(filename),
    content_type: contentType,
    size_bytes: sizeBytes,
    content_hash: toHex(actualContentHashBytes),
    encrypted_commitment: descriptor.encrypted_commitment,
    bytes: decrypted,
  };
}

/**
 * Authenticates an ordered array of attachment descriptors (and their
 * encrypted commitments) with AES-256-GMAC (0-byte AES-GCM over canonical
 * length-prefixed manifest AAD). Supports empty (`[]`), single, and
 * multi-attachment manifests, including detached ciphertext storage flows.
 */
export async function authenticateAttachmentManifest(
  key: CryptoKey,
  descriptors: readonly AuthenticatedAttachmentDescriptor[],
  options?: SealAttachmentSetOptions,
): Promise<AuthenticatedAttachmentManifest> {
  if (
    options?.manifestNonce !== undefined &&
    options.manifestNonce.byteLength !== GCM_NONCE_BYTES
  ) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `manifest nonce must be ${GCM_NONCE_BYTES} bytes`,
    );
  }

  const manifestAad = encodeAttachmentManifestAad(descriptors, options?.context);
  const gmac = await sealAead(key, new Uint8Array(0), options?.manifestNonce, manifestAad);

  return {
    version: ATTACHMENT_MANIFEST_VERSION,
    algorithm: ATTACHMENT_AEAD_ALGORITHM,
    nonce: toHex(gmac.nonce),
    mac: toHex(gmac.tag),
    descriptors: descriptors.map((d) => ({
      index: d.index,
      total_count: d.total_count,
      filename: d.filename,
      content_type: d.content_type,
      size_bytes: d.size_bytes,
      content_hash: toHex(fromHexStrict(d.content_hash, SHA256_BYTES, "content_hash")),
      encrypted_commitment: parseCommitmentDigestBytes(d.encrypted_commitment).canonicalCommitment,
    })),
  };
}

/**
 * Verifies an {@link AuthenticatedAttachmentManifest} in constant time via
 * WebCrypto AES-256-GMAC and returns the verified ordered descriptors.
 * Any descriptor mutation, substitution, truncation, duplication, or
 * reordering fails closed.
 */
export async function verifyAttachmentManifest(
  key: CryptoKey,
  manifest: AuthenticatedAttachmentManifest,
  options?: OpenAttachmentSetOptions,
): Promise<readonly AuthenticatedAttachmentDescriptor[]> {
  if (!manifest || typeof manifest !== "object") {
    throw new AttachmentMetadataError("crypto_validation_error", "attachment manifest is missing");
  }
  if (manifest.version !== ATTACHMENT_MANIFEST_VERSION) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "unsupported attachment manifest version",
    );
  }
  if (manifest.algorithm !== ATTACHMENT_AEAD_ALGORITHM) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "unsupported attachment manifest algorithm",
    );
  }

  const nonceBytes = fromHexStrict(manifest.nonce, GCM_NONCE_BYTES, "manifest.nonce");
  const tagBytes = fromHexStrict(manifest.mac, GCM_TAG_BYTES, "manifest.mac");
  const manifestAad = encodeAttachmentManifestAad(manifest.descriptors, options?.context);

  try {
    await openAead(key, new Uint8Array(0), tagBytes, nonceBytes, manifestAad);
  } catch {
    throw new AttachmentMetadataError(
      "crypto_integrity_error",
      "attachment manifest authentication failed",
    );
  }

  return manifest.descriptors.map((d) => ({ ...d }));
}

/**
 * Seals an ordered list of attachments, binding every attachment's exact
 * position (`index`), `total_count`, `filename`, `content_type`, `size_bytes`,
 * and `content_hash` into per-attachment AES-256-GCM AAD, plus an overarching
 * AES-256-GMAC manifest over all descriptors and `encrypted_commitment`s.
 */
export async function sealAttachmentSet(
  key: CryptoKey,
  inputs: readonly Omit<SealAttachmentInput, "index" | "total_count" | "context">[],
  options?: SealAttachmentSetOptions,
): Promise<AuthenticatedAttachmentSet> {
  if (!Array.isArray(inputs)) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment inputs must be an array",
    );
  }
  if (inputs.length > MAX_ATTACHMENTS) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      `attachment count exceeds ${MAX_ATTACHMENTS}`,
    );
  }

  const totalCount = inputs.length;
  const sealedAttachments: AuthenticatedEncryptedAttachment[] = [];

  for (let i = 0; i < totalCount; i += 1) {
    const item = inputs[i];
    const sealed = await sealAttachment(key, {
      ...item,
      index: i,
      total_count: totalCount,
      context: options?.context,
    });
    sealedAttachments.push(sealed);
  }

  const manifest = await authenticateAttachmentManifest(
    key,
    sealedAttachments.map((a) => a.descriptor),
    options,
  );

  return {
    manifest,
    attachments: sealedAttachments,
  };
}

/**
 * Verifies the set-level manifest AND opens every attachment in order,
 * cross-checking that each attachment's descriptor matches the verified
 * manifest entry byte-for-byte. Rejects descriptor substitution, reordering,
 * truncation, appended attachments, or any metadata/ciphertext tamper.
 */
export async function openAttachmentSet(
  key: CryptoKey,
  bundle: AuthenticatedAttachmentSet,
  options?: OpenAttachmentSetOptions,
): Promise<readonly OpenedAuthenticatedAttachment[]> {
  if (!bundle || typeof bundle !== "object") {
    throw new AttachmentMetadataError("crypto_validation_error", "attachment bundle is missing");
  }
  if (!Array.isArray(bundle.attachments)) {
    throw new AttachmentMetadataError(
      "crypto_validation_error",
      "attachment bundle attachments must be an array",
    );
  }

  const verifiedDescriptors = await verifyAttachmentManifest(key, bundle.manifest, options);
  if (bundle.attachments.length !== verifiedDescriptors.length) {
    throw new AttachmentMetadataError(
      "crypto_integrity_error",
      "attachment count does not match authenticated manifest",
    );
  }

  const totalCount = verifiedDescriptors.length;
  const opened: OpenedAuthenticatedAttachment[] = [];

  for (let i = 0; i < totalCount; i += 1) {
    const att = bundle.attachments[i];
    const manifestDesc = verifiedDescriptors[i];
    if (!att || !att.descriptor) {
      throw new AttachmentMetadataError(
        "crypto_validation_error",
        `missing attachment entry at index ${i}`,
      );
    }

    // Verify the attachment carries the exact descriptor and commitment authenticated by the manifest.
    const expectedDescAad = encodeAttachmentDescriptorAad(manifestDesc, options?.context);
    const actualDescAad = encodeAttachmentDescriptorAad(att.descriptor, options?.context);
    const expectedCommit = parseCommitmentDigestBytes(manifestDesc.encrypted_commitment);
    const actualCommit = parseCommitmentDigestBytes(att.descriptor.encrypted_commitment);
    if (
      !constantTimeEqual(expectedDescAad, actualDescAad) ||
      !constantTimeEqual(expectedCommit.digestBytes, actualCommit.digestBytes)
    ) {
      throw new AttachmentMetadataError(
        "crypto_integrity_error",
        `attachment descriptor at index ${i} does not match authenticated manifest`,
      );
    }

    const result = await openAttachment(key, att, {
      expectedIndex: i,
      expectedTotalCount: totalCount,
      context: options?.context,
    });
    opened.push(result);
  }

  return opened;
}

function isInvisibleOrControlCodePoint(cp: number): boolean {
  // ASCII C0 controls (0x00..0x1F) and DEL + C1 controls (0x7F..0x9F)
  if (cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f)) return true;
  // Soft hyphen
  if (cp === 0x00ad) return true;
  // Arabic Letter Mark, LRM, RLM
  if (cp === 0x061c || cp === 0x200e || cp === 0x200f) return true;
  // Zero-width space / non-joiner / joiner
  if (cp >= 0x200b && cp <= 0x200d) return true;
  // Unicode Bidirectional embedding / override controls (LRE, RLE, PDF, LRO, RLO U+202E)
  if (cp >= 0x202a && cp <= 0x202e) return true;
  // Line / paragraph separators
  if (cp === 0x2028 || cp === 0x2029) return true;
  // Word joiner + invisible operators + Bidi isolates (LRI, RLI, FSI, PDI U+2066..U+2069)
  if (cp >= 0x2060 && cp <= 0x2069) return true;
  // BOM / zero-width no-break space
  if (cp === 0xfeff) return true;
  // Interlinear annotation controls
  if (cp >= 0xfff9 && cp <= 0xfffb) return true;
  // Lone UTF-16 surrogates
  if (cp >= 0xd800 && cp <= 0xdfff) return true;
  return false;
}

function stripDangerousCodePoints(input: string): string {
  let out = "";
  for (const ch of input) {
    const cp = ch.codePointAt(0);
    if (cp === undefined || isInvisibleOrControlCodePoint(cp)) {
      continue;
    }
    out += ch;
  }
  return out;
}

function truncatePreservingExtension(name: string, maxCodePoints: number): string {
  const chars = Array.from(name);
  if (chars.length <= maxCodePoints) {
    return name;
  }

  const lastDot = name.lastIndexOf(".");
  if (lastDot > 0 && lastDot < name.length - 1) {
    const extChars = Array.from(name.slice(lastDot));
    if (extChars.length <= 16 && extChars.length < maxCodePoints - 1) {
      const stemBudget = maxCodePoints - extChars.length;
      const stemChars = Array.from(name.slice(0, lastDot)).slice(0, stemBudget);
      return stemChars.join("") + extChars.join("");
    }
  }

  return chars.slice(0, maxCodePoints).join("");
}

/**
 * Normalizes a raw attachment filename strictly for UI display or download
 * prompts — NEVER inside cryptographic identity or AAD computation.
 *
 * Defenses applied:
 * 1. Unicode NFC normalization for consistent glyph rendering.
 * 2. Strips ASCII C0/C1 control characters (including NUL `\0`, CR/LF),
 *    Unicode Bidi overrides/isolates (`U+202E` RLO extension spoofing, etc.),
 *    zero-width format characters, and unpaired surrogates.
 * 3. Collapses `\` and `/` path separators and extracts the terminal path
 *    segment, rejecting `.` and `..` traversal segments.
 * 4. Replaces shell/filesystem metacharacters (`< > : " | ? *`) with `_`,
 *    collapses internal whitespace runs, and strips leading spaces and
 *    trailing spaces/dots.
 * 5. Prefixes Windows reserved device stems (`CON`, `PRN`, `AUX`, `NUL`,
 *    `COM1`–`COM9`, `LPT1`–`LPT9`) with `_`.
 * 6. Bounds output length to {@link MAX_DISPLAY_FILENAME_LENGTH} code points
 *    while preserving a short file extension when present.
 */
export function normalizeFilenameForDisplay(filename: string): string {
  if (typeof filename !== "string" || filename.length === 0) {
    return DEFAULT_DISPLAY_FILENAME;
  }

  const strippedRaw = stripDangerousCodePoints(filename);
  const normalized = strippedRaw.normalize("NFC");

  // Unify path separators and extract the final non-empty segment.
  const segments = normalized
    .replace(/\\/g, "/")
    .split("/")
    .filter((segment) => segment.length > 0);

  let base = segments.length > 0 ? segments[segments.length - 1] : "";
  if (base === "." || base === "..") {
    return DEFAULT_DISPLAY_FILENAME;
  }

  // Replace filesystem-reserved metacharacters and normalize whitespace.
  base = base.replace(/[<>:"|?*]/g, "_").replace(/\s+/g, " ");

  // Strip leading whitespace and trailing whitespace or dots.
  base = base.replace(/^\s+/g, "").replace(/[\s.]+$/g, "");

  if (base.length === 0 || base === "." || base === "..") {
    return DEFAULT_DISPLAY_FILENAME;
  }

  // Guard Windows reserved device names (e.g. "NUL", "CON.txt", "com1.tar.gz").
  const dotIndex = base.indexOf(".");
  const stem = dotIndex === -1 ? base : base.slice(0, dotIndex);
  if (WINDOWS_RESERVED_BASENAME_REGEX.test(stem)) {
    base = `_${base}`;
  }

  base = truncatePreservingExtension(base, MAX_DISPLAY_FILENAME_LENGTH);
  base = base.replace(/[\s.]+$/g, "");

  return base.length === 0 ? DEFAULT_DISPLAY_FILENAME : base;
}

/**
 * Alias of {@link normalizeFilenameForDisplay} for explicit attachment display
 * normalization call sites.
 */
export function normalizeAttachmentFilenameForDisplay(filename: string): string {
  return normalizeFilenameForDisplay(filename);
}

/**
 * Alias of {@link normalizeFilenameForDisplay} preserved for callers importing
 * `sanitizeFilenameForDisplay`.
 */
export function sanitizeFilenameForDisplay(filename: string): string {
  return normalizeFilenameForDisplay(filename);
}
