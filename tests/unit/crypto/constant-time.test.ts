import { describe, expect, it } from "vitest";

import { createCommitment, verifyCommitment } from "../../../src/services/crypto/commitment";
import {
  ConstantTimeError,
  constantTimeEqual,
  constantTimeEqualOrThrow,
} from "../../../src/services/crypto/constant-time";
import {
  deriveKeyId,
  keyIdsEqual,
  resolveKeysFromSet,
  type KeyMetadata,
} from "../../../src/services/crypto/key-id";
import { normalizeRecipients } from "../../../src/services/crypto/multi-recipient";
import { decryptAttachment, OpenEnvelopeError } from "../../../src/services/crypto/open-envelope";

function bytes(values: number[]): Uint8Array {
  return new Uint8Array(values);
}

function trackByteReads(source: Uint8Array): { view: Uint8Array; reads: number[] } {
  const reads: number[] = [];
  const view = new Proxy(source, {
    get(target, prop, receiver) {
      if (typeof prop === "string" && /^\d+$/.test(prop)) {
        reads.push(Number(prop));
      }
      const value = Reflect.get(target, prop, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { view, reads };
}

describe("constant-time byte comparison (#35 / #1718)", () => {
  it("returns true for identical equal-length values across cryptographic sizes", () => {
    for (const length of [0, 1, 12, 16, 32, 64]) {
      const sample = new Uint8Array(length);
      for (let i = 0; i < length; i += 1) {
        sample[i] = (i * 37 + 13) & 0xff;
      }
      expect(constantTimeEqual(sample, sample.slice())).toBe(true);
      expect(constantTimeEqualOrThrow(sample, sample.slice())).toBe(true);
    }
  });

  it("visits every byte without early exit for all positions of first difference", () => {
    for (const length of [12, 16, 32, 64]) {
      const base = new Uint8Array(length);
      for (let i = 0; i < length; i += 1) {
        base[i] = (i * 19 + 0x5a) & 0xff;
      }

      for (let firstDiffPos = 0; firstDiffPos < length; firstDiffPos += 1) {
        for (let bit = 0; bit < 8; bit += 1) {
          const candidate = base.slice();
          candidate[firstDiffPos] ^= 1 << bit;

          const trackedA = trackByteReads(base);
          const trackedB = trackByteReads(candidate);

          expect(constantTimeEqual(trackedA.view, trackedB.view)).toBe(false);
          expect(constantTimeEqualOrThrow(trackedA.view, trackedB.view)).toBe(false);
          expect(trackedA.reads).toHaveLength(length * 2);
          expect(trackedB.reads).toHaveLength(length * 2);
        }
      }
    }
  });

  it("follows a documented non-shortcut safe path on length mismatches", () => {
    const shorter = bytes([1, 2, 3, 4]);
    const longer = bytes([1, 2, 3, 4, 0, 0]);
    const trackedShorter = trackByteReads(shorter);
    const trackedLonger = trackByteReads(longer);

    expect(constantTimeEqual(trackedShorter.view, trackedLonger.view)).toBe(false);
    expect(trackedShorter.reads).toHaveLength(shorter.length);
    expect(trackedLonger.reads).toHaveLength(longer.length);

    expect(constantTimeEqual(longer, shorter)).toBe(false);
    expect(constantTimeEqual(bytes([]), bytes([0]))).toBe(false);
    expect(constantTimeEqual(bytes([0]), bytes([]))).toBe(false);
  });

  it("constantTimeEqualOrThrow throws ConstantTimeError on length mismatch or invalid inputs", () => {
    expect(() => constantTimeEqualOrThrow(bytes([1, 2]), bytes([1, 2, 3]))).toThrowError(
      ConstantTimeError,
    );
    expect(() => constantTimeEqualOrThrow(bytes([1]), bytes([1, 2]))).toThrowError(
      expect.objectContaining({ code: "crypto_validation_error" }),
    );
    expect(() => constantTimeEqual("abcd" as unknown as Uint8Array, bytes([1, 2]))).toThrowError(
      ConstantTimeError,
    );
  });

  describe("decoded-byte cryptographic call sites", () => {
    it("verifyCommitment validates 32-byte digest length before constant-time byte comparison", async () => {
      const ciphertext = bytes([10, 20, 30, 40, 50, 60]);
      const commitment = await createCommitment(ciphertext);
      const [version, algo, encoding, hexDigest] = commitment.split(":");

      // Uppercase hex decodes to the identical 32-byte digest (proving decoded-byte comparison)
      const upperCommitment = `${version}:${algo}:${encoding}:${hexDigest.toUpperCase()}`;
      await expect(verifyCommitment(upperCommitment, ciphertext)).resolves.toBeUndefined();

      // Truncated / overlong / odd-length hex digests fail length/codec validation before comparison
      await expect(
        verifyCommitment(`${version}:${algo}:${encoding}:${hexDigest.slice(0, 62)}`, ciphertext),
      ).rejects.toMatchObject({ code: "crypto_parse_error" });
      await expect(
        verifyCommitment(`${version}:${algo}:${encoding}:${hexDigest}00`, ciphertext),
      ).rejects.toMatchObject({ code: "crypto_parse_error" });

      // Single-bit flip at every byte position of the 32-byte commitment digest fails closed
      const digestBytes = new Uint8Array(
        hexDigest.match(/.{2}/g)!.map((pair) => Number.parseInt(pair, 16)),
      );
      for (let pos = 0; pos < digestBytes.length; pos += 1) {
        const mutated = digestBytes.slice();
        mutated[pos] ^= 0x01;
        const mutatedHex = Array.from(mutated)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
        await expect(
          verifyCommitment(`${version}:${algo}:${encoding}:${mutatedHex}`, ciphertext),
        ).rejects.toMatchObject({ code: "crypto_commitment_error" });
      }
    });

    it("keyIdsEqual and resolveKeysFromSet compare decoded 32-byte key identifier digests", async () => {
      const idA = await deriveKeyId(bytes([1, 2, 3, 4]));
      const idB = await deriveKeyId(bytes([1, 2, 3, 5]));
      expect(keyIdsEqual(idA, idA)).toBe(true);
      expect(keyIdsEqual(idA, idB)).toBe(false);

      const pool: KeyMetadata[] = [
        {
          keyId: idA,
          algorithm: "Ed25519",
          version: 1,
          createdAt: "2026-07-23T12:00:00Z",
          rotationState: "active",
        },
        {
          keyId: idB,
          algorithm: "Ed25519",
          version: 1,
          createdAt: "2026-07-23T12:00:00Z",
          rotationState: "active",
        },
      ];
      const matched = resolveKeysFromSet(idA, pool, { allowRotatedKeys: true });
      expect(matched).toHaveLength(1);
      expect(matched[0].keyId).toBe(idA);
    });

    it("decryptAttachment validates 32-byte expectedContentHash before constant-time comparison", async () => {
      const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
        "encrypt",
        "decrypt",
      ]);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = new TextEncoder().encode("constant-time attachment payload");
      const sealed = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext),
      );
      const tag = sealed.slice(sealed.length - 16);
      const nonceHex = Array.from(iv)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const macHex = Array.from(tag)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      let binary = "";
      for (const b of sealed) binary += String.fromCharCode(b);
      const ciphertextB64 = btoa(binary);

      await expect(
        decryptAttachment(key, {
          ciphertext: ciphertextB64,
          nonce: nonceHex,
          mac: macHex,
          expectedContentHash: "abcd",
        }),
      ).rejects.toThrow(OpenEnvelopeError);
    });

    it("normalizeRecipients compares duplicate recipient keyMaterial in constant time", () => {
      const key1 = bytes([1, 2, 3, 4, 5, 6, 7, 8]);
      const key2 = bytes([1, 2, 3, 4, 5, 6, 7, 9]);
      expect(
        normalizeRecipients([
          { id: "alice", keyMaterial: key1 },
          { id: "ALICE", keyMaterial: key1.slice() },
        ]),
      ).toHaveLength(1);
      expect(() =>
        normalizeRecipients([
          { id: "alice", keyMaterial: key1 },
          { id: "alice", keyMaterial: key2 },
        ]),
      ).toThrow();
    });
  });
});
