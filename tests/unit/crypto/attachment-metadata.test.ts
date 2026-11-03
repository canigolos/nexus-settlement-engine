import { describe, expect, it } from "vitest";
import { encodeAad, type ProtectedHeader } from "../../../src/services/crypto/aad";
import {
  AttachmentMetadataError,
  DEFAULT_DISPLAY_FILENAME,
  MAX_DISPLAY_FILENAME_LENGTH,
  authenticateAttachmentManifest,
  canonicalizeAttachmentDescriptors,
  encodeAttachmentDescriptorAad,
  encodeAttachmentManifestAad,
  normalizeAttachmentFilenameForDisplay,
  normalizeFilenameForDisplay,
  openAttachment,
  openAttachmentSet,
  sanitizeFilenameForDisplay,
  sealAttachment,
  sealAttachmentSet,
  validateAttachmentDescriptor,
  verifyAttachmentManifest,
  type AuthenticatedAttachmentSet,
  type AuthenticatedEncryptedAttachment,
} from "../../../src/services/crypto/attachment-metadata";
import { sealEnvelope } from "../../../src/services/crypto/envelope";
import { openEnvelope, type KeyProvider } from "../../../src/services/crypto/open-envelope";
import { getCryptoTestVectors } from "../../../src/services/crypto/testing";

type DeepMutable<T> = {
  -readonly [K in keyof T]: T[K] extends object ? DeepMutable<T[K]> : T[K];
};

function utf8(text: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(text);
}

function flipHexNibble(hex: string, index: number): string {
  const chars = hex.split("");
  chars[index] = chars[index].toLowerCase() === "0" ? "1" : "0";
  return chars.join("");
}

async function generateAesKey(extractable = false): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, extractable, [
    "encrypt",
    "decrypt",
  ]);
}

describe("Attachment Metadata Authentication & Display Normalization (#50)", () => {
  const sender = "alice@example.com";
  const recipient = "bob@example.com";
  const body = "Confidential body text";

  const attachment1 = {
    filename: "invoice.pdf",
    content_type: "application/pdf",
    size_bytes: 1024,
    data: utf8("Dummy pdf content").buffer,
  };

  const attachment2 = {
    filename: "notes.txt",
    content_type: "text/plain",
    size_bytes: 512,
    data: utf8("Dummy txt content").buffer,
  };

  const setupMockKey = async () => {
    const vectors = getCryptoTestVectors();
    const mockKey = await generateAesKey(true);
    vectors.generateKey = async () => mockKey;
    const keyProvider: KeyProvider = {
      async resolveKey() {
        return mockKey;
      },
    };
    return {
      mockKey,
      keyProvider,
      cleanUp: () => {
        vectors.generateKey = undefined;
      },
    };
  };

  describe("envelope AAD integration (sealEnvelope / openEnvelope / encodeAad)", () => {
    it("seals and opens an envelope with authenticated attachments", async () => {
      const { keyProvider, cleanUp } = await setupMockKey();
      try {
        const sealed = await sealEnvelope({
          sender,
          recipient,
          body,
          attachments: [attachment1, attachment2],
        });

        const opened = await openEnvelope(sealed, keyProvider);
        expect(opened.body).toBe(body);
        expect(opened.attachments).toHaveLength(2);
        expect(opened.attachments[0].filename).toBe("invoice.pdf");
        expect(opened.attachments[0].content_type).toBe("application/pdf");
        expect(opened.attachments[1].filename).toBe("notes.txt");
        expect(opened.attachments[1].content_type).toBe("text/plain");
      } finally {
        cleanUp();
      }
    });

    it("fails verification when an attachment filename is mutated", async () => {
      const { keyProvider, cleanUp } = await setupMockKey();
      try {
        const sealed = await sealEnvelope({
          sender,
          recipient,
          body,
          attachments: [attachment1, attachment2],
        });

        sealed.payload.attachments[0].filename = "malicious.exe";

        await expect(openEnvelope(sealed, keyProvider)).rejects.toThrow(
          "decryption failed (wrong key or tampered)",
        );
      } finally {
        cleanUp();
      }
    });

    it("fails verification when an attachment MIME type is mutated", async () => {
      const { keyProvider, cleanUp } = await setupMockKey();
      try {
        const sealed = await sealEnvelope({
          sender,
          recipient,
          body,
          attachments: [attachment1, attachment2],
        });

        sealed.payload.attachments[0].content_type = "text/html";

        await expect(openEnvelope(sealed, keyProvider)).rejects.toThrow(
          "decryption failed (wrong key or tampered)",
        );
      } finally {
        cleanUp();
      }
    });

    it("fails verification when attachment size_bytes or content_hash is mutated", async () => {
      const { keyProvider, cleanUp } = await setupMockKey();
      try {
        const sealed = await sealEnvelope({
          sender,
          recipient,
          body,
          attachments: [attachment1, attachment2],
        });

        const sizeTampered = structuredClone(sealed);
        sizeTampered.payload.attachments[0].size_bytes += 1;
        await expect(openEnvelope(sizeTampered, keyProvider)).rejects.toThrow(
          "decryption failed (wrong key or tampered)",
        );

        const hashTampered = structuredClone(sealed);
        hashTampered.payload.attachments[0].content_hash = flipHexNibble(
          hashTampered.payload.attachments[0].content_hash,
          0,
        );
        await expect(openEnvelope(hashTampered, keyProvider)).rejects.toThrow(
          "decryption failed (wrong key or tampered)",
        );
      } finally {
        cleanUp();
      }
    });

    it("fails verification when attachments are reordered", async () => {
      const { keyProvider, cleanUp } = await setupMockKey();
      try {
        const sealed = await sealEnvelope({
          sender,
          recipient,
          body,
          attachments: [attachment1, attachment2],
        });

        const temp = sealed.payload.attachments[0];
        sealed.payload.attachments[0] = sealed.payload.attachments[1];
        sealed.payload.attachments[1] = temp;

        await expect(openEnvelope(sealed, keyProvider)).rejects.toThrow(
          "decryption failed (wrong key or tampered)",
        );
      } finally {
        cleanUp();
      }
    });

    it("binds optional encrypted_commitment in ProtectedHeader encodeAad", () => {
      const commitmentA = `v1:sha256:hex:${"a".repeat(64)}`;
      const commitmentB = `v1:sha256:hex:${"b".repeat(64)}`;
      const baseHeader: ProtectedHeader = {
        version: "v1",
        sender: "G" + "A".repeat(55),
        recipient: "G" + "B".repeat(55),
        timestamp: "2026-08-01T00:00:00.000Z",
        attachments: [
          {
            filename: "statement.pdf",
            content_type: "application/pdf",
            size_bytes: 2048,
            content_hash: "c".repeat(64),
            encrypted_commitment: commitmentA,
          },
        ],
      };

      const aadA = encodeAad(baseHeader);
      const aadB = encodeAad({
        ...baseHeader,
        attachments: [{ ...baseHeader.attachments[0], encrypted_commitment: commitmentB }],
      });
      expect(aadA).not.toEqual(aadB);

      expect(() =>
        encodeAad({
          ...baseHeader,
          attachments: [{ ...baseHeader.attachments[0], encrypted_commitment: "v2:md5:hex:1234" }],
        }),
      ).toThrow(AttachmentMetadataError);
    });
  });

  describe("per-attachment AEAD metadata & commitment binding (sealAttachment / openAttachment)", () => {
    it("round-trips empty (0-byte), binary, and Unicode-named attachments with non-extractable keys", async () => {
      const key = await generateAesKey(false);

      const emptySealed = await sealAttachment(key, {
        filename: "empty.txt",
        content_type: "text/plain; charset=utf-8",
        data: new Uint8Array(0),
      });
      const emptyOpened = await openAttachment(key, emptySealed);
      expect(emptyOpened.bytes.byteLength).toBe(0);
      expect(emptyOpened.size_bytes).toBe(0);
      expect(emptyOpened.filename).toBe("empty.txt");
      expect(emptyOpened.content_type).toBe("text/plain; charset=utf-8");

      const unicodeData = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0xff]);
      const unicodeSealed = await sealAttachment(key, {
        filename: "契約書_2026_🔒.pdf",
        content_type: "application/pdf",
        data: unicodeData,
        context: "msg-id-9942",
      });
      const unicodeOpened = await openAttachment(key, unicodeSealed, {
        expectedIndex: 0,
        expectedTotalCount: 1,
        context: "msg-id-9942",
      });
      expect(unicodeOpened.bytes).toEqual(unicodeData);
      expect(unicodeOpened.filename).toBe("契約書_2026_🔒.pdf");
      expect(unicodeOpened.displayFilename).toBe("契約書_2026_🔒.pdf");
      expect(unicodeOpened.encrypted_commitment).toMatch(/^v1:sha256:hex:[0-9a-f]{64}$/);
    });

    it("rejects any mutation to filename, MIME type, size_bytes, ordering, content_hash, commitment, or context", async () => {
      const key = await generateAesKey(false);
      const sealed = await sealAttachment(key, {
        filename: "quarterly-report.pdf",
        content_type: "application/pdf",
        data: utf8("Q3 financial summary"),
        index: 0,
        total_count: 2,
        context: "envelope-ctx-1",
      });

      const mutate = (
        fn: (draft: DeepMutable<AuthenticatedEncryptedAttachment>) => void,
      ): AuthenticatedEncryptedAttachment => {
        const clone = structuredClone(sealed) as DeepMutable<AuthenticatedEncryptedAttachment>;
        fn(clone);
        return clone;
      };

      // Filename single-char / extension / case / whitespace mutations
      for (const badName of [
        "quarterly-report.exe",
        "Quarterly-Report.pdf",
        "quarterly-report.pdf ",
        "quarterly-report.pdg",
      ]) {
        await expect(
          openAttachment(
            key,
            mutate((d) => {
              d.descriptor.filename = badName;
            }),
            { context: "envelope-ctx-1" },
          ),
        ).rejects.toMatchObject({ code: "crypto_decrypt_error" });
      }

      // MIME type mutations (type swap, case change, parameter injection)
      for (const badMime of [
        "text/html",
        "APPLICATION/PDF",
        "application/pdf; charset=utf-7",
        "application/x-msdownload",
      ]) {
        await expect(
          openAttachment(
            key,
            mutate((d) => {
              d.descriptor.content_type = badMime;
            }),
            { context: "envelope-ctx-1" },
          ),
        ).rejects.toMatchObject({ code: "crypto_decrypt_error" });
      }

      // Declared size mutation fails closed
      await expect(
        openAttachment(
          key,
          mutate((d) => {
            d.descriptor.size_bytes += 1;
          }),
          { context: "envelope-ctx-1" },
        ),
      ).rejects.toMatchObject({ code: "crypto_integrity_error" });

      // Ordering mutations (index or total_count) fail closed
      await expect(
        openAttachment(
          key,
          mutate((d) => {
            d.descriptor.index = 1;
          }),
          { context: "envelope-ctx-1" },
        ),
      ).rejects.toMatchObject({ code: "crypto_decrypt_error" });

      await expect(
        openAttachment(
          key,
          mutate((d) => {
            d.descriptor.total_count = 3;
          }),
          { context: "envelope-ctx-1" },
        ),
      ).rejects.toMatchObject({ code: "crypto_decrypt_error" });

      // Plaintext content_hash mutation fails AEAD AAD check before releasing plaintext
      await expect(
        openAttachment(
          key,
          mutate((d) => {
            d.descriptor.content_hash = flipHexNibble(d.descriptor.content_hash, 63);
          }),
          { context: "envelope-ctx-1" },
        ),
      ).rejects.toMatchObject({ code: "crypto_decrypt_error" });

      //Encrypted attachment commitment mutation fails commitment verification
      await expect(
        openAttachment(
          key,
          mutate((d) => {
            const parts = d.descriptor.encrypted_commitment.split(":");
            parts[3] = flipHexNibble(parts[3], 17);
            d.descriptor.encrypted_commitment = parts.join(":");
          }),
          { context: "envelope-ctx-1" },
        ),
      ).rejects.toMatchObject({ code: "crypto_commitment_error" });

      // Uppercase hex mutations on content_hash, encrypted_commitment, nonce, or mac fail closed
      const forceUpperHex = (hex: string): string =>
        /[a-f]/.test(hex) ? hex.toUpperCase() : `A${hex.slice(1)}`;
      await expect(
        openAttachment(
          key,
          mutate((d) => {
            d.descriptor.content_hash = forceUpperHex(d.descriptor.content_hash);
          }),
          { context: "envelope-ctx-1" },
        ),
      ).rejects.toMatchObject({ code: "crypto_validation_error" });
      await expect(
        openAttachment(
          key,
          mutate((d) => {
            const parts = d.descriptor.encrypted_commitment.split(":");
            parts[3] = forceUpperHex(parts[3]);
            d.descriptor.encrypted_commitment = parts.join(":");
          }),
          { context: "envelope-ctx-1" },
        ),
      ).rejects.toMatchObject({ code: "crypto_validation_error" });
      await expect(
        openAttachment(
          key,
          mutate((d) => {
            d.encryption_metadata.nonce = forceUpperHex(d.encryption_metadata.nonce);
          }),
          { context: "envelope-ctx-1" },
        ),
      ).rejects.toMatchObject({ code: "crypto_validation_error" });
      await expect(
        openAttachment(
          key,
          mutate((d) => {
            d.encryption_metadata.mac = forceUpperHex(d.encryption_metadata.mac);
          }),
          { context: "envelope-ctx-1" },
        ),
      ).rejects.toMatchObject({ code: "crypto_validation_error" });

      // Wrong or missing context fails closed
      await expect(
        openAttachment(key, sealed, { context: "envelope-ctx-2" }),
      ).rejects.toMatchObject({ code: "crypto_decrypt_error" });
      await expect(openAttachment(key, sealed)).rejects.toMatchObject({
        code: "crypto_decrypt_error",
      });
    });

    it("rejects mismatched declared size_bytes or declared content_hash at seal time", async () => {
      const key = await generateAesKey(false);
      await expect(
        sealAttachment(key, {
          filename: "doc.pdf",
          content_type: "application/pdf",
          data: utf8("12345"),
          size_bytes: 99,
        }),
      ).rejects.toMatchObject({ code: "crypto_validation_error" });

      await expect(
        sealAttachment(key, {
          filename: "doc.pdf",
          content_type: "application/pdf",
          data: utf8("12345"),
          content_hash: "0".repeat(64),
        }),
      ).rejects.toMatchObject({ code: "crypto_commitment_error" });
    });
  });

  describe("descriptor substitution and reordering attacks (sealAttachmentSet / openAttachmentSet)", () => {
    it("round-trips empty ([]), single, and multi-attachment ordered sets", async () => {
      const key = await generateAesKey(false);

      const emptySet = await sealAttachmentSet(key, [], { context: "env-empty" });
      expect(emptySet.manifest.descriptors).toHaveLength(0);
      await expect(
        openAttachmentSet(key, emptySet, { context: "env-empty" }),
      ).resolves.toStrictEqual([]);

      const multiSet = await sealAttachmentSet(
        key,
        [
          {
            filename: "01-terms.pdf",
            content_type: "application/pdf",
            data: utf8("Same-length payload A!"),
          },
          {
            filename: "02-receipt.json",
            content_type: "application/json",
            data: utf8("Same-length payload B!"),
          },
          {
            filename: "03-archive.tar",
            content_type: "application/x-tar",
            data: utf8("Same-length payload C!"),
          },
        ],
        { context: "env-multi" },
      );

      const opened = await openAttachmentSet(key, multiSet, { context: "env-multi" });
      expect(opened.map((a) => a.filename)).toEqual([
        "01-terms.pdf",
        "02-receipt.json",
        "03-archive.tar",
      ]);
      expect(opened.map((a) => a.index)).toEqual([0, 1, 2]);
      expect(new TextDecoder().decode(opened[1].bytes)).toBe("Same-length payload B!");
    });

    it("rejects descriptor substitution onto equal-size encrypted attachment bytes", async () => {
      const key = await generateAesKey(false);
      // Identical 24-byte lengths so size checks alone cannot distinguish them
      const benignBytes = utf8("BENIGN_PDF_DOCUMENT_DATA");
      const executableBytes = utf8("MALICIOUS_EXECUTABLE_BIN");

      const bundle = await sealAttachmentSet(key, [
        {
          filename: "benign-report.pdf",
          content_type: "application/pdf",
          data: benignBytes,
        },
        {
          filename: "update-tool.exe",
          content_type: "application/x-msdownload",
          data: executableBytes,
        },
      ]);

      // Attack 1: Substitute benign descriptor[0] onto executable attachment[1]'s ciphertext + MAC
      const substitutedSingle: AuthenticatedEncryptedAttachment = {
        descriptor: {
          ...bundle.attachments[0].descriptor,
          // Even if attacker recomputes unkeyed encrypted_commitment for attachment[1]'s bytes,
          // AES-GCM AAD tag verification under the content key rejects the substituted descriptor!
          encrypted_commitment: bundle.attachments[1].descriptor.encrypted_commitment,
        },
        ciphertext: bundle.attachments[1].ciphertext,
        encryption_metadata: bundle.attachments[1].encryption_metadata,
      };
      await expect(
        openAttachment(key, substitutedSingle, { expectedIndex: 0, expectedTotalCount: 2 }),
      ).rejects.toMatchObject({ code: "crypto_decrypt_error" });

      // Attack 2: Swap ciphertexts/MACs inside the bundle while keeping manifest descriptors intact
      const swappedCiphertexts: AuthenticatedAttachmentSet = {
        manifest: bundle.manifest,
        attachments: [
          {
            descriptor: bundle.attachments[0].descriptor,
            ciphertext: bundle.attachments[1].ciphertext,
            encryption_metadata: bundle.attachments[1].encryption_metadata,
          },
          {
            descriptor: bundle.attachments[1].descriptor,
            ciphertext: bundle.attachments[0].ciphertext,
            encryption_metadata: bundle.attachments[0].encryption_metadata,
          },
        ],
      };
      await expect(openAttachmentSet(key, swappedCiphertexts)).rejects.toThrow(
        AttachmentMetadataError,
      );

      // Attack 3: Substitute a valid single-attachment bundle into a 2-attachment slot
      const standalone = await sealAttachmentSet(key, [
        {
          filename: "benign-report.pdf",
          content_type: "application/pdf",
          data: benignBytes,
        },
      ]);
      await expect(
        openAttachment(key, standalone.attachments[0], {
          expectedIndex: 0,
          expectedTotalCount: 2,
        }),
      ).rejects.toMatchObject({ code: "crypto_integrity_error" });
    });

    it("rejects attachment reordering, duplication, and truncation even when indices are rewritten", async () => {
      const key = await generateAesKey(false);
      const bundle = await sealAttachmentSet(key, [
        {
          filename: "step-1.txt",
          content_type: "text/plain",
          data: utf8("First step"),
        },
        {
          filename: "step-2.txt",
          content_type: "text/plain",
          data: utf8("Second step"),
        },
      ]);

      // Direct swap [1, 0] in attachments array
      await expect(
        openAttachmentSet(key, {
          manifest: bundle.manifest,
          attachments: [bundle.attachments[1], bundle.attachments[0]],
        }),
      ).rejects.toMatchObject({ code: "crypto_integrity_error" });

      // Reorder both manifest descriptors and attachments AND rewrite indices 0, 1
      const rewrittenAttachments = [bundle.attachments[1], bundle.attachments[0]].map(
        (att, idx) => ({
          ...att,
          descriptor: { ...att.descriptor, index: idx },
        }),
      );
      const rewrittenManifest = {
        ...bundle.manifest,
        descriptors: rewrittenAttachments.map((a) => a.descriptor),
      };
      await expect(
        openAttachmentSet(key, {
          manifest: rewrittenManifest,
          attachments: rewrittenAttachments,
        }),
      ).rejects.toMatchObject({ code: "crypto_integrity_error" });

      // Even opening reordered attachment[1] directly at index 0 fails per-attachment AEAD
      await expect(
        openAttachment(key, rewrittenAttachments[0], { expectedIndex: 0, expectedTotalCount: 2 }),
      ).rejects.toMatchObject({ code: "crypto_decrypt_error" });

      // Truncation attack ([0, 1] -> [0])
      await expect(
        openAttachmentSet(key, {
          manifest: {
            ...bundle.manifest,
            descriptors: [{ ...bundle.manifest.descriptors[0], total_count: 1 }],
          },
          attachments: [
            {
              ...bundle.attachments[0],
              descriptor: { ...bundle.attachments[0].descriptor, total_count: 1 },
            },
          ],
        }),
      ).rejects.toMatchObject({ code: "crypto_integrity_error" });

      // Duplication attack ([0, 1] -> [0, 0])
      const duplicatedDesc1 = { ...bundle.attachments[0].descriptor, index: 1 };
      await expect(
        verifyAttachmentManifest(key, {
          ...bundle.manifest,
          descriptors: [bundle.manifest.descriptors[0], duplicatedDesc1],
        }),
      ).rejects.toMatchObject({ code: "crypto_integrity_error" });
    });

    it("authenticates detached descriptor manifests without inline ciphertexts", async () => {
      const key = await generateAesKey(false);
      const descriptors = [
        {
          index: 0,
          total_count: 2,
          filename: "ledger-export.csv",
          content_type: "text/csv",
          size_bytes: 4096,
          content_hash: "1".repeat(64),
          encrypted_commitment: `v1:sha256:hex:${"2".repeat(64)}`,
        },
        {
          index: 1,
          total_count: 2,
          filename: "audit-proof.bin",
          content_type: "application/octet-stream",
          size_bytes: 8192,
          content_hash: "3".repeat(64),
          encrypted_commitment: `v1:sha256:hex:${"4".repeat(64)}`,
        },
      ] as const;

      const manifest = await authenticateAttachmentManifest(key, descriptors, {
        context: "detached-r2-session",
      });
      const verified = await verifyAttachmentManifest(key, manifest, {
        context: "detached-r2-session",
      });
      expect(verified).toEqual(descriptors);

      // Mutate detached commitment digest
      const tampered = structuredClone(manifest) as DeepMutable<typeof manifest>;
      tampered.descriptors[1].encrypted_commitment = `v1:sha256:hex:${"5".repeat(64)}`;
      await expect(
        verifyAttachmentManifest(key, tampered, { context: "detached-r2-session" }),
      ).rejects.toMatchObject({ code: "crypto_integrity_error" });
    });
  });

  describe("canonical serialization boundary unambiguity & input validation", () => {
    it("prevents field-boundary concatenation collisions across length-prefixed AAD and JCS", () => {
      const hash = "a".repeat(64);
      const commitment = `v1:sha256:hex:${"b".repeat(64)}`;

      // Classic delimiter shift: ("report|text", "plain/sub") vs ("report", "text|plain/sub")
      const descLeft = {
        index: 0,
        total_count: 1,
        filename: 'report.pdf","content_type":"text/html',
        content_type: "application/pdf",
        size_bytes: 128,
        content_hash: hash,
      };
      const descRight = {
        index: 0,
        total_count: 1,
        filename: "report.pdf",
        content_type: "text/html",
        size_bytes: 128,
        content_hash: hash,
      };

      expect(encodeAttachmentDescriptorAad(descLeft)).not.toEqual(
        encodeAttachmentDescriptorAad(descRight),
      );
      expect(canonicalizeAttachmentDescriptors([descLeft])).not.toEqual(
        canonicalizeAttachmentDescriptors([descRight]),
      );

      // Context presence vs empty context bytes must also remain distinct
      const withoutContext = encodeAttachmentDescriptorAad(descRight);
      const withEmptyContext = encodeAttachmentDescriptorAad(descRight, new Uint8Array(0));
      expect(withoutContext).not.toEqual(withEmptyContext);

      // Single-descriptor AAD domain vs manifest AAD domain never collide
      const manifestBytes = encodeAttachmentManifestAad([
        { ...descRight, encrypted_commitment: commitment },
      ]);
      expect(manifestBytes).not.toEqual(withoutContext);
    });

    it("rejects malformed descriptors, lone UTF-16 surrogates, and invalid MIME syntax", () => {
      const validHash = "f".repeat(64);

      // Lone surrogates would otherwise silently coerce to U+FFFD under TextEncoder
      expect(() =>
        validateAttachmentDescriptor({
          filename: "bad\uD800name.txt",
          content_type: "text/plain",
          size_bytes: 10,
          content_hash: validHash,
        }),
      ).toThrow(AttachmentMetadataError);

      expect(() =>
        validateAttachmentDescriptor({
          filename: "valid.txt",
          content_type: "not-a-mime-type",
          size_bytes: 10,
          content_hash: validHash,
        }),
      ).toThrow(AttachmentMetadataError);

      expect(() =>
        validateAttachmentDescriptor({
          filename: "valid.txt",
          content_type: "text/plain\r\nX-Injected: 1",
          size_bytes: 10,
          content_hash: validHash,
        }),
      ).toThrow(AttachmentMetadataError);

      expect(() =>
        validateAttachmentDescriptor({
          filename: "valid.txt",
          content_type: "text/plain",
          size_bytes: -1,
          content_hash: validHash,
        }),
      ).toThrow(AttachmentMetadataError);
    });
  });

  describe("separation of cryptographic identity from display filename normalization", () => {
    it("preserves unsafe wire filenames inside cryptographic identity while normalizing for display", async () => {
      const { keyProvider, cleanUp } = await setupMockKey();
      try {
        const traversalAttachment = {
          filename: "../../../etc/passwd",
          content_type: "text/plain",
          size_bytes: 18,
          data: utf8("etc passwd content").buffer,
        };

        const sealed = await sealEnvelope({
          sender,
          recipient,
          body,
          attachments: [traversalAttachment],
        });

        const opened = await openEnvelope(sealed, keyProvider);
        expect(opened.attachments[0].filename).toBe("../../../etc/passwd");
        expect(sanitizeFilenameForDisplay(opened.attachments[0].filename)).toBe("passwd");
      } finally {
        cleanUp();
      }
    });

    it("treats two filenames with identical display output as distinct cryptographic identities", async () => {
      const key = await generateAesKey(false);

      // Both "../../../etc/passwd" and "passwd" normalize to "passwd" for display,
      // and both "invoice\u202Efdp.exe" and "invoicefdp.exe" normalize to "invoicefdp.exe",
      // and NFC "caf\u00e9.pdf" vs NFD "cafe\u0301.pdf" normalize to NFC "caf\u00e9.pdf".
      const pairs: ReadonlyArray<[string, string, string]> = [
        ["../../../etc/passwd", "passwd", "passwd"],
        ["invoice\u202Efdp.exe", "invoicefdp.exe", "invoicefdp.exe"],
        ["caf\u00e9.pdf", "cafe\u0301.pdf", "caf\u00e9.pdf"],
      ];

      for (const [wireUnsafe, wireClean, expectedDisplay] of pairs) {
        expect(normalizeFilenameForDisplay(wireUnsafe)).toBe(expectedDisplay);
        expect(normalizeFilenameForDisplay(wireClean)).toBe(expectedDisplay);

        const sealed = await sealAttachment(key, {
          filename: wireUnsafe,
          content_type: "application/octet-stream",
          data: utf8("payload"),
        });

        const opened = await openAttachment(key, sealed);
        expect(opened.filename).toBe(wireUnsafe);
        expect(opened.displayFilename).toBe(expectedDisplay);

        // Replacing the wire filename with its display-normalized counterpart MUST fail AEAD!
        const mutated: AuthenticatedEncryptedAttachment = {
          ...sealed,
          descriptor: {
            ...sealed.descriptor,
            filename: wireClean,
          },
        };
        await expect(openAttachment(key, mutated)).rejects.toMatchObject({
          code: "crypto_decrypt_error",
        });
      }
    });

    it("neutralizes path traversal, Bidi RLO extension spoofing, controls, Windows devices, and overlong names", () => {
      // Unix & Windows directory traversal and dot segments
      expect(normalizeFilenameForDisplay("../../../etc/passwd")).toBe("passwd");
      expect(normalizeFilenameForDisplay("..\\..\\Windows\\System32\\cmd.exe")).toBe("cmd.exe");
      expect(normalizeFilenameForDisplay("..")).toBe(DEFAULT_DISPLAY_FILENAME);
      expect(normalizeFilenameForDisplay(".")).toBe(DEFAULT_DISPLAY_FILENAME);
      expect(normalizeFilenameForDisplay("folder/..")).toBe(DEFAULT_DISPLAY_FILENAME);
      expect(normalizeFilenameForDisplay("////")).toBe(DEFAULT_DISPLAY_FILENAME);

      // Unicode Right-to-Left Override (U+202E) & Bidi isolate extension spoofing
      expect(normalizeFilenameForDisplay("annex_\u202Efdp.exe")).toBe("annex_fdp.exe");
      expect(normalizeFilenameForDisplay("\u2067invoice\u2069.pdf")).toBe("invoice.pdf");

      // NUL byte & ASCII C0/C1 control characters + zero-width characters
      expect(normalizeFilenameForDisplay("report.pdf\u0000.exe")).toBe("report.pdf.exe");
      expect(normalizeFilenameForDisplay("line1\r\nline2\u200B.txt")).toBe("line1line2.txt");
      expect(normalizeFilenameForDisplay("\u0000\u0007\u001b")).toBe(DEFAULT_DISPLAY_FILENAME);

      // Trailing dots/spaces and shell metacharacters
      expect(normalizeFilenameForDisplay("statement.pdf...   ")).toBe("statement.pdf");
      expect(normalizeFilenameForDisplay('bad<>:"|?*chars.txt')).toBe("bad_______chars.txt");

      // Windows reserved device stems
      expect(normalizeFilenameForDisplay("CON")).toBe("_CON");
      expect(normalizeFilenameForDisplay("nul.txt")).toBe("_nul.txt");
      expect(normalizeFilenameForDisplay("com1.tar.gz")).toBe("_com1.tar.gz");
      expect(normalizeFilenameForDisplay("LPT9.log")).toBe("_LPT9.log");

      // Length bounding while preserving final file extension
      const overlong = `${"a".repeat(220)}.pdf`;
      const bounded = normalizeFilenameForDisplay(overlong);
      expect(Array.from(bounded).length).toBe(MAX_DISPLAY_FILENAME_LENGTH);
      expect(bounded.endsWith(".pdf")).toBe(true);
      expect(normalizeAttachmentFilenameForDisplay("../../../invoice\u202Efdp.exe")).toBe(
        "invoicefdp.exe",
      );
    });
  });
});
