/**
 * HMAC Message Integrity Module.
 *
 * Signs and verifies assistant messages to detect conversation history
 * manipulation (T15). Uses the Web Crypto API (SubtleCrypto) for HMAC
 * operations so it works on Edge runtimes. Falls back to a simple
 * hash-based approach when SubtleCrypto is not available.
 */

import type {
  MessageIntegrityConfig,
  PromptMessage,
  SignedConversation,
  SignedMessage,
  IntegrityResult,
} from "../types.js";

/**
 * Check whether the SubtleCrypto API is available in the current runtime.
 */
function hasSubtleCrypto(): boolean {
  return (
    typeof globalThis !== "undefined" &&
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.subtle !== "undefined"
  );
}

/**
 * Convert a string to a Uint8Array (UTF-8 encoded).
 */
function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Convert an ArrayBuffer to a lowercase hex string.
 */
function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Simple fallback hash when SubtleCrypto is unavailable.
 *
 * This is NOT cryptographically secure — it provides a basic integrity
 * check only. Uses a variant of DJB2 combined with the secret to produce
 * a hex digest. Production deployments should always use SubtleCrypto.
 */
function fallbackHmac(secret: string, data: string): string {
  const combined = secret + ":" + data;
  let h1 = 0x811c9dc5; // FNV offset basis
  let h2 = 0x01000193; // FNV prime

  for (let i = 0; i < combined.length; i++) {
    const c = combined.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193);
    h2 = Math.imul(h2 ^ c, 0x811c9dc5);
  }

  // Produce 32 hex chars (128-bit) by combining the two hashes
  const a = (h1 >>> 0).toString(16).padStart(8, "0");
  const b = (h2 >>> 0).toString(16).padStart(8, "0");
  const c = ((h1 ^ h2) >>> 0).toString(16).padStart(8, "0");
  const d = (Math.imul(h1, h2) >>> 0).toString(16).padStart(8, "0");
  return a + b + c + d;
}

/**
 * MessageSigner — signs and verifies assistant messages using HMAC-SHA256.
 *
 * Detects history manipulation (T15) by cryptographically binding message
 * content to signatures. Supports chained hashing for ordering integrity:
 * each signature incorporates the previous signature, so reordering or
 * inserting messages is detectable.
 *
 * @example
 * ```ts
 * const signer = new MessageSigner({ secret: 'my-hmac-secret' });
 *
 * // Sign a conversation
 * const signed = await signer.signConversation(messages);
 *
 * // Later, verify integrity
 * const result = await signer.verifyConversation(signed);
 * if (!result.valid) {
 *   console.warn('Tampered messages at indices:', result.tamperedIndices);
 * }
 * ```
 */
export class MessageSigner {
  private readonly secret: string;
  private readonly algorithm: string;
  private readonly assistantOnly: boolean;
  private cryptoKey: CryptoKey | null = null;
  private readonly useSubtleCrypto: boolean;

  constructor(config: MessageIntegrityConfig) {
    this.secret = config.secret;
    this.algorithm = config.algorithm ?? "SHA-256";
    this.assistantOnly = config.assistantOnly ?? true;
    this.useSubtleCrypto = hasSubtleCrypto();
  }

  /**
   * Import the HMAC key for SubtleCrypto operations.
   * Caches the key after first import.
   */
  private async getKey(): Promise<CryptoKey> {
    if (this.cryptoKey) return this.cryptoKey;

    const keyData = stringToBytes(this.secret);
    this.cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      keyData.buffer as ArrayBuffer,
      { name: "HMAC", hash: { name: this.algorithm } },
      false,
      ["sign", "verify"],
    );

    return this.cryptoKey;
  }

  /**
   * Compute HMAC signature for the given data string.
   */
  private async hmac(data: string): Promise<string> {
    if (!this.useSubtleCrypto) {
      return fallbackHmac(this.secret, data);
    }

    const key = await this.getKey();
    const encoded = stringToBytes(data);
    const signature = await globalThis.crypto.subtle.sign(
      "HMAC",
      key,
      encoded.buffer as ArrayBuffer,
    );
    return bufferToHex(signature);
  }

  /**
   * Build the signable content string for a message.
   * Includes role and content to prevent role-swapping attacks.
   */
  private messagePayload(message: PromptMessage, previousSignature?: string): string {
    const base = `${message.role}:${message.content}`;
    if (previousSignature) {
      return `${previousSignature}|${base}`;
    }
    return base;
  }

  /**
   * Determine whether a message should be signed based on configuration.
   */
  private shouldSign(message: PromptMessage): boolean {
    if (this.assistantOnly) {
      return message.role === "assistant";
    }
    return true;
  }

  /**
   * Sign a single message and return its HMAC-SHA256 hex signature.
   *
   * @param message - The message to sign
   * @returns The HMAC-SHA256 hex signature string
   */
  async sign(message: PromptMessage): Promise<string> {
    const payload = this.messagePayload(message);
    return this.hmac(payload);
  }

  /**
   * Verify that a signature matches the given message content.
   *
   * @param message - The message to verify
   * @param signature - The expected HMAC signature
   * @returns true if the signature is valid
   */
  async verify(message: PromptMessage, signature: string): Promise<boolean> {
    const expected = await this.sign(message);
    return expected === signature;
  }

  /**
   * Sign all messages in a conversation, producing a SignedConversation.
   *
   * Each signed message's signature includes the previous signature
   * (chain hashing) to ensure ordering integrity. Messages that are
   * not signed (e.g., user messages when assistantOnly is true) get
   * an empty signature but still participate in chain ordering.
   *
   * @param messages - The conversation messages to sign
   * @returns A SignedConversation with signatures and a chain hash
   */
  async signConversation(messages: PromptMessage[]): Promise<SignedConversation> {
    const signed: SignedMessage[] = [];
    let previousSignature = "";

    for (const message of messages) {
      if (this.shouldSign(message)) {
        const payload = this.messagePayload(message, previousSignature || undefined);
        const signature = await this.hmac(payload);
        signed.push({ message, signature });
        previousSignature = signature;
      } else {
        // Non-signed messages still contribute to chain ordering
        // via their content hash, but get an empty signature
        const orderPayload = previousSignature
          ? `${previousSignature}|${message.role}:${message.content}`
          : `${message.role}:${message.content}`;
        previousSignature = await this.hmac(orderPayload);
        signed.push({ message, signature: "" });
      }
    }

    // The chain hash is the final accumulated signature
    const chainHash = previousSignature || (await this.hmac("empty-conversation"));

    return { messages: signed, chainHash };
  }

  /**
   * Verify the integrity of a signed conversation.
   *
   * Checks each signed message's signature and verifies the chain hash
   * to detect both content tampering and message reordering/insertion.
   *
   * @param signed - The SignedConversation to verify
   * @returns An IntegrityResult with detailed tampering information
   */
  async verifyConversation(signed: SignedConversation): Promise<IntegrityResult> {
    const tamperedIndices: number[] = [];
    let previousSignature = "";

    for (let i = 0; i < signed.messages.length; i++) {
      const entry = signed.messages[i] as SignedMessage;
      const { message, signature } = entry;

      if (this.shouldSign(message)) {
        // Recompute the chained signature
        const payload = this.messagePayload(message, previousSignature || undefined);
        const expected = await this.hmac(payload);

        if (expected !== signature) {
          tamperedIndices.push(i);
        }

        previousSignature = signature;
      } else {
        // Non-signed messages still contribute to chain via their order hash
        const orderPayload = previousSignature
          ? `${previousSignature}|${message.role}:${message.content}`
          : `${message.role}:${message.content}`;
        previousSignature = await this.hmac(orderPayload);
      }
    }

    // Verify the chain hash
    const expectedChainHash = previousSignature || (await this.hmac("empty-conversation"));
    const chainValid = expectedChainHash === signed.chainHash;

    return {
      valid: tamperedIndices.length === 0 && chainValid,
      tamperedIndices,
      chainValid,
    };
  }
}
