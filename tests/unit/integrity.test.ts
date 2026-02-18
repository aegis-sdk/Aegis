import { describe, it, expect } from "vitest";
import { MessageSigner } from "../../packages/core/src/integrity/index.js";

const SECRET = "test-hmac-secret";

describe("MessageSigner", () => {
  const signer = new MessageSigner({ secret: SECRET });

  // ─── sign() ──────────────────────────────────────────────────────────────

  describe("sign()", () => {
    it("returns a non-empty hex string", async () => {
      const sig = await signer.sign({ role: "assistant", content: "Hello!" });
      expect(sig).toBeTruthy();
      expect(sig.length).toBeGreaterThan(0);
      // Should be a hex string (only 0-9, a-f)
      expect(sig).toMatch(/^[0-9a-f]+$/);
    });

    it("is deterministic — same message produces the same signature", async () => {
      const msg = { role: "assistant" as const, content: "Deterministic test" };
      const sig1 = await signer.sign(msg);
      const sig2 = await signer.sign(msg);
      expect(sig1).toBe(sig2);
    });

    it("produces different signatures for different messages", async () => {
      const sigA = await signer.sign({ role: "assistant", content: "Message A" });
      const sigB = await signer.sign({ role: "assistant", content: "Message B" });
      expect(sigA).not.toBe(sigB);
    });
  });

  // ─── verify() ────────────────────────────────────────────────────────────

  describe("verify()", () => {
    it("returns true for a correctly signed message", async () => {
      const msg = { role: "assistant" as const, content: "Trusted output" };
      const sig = await signer.sign(msg);
      const valid = await signer.verify(msg, sig);
      expect(valid).toBe(true);
    });

    it("returns false when message content has been tampered with", async () => {
      const msg = { role: "assistant" as const, content: "Original content" };
      const sig = await signer.sign(msg);
      const tampered = { role: "assistant" as const, content: "Tampered content" };
      const valid = await signer.verify(tampered, sig);
      expect(valid).toBe(false);
    });

    it("returns false for a wrong signature", async () => {
      const msg = { role: "assistant" as const, content: "Some output" };
      const valid = await signer.verify(msg, "deadbeef0000111122223333aaaabbbb");
      expect(valid).toBe(false);
    });
  });

  // ─── signConversation() ──────────────────────────────────────────────────

  describe("signConversation()", () => {
    it("returns correct structure with messages array and chainHash", async () => {
      const messages = [
        { role: "user" as const, content: "What is 2+2?" },
        { role: "assistant" as const, content: "4" },
      ];
      const signed = await signer.signConversation(messages);

      expect(signed).toHaveProperty("messages");
      expect(signed).toHaveProperty("chainHash");
      expect(signed.messages).toHaveLength(2);
      expect(signed.chainHash).toBeTruthy();
      expect(signed.chainHash).toMatch(/^[0-9a-f]+$/);

      // Each entry should have the original message and a signature field
      for (const entry of signed.messages) {
        expect(entry).toHaveProperty("message");
        expect(entry).toHaveProperty("signature");
        expect(entry.message).toHaveProperty("role");
        expect(entry.message).toHaveProperty("content");
      }
    });

    it("only signs assistant messages when assistantOnly is true (default)", async () => {
      const messages = [
        { role: "user" as const, content: "Hello" },
        { role: "assistant" as const, content: "Hi there!" },
        { role: "user" as const, content: "How are you?" },
        { role: "assistant" as const, content: "I am well." },
      ];
      const signed = await signer.signConversation(messages);

      // User messages (index 0 and 2) should have empty signatures
      expect(signed.messages[0]!.signature).toBe("");
      expect(signed.messages[2]!.signature).toBe("");

      // Assistant messages (index 1 and 3) should have non-empty signatures
      expect(signed.messages[1]!.signature).not.toBe("");
      expect(signed.messages[3]!.signature).not.toBe("");
    });

    it("signs ALL messages when assistantOnly is false", async () => {
      const allSigner = new MessageSigner({ secret: SECRET, assistantOnly: false });
      const messages = [
        { role: "user" as const, content: "Hello" },
        { role: "assistant" as const, content: "Hi there!" },
        { role: "user" as const, content: "Goodbye" },
      ];
      const signed = await allSigner.signConversation(messages);

      // Every message should have a non-empty signature
      for (const entry of signed.messages) {
        expect(entry.signature).not.toBe("");
        expect(entry.signature).toMatch(/^[0-9a-f]+$/);
      }
    });
  });

  // ─── verifyConversation() ────────────────────────────────────────────────

  describe("verifyConversation()", () => {
    it("valid conversation passes verification", async () => {
      const messages = [
        { role: "user" as const, content: "Tell me a joke" },
        { role: "assistant" as const, content: "Why did the chicken cross the road?" },
        { role: "user" as const, content: "Why?" },
        { role: "assistant" as const, content: "To get to the other side." },
      ];
      const signed = await signer.signConversation(messages);
      const result = await signer.verifyConversation(signed);

      expect(result.valid).toBe(true);
      expect(result.tamperedIndices).toHaveLength(0);
      expect(result.chainValid).toBe(true);
    });

    it("detects tampered message content", async () => {
      const messages = [
        { role: "user" as const, content: "What is the capital of France?" },
        { role: "assistant" as const, content: "The capital of France is Paris." },
      ];
      const signed = await signer.signConversation(messages);

      // Tamper with the assistant message content
      signed.messages[1] = {
        message: { role: "assistant", content: "The capital of France is Berlin." },
        signature: signed.messages[1]!.signature,
      };

      const result = await signer.verifyConversation(signed);

      expect(result.valid).toBe(false);
      expect(result.tamperedIndices).toContain(1);
    });

    it("detects chain hash manipulation", async () => {
      const messages = [
        { role: "user" as const, content: "Hello" },
        { role: "assistant" as const, content: "Hi" },
      ];
      const signed = await signer.signConversation(messages);

      // Manipulate the chain hash
      signed.chainHash = "aaaaaaaaaaaabbbbbbbbbbbbccccccccccccdddddddddddd";

      const result = await signer.verifyConversation(signed);

      expect(result.chainValid).toBe(false);
      // The overall result should be invalid because chain is broken
      expect(result.valid).toBe(false);
    });

    it("detects message reordering", async () => {
      const messages = [
        { role: "user" as const, content: "First question" },
        { role: "assistant" as const, content: "First answer" },
        { role: "user" as const, content: "Second question" },
        { role: "assistant" as const, content: "Second answer" },
      ];
      const signed = await signer.signConversation(messages);

      // Swap the two assistant messages (index 1 and 3)
      const temp = signed.messages[1]!;
      signed.messages[1] = signed.messages[3]!;
      signed.messages[3] = temp;

      const result = await signer.verifyConversation(signed);

      // Reordering should break either signatures or chain (or both)
      expect(result.valid).toBe(false);
    });

    it("empty conversation passes verification", async () => {
      const signed = await signer.signConversation([]);
      const result = await signer.verifyConversation(signed);

      expect(result.valid).toBe(true);
      expect(result.tamperedIndices).toHaveLength(0);
      expect(result.chainValid).toBe(true);
      expect(signed.messages).toHaveLength(0);
      // Chain hash should still exist for an empty conversation
      expect(signed.chainHash).toBeTruthy();
    });
  });
});
