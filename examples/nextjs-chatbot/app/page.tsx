"use client";

import { useChat } from "ai/react";

export default function Chat() {
  const { messages, input, handleInputChange, handleSubmit, error } = useChat();

  return (
    <main style={{ maxWidth: 600, margin: "0 auto", padding: "2rem" }}>
      <h1>Aegis Chatbot</h1>
      <p style={{ color: "#666" }}>Protected by @aegis-sdk/core with strict policy.</p>

      <div
        style={{
          border: "1px solid #ddd",
          borderRadius: 8,
          padding: "1rem",
          minHeight: 300,
          marginBottom: "1rem",
          overflowY: "auto",
        }}
      >
        {messages.map((m) => (
          <div key={m.id} style={{ marginBottom: "0.75rem" }}>
            <strong>{m.role === "user" ? "You" : "AI"}:</strong> {m.content}
          </div>
        ))}
      </div>

      {error && (
        <div
          style={{
            background: "#fee",
            border: "1px solid #c00",
            borderRadius: 4,
            padding: "0.5rem 1rem",
            marginBottom: "1rem",
            color: "#900",
          }}
        >
          {error.message.includes("blocked")
            ? "Your message was blocked by Aegis. It may contain a prompt injection attempt."
            : error.message}
        </div>
      )}

      <form onSubmit={handleSubmit} style={{ display: "flex", gap: 8 }}>
        <input
          value={input}
          onChange={handleInputChange}
          placeholder="Say something..."
          style={{
            flex: 1,
            padding: "0.5rem",
            borderRadius: 4,
            border: "1px solid #ccc",
            fontSize: 16,
          }}
        />
        <button
          type="submit"
          style={{
            padding: "0.5rem 1rem",
            borderRadius: 4,
            border: "none",
            background: "#111",
            color: "#fff",
            fontSize: 16,
            cursor: "pointer",
          }}
        >
          Send
        </button>
      </form>
    </main>
  );
}
