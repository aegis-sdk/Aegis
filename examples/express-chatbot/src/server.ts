import express from "express";
import OpenAI from "openai";
import { Aegis, AegisInputBlocked } from "@aegis-sdk/core";
import { aegisMiddleware } from "@aegis-sdk/express";

// ─── Setup ──────────────────────────────────────────────────────────────────

const app = express();
const port = 3001;

const openai = new OpenAI(); // Uses OPENAI_API_KEY env var
const aegis = new Aegis({
  policy: "balanced",
  canaryTokens: ["SYSTEM_CANARY_TOKEN_12345"],
  monitor: { detectPII: true, detectSecrets: true },
});

// ─── Middleware ──────────────────────────────────────────────────────────────

// Aegis middleware scans all POST request bodies automatically
app.use("/api/chat", aegisMiddleware(aegis));

// ─── Routes ─────────────────────────────────────────────────────────────────

app.post("/api/chat", async (req, res) => {
  const messages = req.body?.messages;

  if (!Array.isArray(messages)) {
    res.status(400).json({ error: "messages array required" });
    return;
  }

  try {
    // Messages were already scanned by aegisMiddleware.
    // The middleware attaches scan results to req.aegis.
    const stream = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages,
      stream: true,
    });

    // Stream the response
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    for await (const chunk of stream) {
      const content = chunk.choices[0]?.delta?.content;
      if (content) {
        res.write(`data: ${JSON.stringify({ content })}\n\n`);
      }
    }

    res.write("data: [DONE]\n\n");
    res.end();
  } catch (err) {
    if (err instanceof AegisInputBlocked) {
      res.status(403).json({
        error: "Input blocked by Aegis",
        detections: err.scanResult.detections,
        score: err.scanResult.score,
      });
      return;
    }
    console.error("Chat error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", aegis: "active" });
});

// ─── Start ──────────────────────────────────────────────────────────────────

app.listen(port, () => {
  console.log(`Express chatbot running on http://localhost:${port}`);
  console.log("POST /api/chat with { messages: [...] }");
});
