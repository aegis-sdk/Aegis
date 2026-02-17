import { type CoreMessage, streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { Aegis, AegisInputBlocked } from "@aegis-sdk/core";
import { guardMessages } from "@aegis-sdk/vercel";

const aegis = new Aegis({ policy: "strict" });

export async function POST(req: Request) {
  const { messages } = await req.json();

  try {
    // 1. Guard input — scans all user messages for prompt injection
    const safeMessages = await guardMessages(aegis, messages);

    // 2. Stream the response (input has been validated by Aegis)
    const result = streamText({
      model: openai("gpt-4o-mini"),
      messages: safeMessages as CoreMessage[],
    });

    // 3. Return the streamed response
    return result.toDataStreamResponse();
  } catch (err) {
    if (err instanceof AegisInputBlocked) {
      return new Response(
        JSON.stringify({ error: "Input blocked by Aegis", details: err.scanResult }),
        { status: 403, headers: { "Content-Type": "application/json" } },
      );
    }
    throw err;
  }
}
