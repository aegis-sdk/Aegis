import { json } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import OpenAI from "openai";
import { Aegis, AegisInputBlocked } from "@aegis-sdk/core";

const openai = new OpenAI();
const aegis = new Aegis({
  policy: "balanced",
  canaryTokens: ["SYSTEM_CANARY_TOKEN"],
  monitor: { detectPII: true, detectSecrets: true },
  agentLoop: { defaultMaxSteps: 10 },
});

const TOOLS: OpenAI.Chat.Completions.ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "search",
      description: "Search for information",
      parameters: { type: "object", properties: { query: { type: "string" } }, required: ["query"] },
    },
  },
];

export const POST: RequestHandler = async ({ request }) => {
  const { messages } = await request.json();

  try {
    // 1. Guard input — scan for prompt injection
    const safeMessages = await aegis.guardInput(messages);

    // 2. Agentic loop — model may call tools
    let step = 0;
    let currentMessages = [...safeMessages];

    while (step < 10) {
      step++;

      const response = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: currentMessages,
        tools: TOOLS,
      });

      const choice = response.choices[0]!;

      if (choice.finish_reason === "tool_calls" && choice.message.tool_calls) {
        // 3. Guard each chain step — scan tool output before feeding back
        for (const toolCall of choice.message.tool_calls) {
          const toolOutput = `Simulated result for: ${toolCall.function.arguments}`;

          const stepResult = await aegis.guardChainStep(toolOutput, {
            step,
            initialTools: ["search"],
          });

          if (!stepResult.safe) {
            return json({ error: "Chain step blocked", reason: stepResult.reason }, { status: 403 });
          }

          currentMessages.push(choice.message as OpenAI.Chat.Completions.ChatCompletionMessageParam);
          currentMessages.push({
            role: "tool",
            tool_call_id: toolCall.id,
            content: toolOutput,
          });
        }
      } else {
        // Final response — return it
        return json({ content: choice.message.content });
      }
    }

    return json({ error: "Step budget exceeded" }, { status: 429 });
  } catch (err) {
    if (err instanceof AegisInputBlocked) {
      return json(
        { error: "Input blocked", detections: err.scanResult.detections },
        { status: 403 },
      );
    }
    throw err;
  }
};
