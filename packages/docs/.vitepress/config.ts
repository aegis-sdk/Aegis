import { defineConfig } from "vitepress";

export default defineConfig({
  title: "Aegis SDK",
  description: "Streaming-first prompt injection defense for JavaScript & TypeScript",

  head: [
    ["meta", { name: "theme-color", content: "#646cff" }],
    ["meta", { name: "og:type", content: "website" }],
    ["meta", { name: "og:title", content: "Aegis SDK" }],
    [
      "meta",
      {
        name: "og:description",
        content: "Streaming-first prompt injection defense for JavaScript & TypeScript",
      },
    ],
  ],

  ignoreDeadLinks: true,

  themeConfig: {
    nav: [
      { text: "Guide", link: "/guide/" },
      { text: "API", link: "/api/" },
      { text: "Testing", link: "/testing/" },
    ],

    sidebar: {
      "/guide/": [
        {
          text: "Getting Started",
          items: [
            { text: "Introduction", link: "/guide/" },
            { text: "Quick Start", link: "/guide/quick-start" },
            { text: "Installation", link: "/guide/installation" },
            { text: "Configuration", link: "/guide/configuration" },
            { text: "Troubleshooting", link: "/guide/troubleshooting" },
            {
              text: "Production Deployment",
              link: "/guide/production",
            },
          ],
        },
        {
          text: "Core Concepts",
          items: [
            { text: "Quarantine", link: "/guide/quarantine" },
            { text: "Input Scanner", link: "/guide/input-scanner" },
            { text: "Stream Monitor", link: "/guide/stream-monitor" },
            { text: "Prompt Builder", link: "/guide/prompt-builder" },
            { text: "Policy Engine", link: "/guide/policy-engine" },
            { text: "Action Validator", link: "/guide/action-validator" },
            { text: "Audit Log", link: "/guide/audit-log" },
            { text: "Sandbox", link: "/guide/sandbox" },
          ],
        },
        {
          text: "Framework Guides",
          items: [
            { text: "Vercel AI SDK", link: "/guide/vercel-ai" },
            { text: "Next.js", link: "/guide/nextjs" },
            { text: "Express", link: "/guide/express" },
            { text: "SvelteKit", link: "/guide/sveltekit" },
            { text: "Hono", link: "/guide/hono" },
            { text: "Fastify", link: "/guide/fastify" },
          ],
        },
        {
          text: "Provider Adapters",
          items: [
            { text: "OpenAI", link: "/guide/openai" },
            { text: "Anthropic", link: "/guide/anthropic" },
            { text: "Google", link: "/guide/google" },
            { text: "Mistral", link: "/guide/mistral" },
            { text: "Ollama", link: "/guide/ollama" },
            { text: "LangChain", link: "/guide/langchain" },
          ],
        },
        {
          text: "Advanced",
          items: [
            { text: "Agentic Defense", link: "/advanced/" },
            { text: "MCP Integration", link: "/advanced/mcp" },
            { text: "Alerting", link: "/advanced/alerting" },
            { text: "Message Integrity", link: "/advanced/integrity" },
            {
              text: "Trajectory Analysis",
              link: "/advanced/trajectory",
            },
            {
              text: "Perplexity Analysis",
              link: "/advanced/perplexity",
            },
            { text: "LLM Judge", link: "/advanced/llm-judge" },
            {
              text: "Multi-Modal Scanning",
              link: "/advanced/multimodal",
            },
            { text: "Auto-Retry", link: "/advanced/auto-retry" },
          ],
        },
      ],

      "/api/": [
        {
          text: "API Reference",
          items: [
            { text: "Overview", link: "/api/" },
            { text: "Aegis Class", link: "/api/aegis" },
            { text: "InputScanner", link: "/api/input-scanner" },
            { text: "StreamMonitor", link: "/api/stream-monitor" },
            { text: "PromptBuilder", link: "/api/prompt-builder" },
            { text: "PolicyEngine", link: "/api/policy-engine" },
            { text: "ActionValidator", link: "/api/action-validator" },
            { text: "AuditLog", link: "/api/audit-log" },
            { text: "Quarantine", link: "/api/quarantine" },
            { text: "Types", link: "/api/types" },
          ],
        },
      ],

      "/testing/": [
        {
          text: "Testing",
          items: [
            { text: "Overview", link: "/testing/" },
            { text: "Red Team Scanner", link: "/testing/red-team" },
            { text: "CLI Tool", link: "/testing/cli" },
            {
              text: "Promptfoo Integration",
              link: "/testing/promptfoo",
            },
            { text: "Boss Battle", link: "/testing/boss-battle" },
          ],
        },
      ],

      "/advanced/": [
        {
          text: "Advanced Topics",
          items: [
            { text: "Agentic Defense", link: "/advanced/" },
            { text: "MCP Integration", link: "/advanced/mcp" },
            { text: "Alerting", link: "/advanced/alerting" },
            { text: "Message Integrity", link: "/advanced/integrity" },
            {
              text: "Trajectory Analysis",
              link: "/advanced/trajectory",
            },
            {
              text: "Perplexity Analysis",
              link: "/advanced/perplexity",
            },
            { text: "LLM Judge", link: "/advanced/llm-judge" },
            {
              text: "Multi-Modal Scanning",
              link: "/advanced/multimodal",
            },
            { text: "Auto-Retry", link: "/advanced/auto-retry" },
          ],
        },
      ],
    },

    socialLinks: [{ icon: "github", link: "https://github.com/aegis-sdk/Aegis" }],

    footer: {
      message: "Released under the MIT License.",
      copyright: "Copyright 2026-present Aegis SDK Contributors",
    },

    search: {
      provider: "local",
    },

    editLink: {
      pattern: "https://github.com/aegis-sdk/Aegis/edit/main/packages/docs/:path",
      text: "Edit this page on GitHub",
    },
  },
});
