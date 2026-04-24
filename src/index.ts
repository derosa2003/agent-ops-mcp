import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import http from "node:http";
import { randomUUID } from "node:crypto";

const API_KEY = process.env.ANTHROPIC_API_KEY;
const MCP_AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;

if (!API_KEY) throw new Error("ANTHROPIC_API_KEY env var is required");
if (!MCP_AUTH_TOKEN) throw new Error("MCP_AUTH_TOKEN env var is required");

const BASE = "https://api.anthropic.com/v1";

const HEADERS: Record<string, string> = {
  "x-api-key": API_KEY,
  "anthropic-version": "2023-06-01",
  "anthropic-beta": "managed-agents-2026-04-01",
  "content-type": "application/json",
};

async function api(path: string, options: RequestInit = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { ...HEADERS, ...(options.headers as Record<string, string> || {}) },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(JSON.stringify(data, null, 2));
  return data;
}

function ok(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

const server = new McpServer({ name: "agent-ops", version: "1.0.0" });

// ── AGENTS ────────────────────────────────────────────────────────────────────

server.tool(
  "list_agents",
  "List all agents in your Anthropic Console",
  {},
  async () => ok(await api("/agents"))
);

server.tool(
  "get_agent",
  "Get the full config and current version for a specific agent",
  { agent_id: z.string().describe("Agent ID, e.g. agent_01HqR2k7vXbZ9...") },
  async ({ agent_id }) => ok(await api(`/agents/${agent_id}`))
);

server.tool(
  "get_agent_versions",
  "Get the full version history of an agent to see how it has changed over time",
  { agent_id: z.string() },
  async ({ agent_id }) => ok(await api(`/agents/${agent_id}/versions`))
);

server.tool(
  "create_agent",
  "Create a new agent configuration in Anthropic Console",
  {
    name: z.string().describe("Human-readable name for the agent"),
    model_id: z.string().describe("Model ID, e.g. claude-opus-4-7 or claude-sonnet-4-6"),
    system: z.string().describe("The system prompt that defines what this agent does"),
    description: z.string().optional().describe("Optional description"),
    include_default_toolset: z
      .boolean()
      .default(true)
      .describe("Whether to include the default agent toolset (bash, file ops, web search, etc)"),
  },
  async ({ name, model_id, system, description, include_default_toolset }) =>
    ok(
      await api("/agents", {
        method: "POST",
        body: JSON.stringify({
          name,
          model: { id: model_id },
          system,
          ...(description && { description }),
          tools: include_default_toolset
            ? [
                {
                  type: "agent_toolset_20260401",
                  default_config: { permission_policy: { type: "always_allow" } },
                },
              ]
            : [],
        }),
      })
    )
);

server.tool(
  "update_agent",
  "Update an agent — system prompt, name, model, or description. Only include fields you want to change. Requires current version number to prevent overwriting concurrent changes.",
  {
    agent_id: z.string(),
    version: z.number().describe("Current version number — get this from get_agent first"),
    system: z.string().optional().describe("New system prompt"),
    name: z.string().optional().describe("New name"),
    model_id: z.string().optional().describe("New model ID"),
    description: z.string().optional(),
  },
  async ({ agent_id, version, system, name, model_id, description }) =>
    ok(
      await api(`/agents/${agent_id}`, {
        method: "PATCH",
        body: JSON.stringify({
          version,
          ...(system !== undefined && { system }),
          ...(name !== undefined && { name }),
          ...(model_id !== undefined && { model: { id: model_id } }),
          ...(description !== undefined && { description }),
        }),
      })
    )
);

server.tool(
  "archive_agent",
  "Archive an agent — makes it read-only and prevents new sessions from referencing it. Existing sessions continue running.",
  { agent_id: z.string() },
  async ({ agent_id }) =>
    ok(await api(`/agents/${agent_id}/archive`, { method: "POST" }))
);

// ── SESSIONS ──────────────────────────────────────────────────────────────────

server.tool(
  "list_sessions",
  "List recent agent sessions, optionally filtered by agent",
  {
    agent_id: z.string().optional().describe("Filter sessions by a specific agent ID"),
  },
  async ({ agent_id }) => {
    const qs = agent_id ? `?agent_id=${agent_id}` : "";
    return ok(await api(`/sessions${qs}`));
  }
);

server.tool(
  "get_session",
  "Get the current status and details of a specific session",
  { session_id: z.string() },
  async ({ session_id }) => ok(await api(`/sessions/${session_id}`))
);

server.tool(
  "stop_session",
  "Stop a running session. Use this to avoid idle billing charges.",
  { session_id: z.string() },
  async ({ session_id }) =>
    ok(await api(`/sessions/${session_id}/stop`, { method: "POST" }))
);

// ── ENVIRONMENTS ──────────────────────────────────────────────────────────────

server.tool(
  "list_environments",
  "List all environment (sandbox container) configurations",
  {},
  async () => ok(await api("/environments"))
);

server.tool(
  "get_environment",
  "Get full configuration for a specific environment",
  { environment_id: z.string() },
  async ({ environment_id }) => ok(await api(`/environments/${environment_id}`))
);

server.tool(
  "create_environment",
  "Create a new environment configuration — defines the sandbox container your agent sessions run in",
  {
    name: z.string(),
    description: z.string().optional(),
  },
  async ({ name, description }) =>
    ok(
      await api("/environments", {
        method: "POST",
        body: JSON.stringify({ name, ...(description && { description }) }),
      })
    )
);

server.tool(
  "delete_environment",
  "Delete an environment configuration",
  { environment_id: z.string() },
  async ({ environment_id }) =>
    ok(await api(`/environments/${environment_id}`, { method: "DELETE" }))
);

// ── SKILLS ────────────────────────────────────────────────────────────────────

server.tool(
  "list_skills",
  "List all custom skills uploaded to your Anthropic Console",
  {},
  async () => ok(await api("/skills"))
);

server.tool(
  "get_skill",
  "Get full details for a specific skill",
  { skill_id: z.string() },
  async ({ skill_id }) => ok(await api(`/skills/${skill_id}`))
);

// ── HTTP SERVER ───────────────────────────────────────────────────────────────

const transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => randomUUID(),
});

const httpServer = http.createServer(async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || auth !== `Bearer ${MCP_AUTH_TOKEN}`) {
    res.writeHead(401, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized" }));
    return;
  }
  if (!req.url || !req.url.startsWith("/mcp")) {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "Not Found" }));
    return;
  }
  let body: unknown = undefined;
  if (req.method === "POST") {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const raw = Buffer.concat(chunks).toString("utf-8");
    if (raw.length > 0) {
      try {
        body = JSON.parse(raw);
      } catch {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON body" }));
        return;
      }
    }
  }
  await transport.handleRequest(req, res, body);
});

await server.connect(transport);

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`agent-ops MCP server running on port ${PORT}`);
});
