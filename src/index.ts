import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import http from "node:http";
import { randomUUID } from "node:crypto";
import {
  baseUrl,
  handleAuthServerMetadata,
  handleAuthorize,
  handleProtectedResourceMetadata,
  handleRegister,
  handleToken,
  validateAccessToken,
} from "./oauth.js";

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
  "List all agents in your Anthropic Console. By default excludes archived agents.",
  {
    include_archived: z
      .boolean()
      .optional()
      .describe("Include archived agents in the list (default false)"),
  },
  async ({ include_archived }) => {
    const qs = include_archived ? "?include_archived=true" : "";
    return ok(await api(`/agents${qs}`));
  }
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
  "Create a new agent configuration in Anthropic Console. Name must be 1-256 chars. System prompt is limited to 100KB. Max 50 tools, 64 skills, 20 MCP servers.",
  {
    name: z.string().describe("Human-readable name (1-256 chars)"),
    model: z.string().describe("Model ID, e.g. claude-opus-4-7 or claude-sonnet-4-6"),
    system: z.string().describe("System prompt that defines what this agent does (max 100KB)"),
    description: z.string().optional(),
    include_default_toolset: z
      .boolean()
      .default(true)
      .describe("Include the default agent toolset (bash, file ops, web search, etc)"),
    skills: z
      .array(z.string())
      .optional()
      .describe("Optional array of skill IDs to attach"),
  },
  async ({ name, model, system, description, include_default_toolset, skills }) => {
    const body: Record<string, unknown> = { name, model, system };
    if (description) body.description = description;
    if (include_default_toolset) {
      body.tools = [
        {
          type: "agent_toolset_20260401",
          default_config: { permission_policy: { type: "always_allow" } },
        },
      ];
    }
    if (skills && skills.length > 0) {
      body.skills = skills.map((id) => ({ id }));
    }
    return ok(
      await api("/agents", {
        method: "POST",
        body: JSON.stringify(body),
      })
    );
  }
);

server.tool(
  "update_agent",
  "Update an agent — system prompt, name, model, or description. Only pass fields you want to change. Creates a new agent version; fetch the latest with get_agent first if you need the current state.",
  {
    agent_id: z.string(),
    system: z.string().optional().describe("New system prompt (max 100KB)"),
    name: z.string().optional().describe("New name (1-256 chars)"),
    model: z.string().optional().describe("New model ID"),
    description: z.string().optional(),
  },
  async ({ agent_id, system, name, model, description }) => {
    const body: Record<string, unknown> = {};
    if (system !== undefined) body.system = system;
    if (name !== undefined) body.name = name;
    if (model !== undefined) body.model = model;
    if (description !== undefined) body.description = description;
    return ok(
      await api(`/agents/${agent_id}`, {
        method: "POST",
        body: JSON.stringify(body),
      })
    );
  }
);

server.tool(
  "archive_agent",
  "Archive an agent — makes it read-only and prevents new sessions from referencing it. Existing sessions continue running.",
  { agent_id: z.string() },
  async ({ agent_id }) =>
    ok(await api(`/agents/${agent_id}/archive`, { method: "POST" }))
);

// ── SESSIONS ──────────────────────────────────────────────────────────────────
// A session is a stateful running conversation with an agent inside a sandbox
// container (environment). Lifecycle: create_session → send_message → list_session_events
// (repeat) → archive_session when done (to stop idle billing).

server.tool(
  "list_sessions",
  "List recent agent sessions. Supports optional pagination cursor.",
  {
    cursor: z.string().optional().describe("Pagination cursor from a previous response"),
    limit: z.number().int().min(1).max(100).optional(),
  },
  async ({ cursor, limit }) => {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));
    const qs = params.toString() ? `?${params.toString()}` : "";
    return ok(await api(`/sessions${qs}`));
  }
);

server.tool(
  "get_session",
  "Get the current status and details of a specific session (running, stopped, failed, etc).",
  { session_id: z.string() },
  async ({ session_id }) => ok(await api(`/sessions/${session_id}`))
);

server.tool(
  "create_session",
  "Start a new agent session. Requires an agent_id and an environment_id (use list_environments to find one). The session boots in a sandbox container and is immediately ready to receive messages via send_message.",
  {
    agent_id: z.string().describe("ID of the agent to run"),
    environment_id: z.string().describe("ID of the environment (sandbox config)"),
    title: z.string().optional().describe("Optional human-readable session title"),
    agent_version: z
      .number()
      .optional()
      .describe("Pin to a specific agent version. Omit to use latest."),
  },
  async ({ agent_id, environment_id, title, agent_version }) => {
    const body: Record<string, unknown> = {
      agent:
        agent_version !== undefined
          ? { type: "agent", id: agent_id, version: agent_version }
          : agent_id,
      environment_id,
    };
    if (title) body.title = title;
    return ok(
      await api("/sessions", {
        method: "POST",
        body: JSON.stringify(body),
      })
    );
  }
);

server.tool(
  "send_message",
  "Send a user message to a running session. The agent will begin responding asynchronously; use list_session_events to read its response.",
  {
    session_id: z.string(),
    text: z.string().describe("The message content to send to the agent"),
  },
  async ({ session_id, text }) =>
    ok(
      await api(`/sessions/${session_id}/events`, {
        method: "POST",
        body: JSON.stringify([
          { type: "user.message", content: [{ type: "text", text }] },
        ]),
      })
    )
);

server.tool(
  "list_session_events",
  "List events from a session — the agent's messages, tool calls, tool results, and user messages, in order. Use the returned cursor to poll for new events as the agent runs.",
  {
    session_id: z.string(),
    cursor: z.string().optional().describe("Pagination cursor to fetch only events after a point"),
    limit: z.number().int().min(1).max(100).optional(),
  },
  async ({ session_id, cursor, limit }) => {
    const params = new URLSearchParams();
    if (cursor) params.set("cursor", cursor);
    if (limit) params.set("limit", String(limit));
    const qs = params.toString() ? `?${params.toString()}` : "";
    return ok(await api(`/sessions/${session_id}/events${qs}`));
  }
);

server.tool(
  "archive_session",
  "Stop and archive a session. Use this when done with a session to halt any idle billing. Session events remain readable after archiving.",
  { session_id: z.string() },
  async ({ session_id }) =>
    ok(await api(`/sessions/${session_id}/archive`, { method: "POST" }))
);

server.tool(
  "delete_session",
  "Permanently delete a session and its events. Cannot be undone. Prefer archive_session unless you need to purge data.",
  { session_id: z.string() },
  async ({ session_id }) =>
    ok(await api(`/sessions/${session_id}`, { method: "DELETE" }))
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
  "Create a new environment — a sandbox container template that sessions run in. Config is optional; omitting it creates a default Linux sandbox. Rate-limited to 60 RPM with max 5 concurrent creations.",
  {
    name: z.string(),
    description: z.string().optional(),
    config: z
      .record(z.unknown())
      .optional()
      .describe(
        "Optional container config object (e.g. { type, networking, packages }). Passed through raw to the API."
      ),
  },
  async ({ name, description, config }) => {
    const body: Record<string, unknown> = { name };
    if (description) body.description = description;
    if (config) body.config = config;
    return ok(
      await api("/environments", {
        method: "POST",
        body: JSON.stringify(body),
      })
    );
  }
);

server.tool(
  "delete_environment",
  "Delete an environment configuration",
  { environment_id: z.string() },
  async ({ environment_id }) =>
    ok(await api(`/environments/${environment_id}`, { method: "DELETE" }))
);

// ── SKILLS ────────────────────────────────────────────────────────────────────
// Skills use a different beta header than the rest of Managed Agents.

const SKILLS_HEADERS = { "anthropic-beta": "skills-2025-10-02" };

server.tool(
  "list_skills",
  "List all custom skills uploaded to your Anthropic Console. Skills are reusable instructions and reference files you can attach to agents via create_agent or update_agent.",
  {},
  async () => ok(await api("/skills", { headers: SKILLS_HEADERS }))
);

server.tool(
  "get_skill",
  "Get full details for a specific skill, including its current version.",
  { skill_id: z.string() },
  async ({ skill_id }) =>
    ok(await api(`/skills/${skill_id}`, { headers: SKILLS_HEADERS }))
);

server.tool(
  "list_skill_versions",
  "List the full version history of a skill.",
  { skill_id: z.string() },
  async ({ skill_id }) =>
    ok(await api(`/skills/${skill_id}/versions`, { headers: SKILLS_HEADERS }))
);

// ── HTTP SERVER ───────────────────────────────────────────────────────────────

const transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => randomUUID(),
});

const httpServer = http.createServer(async (req, res) => {
  const path = (req.url ?? "/").split("?")[0];

  if (path === "/.well-known/oauth-authorization-server") {
    handleAuthServerMetadata(req, res);
    return;
  }
  if (path === "/.well-known/oauth-protected-resource") {
    handleProtectedResourceMetadata(req, res);
    return;
  }
  if (path === "/register") {
    await handleRegister(req, res);
    return;
  }
  if (path === "/authorize") {
    await handleAuthorize(req, res);
    return;
  }
  if (path === "/token") {
    await handleToken(req, res);
    return;
  }

  if (path === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ name: "agent-ops", status: "ok" }));
    return;
  }

  const isMcpPath = path === "/" || path === "/mcp";
  if (!isMcpPath) {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
    return;
  }

  const authHeader = req.headers.authorization;
  const match = authHeader ? authHeader.match(/^Bearer\s+(.+)$/i) : null;
  const accessToken = match ? match[1] : null;
  if (!accessToken || !validateAccessToken(accessToken)) {
    const base = baseUrl(req);
    res.writeHead(401, {
      "content-type": "application/json",
      "www-authenticate": `Bearer realm="mcp", resource_metadata="${base}/.well-known/oauth-protected-resource"`,
    });
    res.end(JSON.stringify({ error: "unauthorized" }));
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
        res.end(JSON.stringify({ error: "invalid_json" }));
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
