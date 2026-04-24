import { createHash, randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

const APPROVAL_TOKEN = process.env.MCP_AUTH_TOKEN!;
const ACCESS_TOKEN_TTL_SEC = 3600;
const AUTH_CODE_TTL_SEC = 600;

interface Client {
  client_id: string;
  client_secret: string | null;
  redirect_uris: string[];
  client_name?: string;
  token_endpoint_auth_method: string;
  created_at: number;
}

interface AuthCode {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  scope?: string;
  expires_at: number;
  used: boolean;
}

interface AccessToken {
  client_id: string;
  expires_at: number;
  scope?: string;
}

interface RefreshToken {
  client_id: string;
  scope?: string;
}

const clients = new Map<string, Client>();
const authCodes = new Map<string, AuthCode>();
const accessTokens = new Map<string, AccessToken>();
const refreshTokens = new Map<string, RefreshToken>();

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("hex");
}

function sha256b64url(s: string): string {
  return createHash("sha256").update(s).digest("base64url");
}

export function baseUrl(req: IncomingMessage): string {
  const proto = (req.headers["x-forwarded-proto"] as string) || "https";
  const host = req.headers.host;
  return `${proto}://${host}`;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(body));
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf-8");
  return raw ? JSON.parse(raw) : {};
}

async function readForm(req: IncomingMessage): Promise<Record<string, string>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf-8");
  const params = new URLSearchParams(raw);
  const out: Record<string, string> = {};
  for (const [k, v] of params) out[k] = v;
  return out;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    switch (c) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      case "'": return "&#39;";
      default: return c;
    }
  });
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of authCodes) if (v.expires_at < now) authCodes.delete(k);
  for (const [k, v] of accessTokens) if (v.expires_at < now) accessTokens.delete(k);
}, 60_000).unref();

export function validateAccessToken(raw: string): boolean {
  const tok = accessTokens.get(raw);
  if (!tok) return false;
  if (tok.expires_at < Date.now()) {
    accessTokens.delete(raw);
    return false;
  }
  return true;
}

export function handleAuthServerMetadata(req: IncomingMessage, res: ServerResponse): void {
  const base = baseUrl(req);
  json(res, 200, {
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    scopes_supported: ["mcp"],
  });
}

export function handleProtectedResourceMetadata(req: IncomingMessage, res: ServerResponse): void {
  const base = baseUrl(req);
  json(res, 200, {
    resource: `${base}/mcp`,
    authorization_servers: [base],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp"],
  });
}

export async function handleRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== "POST") {
    json(res, 405, { error: "method_not_allowed" });
    return;
  }
  let body: Record<string, unknown>;
  try {
    body = await readJson(req);
  } catch {
    json(res, 400, { error: "invalid_client_metadata", error_description: "body must be JSON" });
    return;
  }
  const redirect_uris = body.redirect_uris;
  if (!Array.isArray(redirect_uris) || redirect_uris.length === 0 || !redirect_uris.every((u) => typeof u === "string")) {
    json(res, 400, { error: "invalid_redirect_uri", error_description: "redirect_uris required" });
    return;
  }
  const token_endpoint_auth_method = (body.token_endpoint_auth_method as string) || "none";
  const client_id = randomToken(16);
  const client_secret = token_endpoint_auth_method === "none" ? null : randomToken(32);
  const client: Client = {
    client_id,
    client_secret,
    redirect_uris: redirect_uris as string[],
    client_name: typeof body.client_name === "string" ? body.client_name : undefined,
    token_endpoint_auth_method,
    created_at: Date.now(),
  };
  clients.set(client_id, client);
  const response: Record<string, unknown> = {
    client_id,
    client_id_issued_at: Math.floor(client.created_at / 1000),
    redirect_uris: client.redirect_uris,
    token_endpoint_auth_method,
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  };
  if (client.client_name) response.client_name = client.client_name;
  if (client_secret) response.client_secret = client_secret;
  json(res, 201, response);
}

export async function handleAuthorize(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", baseUrl(req));

  if (req.method === "GET") {
    const p = url.searchParams;
    const response_type = p.get("response_type");
    const client_id = p.get("client_id");
    const redirect_uri = p.get("redirect_uri");
    const state = p.get("state") ?? "";
    const code_challenge = p.get("code_challenge") ?? "";
    const code_challenge_method = p.get("code_challenge_method") ?? "";
    const scope = p.get("scope") ?? "";

    if (response_type !== "code") {
      json(res, 400, { error: "unsupported_response_type" });
      return;
    }
    if (!client_id || !clients.has(client_id)) {
      json(res, 400, { error: "invalid_client" });
      return;
    }
    const client = clients.get(client_id)!;
    if (!redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
      json(res, 400, { error: "invalid_redirect_uri" });
      return;
    }
    if (!code_challenge || code_challenge_method !== "S256") {
      json(res, 400, { error: "invalid_request", error_description: "PKCE with S256 required" });
      return;
    }

    const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>agent-ops — authorize</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0a0e1a; color: #e8ecf4; margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
  .card { background: #111827; border: 1px solid #283350; border-top: 1px solid rgba(255,255,255,0.04); border-radius: 14px; padding: 32px; max-width: 440px; width: 100%; box-shadow: 0 10px 30px rgba(0,0,0,0.4); }
  h1 { margin: 0 0 8px; font-size: 20px; font-weight: 800; color: #a3e635; text-shadow: 0 0 20px rgba(132,204,22,0.2); }
  p { color: #8192ad; font-size: 14px; line-height: 1.5; margin: 0 0 16px; }
  .app { background: #1a2336; border: 1px solid #283350; padding: 12px 14px; border-radius: 8px; margin: 16px 0; font-size: 14px; font-weight: 600; }
  label { display: block; font-size: 11px; color: #8192ad; margin: 20px 0 6px; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; }
  input[type=password] { width: 100%; background: #1a2336; border: 1px solid #283350; color: #e8ecf4; padding: 10px 12px; border-radius: 8px; font-size: 14px; font-family: SFMono-Regular, Menlo, monospace; }
  input[type=password]:focus { outline: none; border-color: #84cc16; box-shadow: 0 0 0 3px rgba(132,204,22,0.2); }
  .row { display: flex; gap: 8px; margin-top: 24px; }
  button { flex: 1; padding: 11px 16px; border-radius: 8px; border: none; font-weight: 600; font-size: 14px; cursor: pointer; font-family: inherit; transition: all 0.15s cubic-bezier(0.4,0,0.2,1); }
  button:active { transform: scale(0.97); }
  .approve { background: linear-gradient(180deg, #84cc16 0%, #6aa311 100%); color: #fff; box-shadow: 0 2px 8px rgba(132,204,22,0.25); }
  .approve:hover { box-shadow: 0 4px 14px rgba(132,204,22,0.35); transform: translateY(-1px); }
  .deny { background: transparent; border: 1px solid #283350; color: #8192ad; }
  .deny:hover { background: rgba(255,255,255,0.04); }
</style>
</head><body>
<form class="card" method="POST" action="/authorize">
  <h1>Authorize connection</h1>
  <p>An application wants to connect to your agent-ops MCP server and manage your Anthropic agents on your behalf.</p>
  <div class="app">${escapeHtml(client.client_name || client.client_id)}</div>
  <label for="approval">Approval password</label>
  <input type="password" id="approval" name="approval" autofocus required />
  <input type="hidden" name="client_id" value="${escapeHtml(client_id)}" />
  <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}" />
  <input type="hidden" name="state" value="${escapeHtml(state)}" />
  <input type="hidden" name="code_challenge" value="${escapeHtml(code_challenge)}" />
  <input type="hidden" name="code_challenge_method" value="${escapeHtml(code_challenge_method)}" />
  <input type="hidden" name="scope" value="${escapeHtml(scope)}" />
  <div class="row">
    <button type="submit" name="action" value="deny" class="deny">Deny</button>
    <button type="submit" name="action" value="approve" class="approve">Approve</button>
  </div>
</form>
</body></html>`;
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(html);
    return;
  }

  if (req.method === "POST") {
    const form = await readForm(req);
    const client_id = form.client_id;
    const redirect_uri = form.redirect_uri;
    const state = form.state ?? "";
    const action = form.action;
    const approval = form.approval;
    const code_challenge = form.code_challenge;
    const code_challenge_method = form.code_challenge_method;

    const client = clients.get(client_id);
    if (!client || !client.redirect_uris.includes(redirect_uri)) {
      json(res, 400, { error: "invalid_client" });
      return;
    }

    if (action === "deny") {
      const u = new URL(redirect_uri);
      u.searchParams.set("error", "access_denied");
      if (state) u.searchParams.set("state", state);
      res.writeHead(302, { location: u.toString() });
      res.end();
      return;
    }

    if (approval !== APPROVAL_TOKEN) {
      res.writeHead(401, { "content-type": "text/html; charset=utf-8" });
      res.end(`<!doctype html><html><body style="font-family:-apple-system,sans-serif;background:#0a0e1a;color:#e8ecf4;padding:32px;max-width:480px;margin:40px auto;"><h2 style="color:#ef4444;margin:0 0 8px;">Wrong approval password</h2><p style="color:#8192ad;">The approval password does not match the <code>MCP_AUTH_TOKEN</code> configured on this server.</p><p><a href="javascript:history.back()" style="color:#84cc16;">← Go back and try again</a></p></body></html>`);
      return;
    }

    const code = randomToken(32);
    authCodes.set(code, {
      client_id,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      scope: form.scope,
      expires_at: Date.now() + AUTH_CODE_TTL_SEC * 1000,
      used: false,
    });
    const u = new URL(redirect_uri);
    u.searchParams.set("code", code);
    if (state) u.searchParams.set("state", state);
    res.writeHead(302, { location: u.toString() });
    res.end();
    return;
  }

  json(res, 405, { error: "method_not_allowed" });
}

export async function handleToken(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== "POST") {
    json(res, 405, { error: "method_not_allowed" });
    return;
  }
  const form = await readForm(req);
  const grant_type = form.grant_type;

  if (grant_type === "authorization_code") {
    const code = form.code;
    const verifier = form.code_verifier;
    const redirect_uri = form.redirect_uri;
    const client_id = form.client_id;
    const entry = code ? authCodes.get(code) : undefined;
    if (!entry || entry.used || entry.expires_at < Date.now()) {
      json(res, 400, { error: "invalid_grant" });
      return;
    }
    if (entry.client_id !== client_id || entry.redirect_uri !== redirect_uri) {
      json(res, 400, { error: "invalid_grant" });
      return;
    }
    const expected = sha256b64url(verifier ?? "");
    if (expected !== entry.code_challenge) {
      json(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
      return;
    }
    entry.used = true;
    const access_token = randomToken(32);
    const refresh_token = randomToken(32);
    accessTokens.set(access_token, {
      client_id,
      expires_at: Date.now() + ACCESS_TOKEN_TTL_SEC * 1000,
      scope: entry.scope,
    });
    refreshTokens.set(refresh_token, { client_id, scope: entry.scope });
    const body: Record<string, unknown> = {
      access_token,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SEC,
      refresh_token,
    };
    if (entry.scope) body.scope = entry.scope;
    json(res, 200, body);
    return;
  }

  if (grant_type === "refresh_token") {
    const old = form.refresh_token;
    const entry = old ? refreshTokens.get(old) : undefined;
    if (!entry) {
      json(res, 400, { error: "invalid_grant" });
      return;
    }
    const access_token = randomToken(32);
    const new_refresh_token = randomToken(32);
    accessTokens.set(access_token, {
      client_id: entry.client_id,
      expires_at: Date.now() + ACCESS_TOKEN_TTL_SEC * 1000,
      scope: entry.scope,
    });
    refreshTokens.delete(old);
    refreshTokens.set(new_refresh_token, { client_id: entry.client_id, scope: entry.scope });
    const body: Record<string, unknown> = {
      access_token,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SEC,
      refresh_token: new_refresh_token,
    };
    if (entry.scope) body.scope = entry.scope;
    json(res, 200, body);
    return;
  }

  json(res, 400, { error: "unsupported_grant_type" });
}
