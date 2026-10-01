#!/usr/bin/env node
// OpenAI-compatible bridge exposing opencode's provider catalog to Velora.
// Velora holds no API keys: opencode owns auth and (free) model access.
import http from "node:http";
import { pathToFileURL } from "node:url";
import { createOpencode } from "@opencode-ai/sdk";

const PROVIDER_ID = "opencode";
const MODEL_PREFIX = "opencode/";
const DEFAULT_BRIDGE_PORT = 8399;
const DEFAULT_OC_PORT = 4599;

const READ_ONLY_TOOLS = {
  read: true, grep: true, glob: true, list: true, bash: true,
  edit: false, write: false, patch: false, task: false, webfetch: false,
  todowrite: false, todoread: false,
};

const TOOL_BRIDGE_NOTE = [
  "Tool bridge note: this environment exposes opencode's tools rather than",
  "tool schemas named in this conversation. Available tools: `read` (read a",
  "file; acts as read_file), `grep` (search; acts as grep), `glob` (list files",
  "matching a pattern; acts as list_files), `bash` (run a shell command).",
  "Use them to explore the repository; produce the final answer in one turn.",
].join(" ");

export function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        out[key] = next;
        i++;
      } else {
        out[key] = true;
      }
    }
  }
  return out;
}

export function parseModel(model) {
  if (typeof model !== "string" || !model.startsWith(MODEL_PREFIX)) {
    const err = new Error(
      `this bridge only serves ${MODEL_PREFIX}* models (opencode provider); got ${JSON.stringify(model)}`);
    err.status = 404;
    err.type = "invalid_request_error";
    err.code = "model_not_found";
    throw err;
  }
  const modelID = model.slice(MODEL_PREFIX.length);
  if (!modelID || modelID.includes("/")) {
    const err = new Error(`invalid opencode model id: ${JSON.stringify(model)}`);
    err.status = 404;
    err.type = "invalid_request_error";
    err.code = "model_not_found";
    throw err;
  }
  return modelID;
}

export function contentOf(message) {
  const c = message?.content;
  if (typeof c === "string") return c;
  if (Array.isArray(c)) {
    return c.map((part) => (typeof part === "string" ? part : part?.text || "")).join("");
  }
  return "";
}

export function flattenMessages(messages) {
  const blocks = [];
  for (const m of messages || []) {
    if (!m || typeof m !== "object") continue;
    if (m.role === "system") continue;
    if (m.role === "user") {
      blocks.push(`USER:\n${contentOf(m)}`);
    } else if (m.role === "assistant") {
      let text = contentOf(m);
      const names = (m.tool_calls || [])
        .map((tc) => tc?.function?.name || tc?.name)
        .filter(Boolean);
      if (names.length) text += `\n[requested tool calls: ${names.join(", ")}]`;
      blocks.push(`ASSISTANT:\n${text}`);
    } else if (m.role === "tool") {
      blocks.push(`TOOL RESULT${m.name ? ` (${m.name})` : ""}:\n${contentOf(m)}`);
    } else {
      blocks.push(`${String(m.role).toUpperCase()}:\n${contentOf(m)}`);
    }
  }
  return blocks.join("\n\n");
}

export function buildSystem(messages) {
  const sys = (messages || [])
    .filter((m) => m && m.role === "system")
    .map(contentOf)
    .filter((t) => t && t.trim());
  return sys.join("\n\n");
}

export function estimateTokens(text) {
  return Math.max(1, Math.ceil(String(text || "").length / 4));
}

export function openaiResponse(model, text, promptText) {
  const completionTokens = estimateTokens(text);
  const promptTokens = estimateTokens(promptText);
  return {
    id: `chatcmpl-oc-${Date.now()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{
      index: 0,
      message: { role: "assistant", content: text },
      finish_reason: "stop",
    }],
    usage: {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: promptTokens + completionTokens,
    },
  };
}

export function openaiError(status, message, type, code) {
  return { status, body: { error: { message, type, code } } };
}

function mapOpencodeError(error) {
  const name = error?.name || "UnknownError";
  const message = error?.message || JSON.stringify(error);
  if (name === "ProviderAuthError") {
    return openaiError(401, `opencode provider auth failed: ${message}`,
      "provider_auth_error", error?.data?.providerID || "opencode");
  }
  if (name === "MessageAbortedError") {
    return openaiError(499, `request aborted: ${message}`, "request_aborted", name);
  }
  if (name === "MessageOutputLengthError") {
    return openaiError(400, `model output too long: ${message}`,
      "invalid_request_error", name);
  }
  return openaiError(502, `opencode error (${name}): ${message}`, "opencode_error", name);
}

function unwrap(result, what) {
  if (result && result.error) {
    const mapped = mapOpencodeError(result.error?.data ?? result.error);
    const err = new Error(mapped.body.error.message);
    err.status = mapped.status;
    err.type = mapped.body.error.type;
    err.code = mapped.body.error.code;
    err.phase = what;
    throw err;
  }
  return result?.data;
}

function textFromParts(parts) {
  let out = "";
  for (const p of parts || []) {
    if (p?.type === "text" && typeof p.text === "string") out += p.text;
  }
  return out;
}

async function listOpencodeModels(client) {
  const data = unwrap(await client.config.providers(), "providers");
  const prov = (data?.providers || []).find((p) => p.id === PROVIDER_ID);
  const models = Object.keys(prov?.models || {});
  return models.sort().map((id) => ({
    id: `${MODEL_PREFIX}${id}`,
    object: "model",
    created: 0,
    owned_by: PROVIDER_ID,
  }));
}

async function handleChat(client, body) {
  const modelID = parseModel(body?.model);
  const messages = Array.isArray(body?.messages) ? body.messages : [];
  if (!messages.length) {
    throw Object.assign(new Error("messages must be a non-empty array"),
      { status: 400, type: "invalid_request_error", code: "invalid_messages" });
  }
  let system = buildSystem(messages);
  const wantsTools = Array.isArray(body.tools) && body.tools.length > 0;
  if (wantsTools) system = system ? `${system}\n\n${TOOL_BRIDGE_NOTE}` : TOOL_BRIDGE_NOTE;
  const transcript = flattenMessages(messages);
  const promptBody = {
    model: { providerID: PROVIDER_ID, modelID },
    parts: [{ type: "text", text: transcript }],
  };
  if (wantsTools) promptBody.tools = READ_ONLY_TOOLS;
  if (system) promptBody.system = system;

  const session = unwrap(await client.session.create({ body: {} }), "session.create");
  try {
    const res = unwrap(await client.session.prompt({
      path: { id: session.id },
      body: promptBody,
    }), "session.prompt");
    const info = res?.info || {};
    if (info.error) {
      const mapped = mapOpencodeError(info.error);
      throw Object.assign(new Error(mapped.body.error.message), {
        status: mapped.status, type: mapped.body.error.type, code: mapped.body.error.code,
      });
    }
    const text = textFromParts(res?.parts);
    return openaiResponse(body.model, text, transcript + (system || ""));
  } finally {
    try {
      await client.session.delete({ path: { id: session.id } });
    } catch { /* best-effort cleanup */ }
  }
}

export async function startBridge(options = {}) {
  const bridgePort = Number(options.port ?? DEFAULT_BRIDGE_PORT);
  const opencodePort = Number(options["opencode-port"] ?? options.opencodePort ?? DEFAULT_OC_PORT);
  const enabled = options.tools === "off" ? false : true;

  const instance = await createOpencode({
    hostname: "127.0.0.1",
    port: opencodePort,
    config: {
      enabled_providers: [PROVIDER_ID],
      permission: { bash: "allow", edit: "allow", webfetch: "allow" },
    },
  });
  const { client, server } = instance;

  const routes = {
    "GET /health": async () => ({
      status: 200,
      body: { ok: true, provider: PROVIDER_ID, opencode_url: instance.server?.url || "" },
    }),
    "GET /v1/models": async () => ({
      status: 200,
      body: { object: "list", data: await listOpencodeModels(client) },
    }),
    "POST /v1/chat/completions": async (reqBody) => {
      if (!enabled) {
        const body = { ...(reqBody || {}) };
        delete body.tools;
        delete body.tool_choice;
        return { status: 200, body: await handleChat(client, body) };
      }
      return { status: 200, body: await handleChat(client, reqBody) };
    },
  };

  const httpServer = http.createServer((req, res) => {
    const key = `${req.method} ${req.url.split("?")[0]}`;
    const route = routes[key];
    const send = (status, payload) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    if (!route) {
      const e = openaiError(404, `unknown route: ${key}`, "invalid_request_error", "not_found");
      return send(e.status, e.body);
    }
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 8 * 1024 * 1024) req.destroy();
    });
    req.on("end", async () => {
      let parsed = null;
      if (req.method === "POST") {
        try {
          parsed = raw ? JSON.parse(raw) : {};
        } catch {
          const e = openaiError(400, "request body is not valid JSON",
            "invalid_request_error", "invalid_json");
          return send(e.status, e.body);
        }
      }
      try {
        const out = await route(parsed);
        send(out.status, out.body);
      } catch (err) {
        const status = err.status || 500;
        const body = {
          error: {
            message: err.message || String(err),
            type: err.type || "bridge_error",
            code: err.code || null,
          },
        };
        send(status, body);
      }
    });
  });
  httpServer.requestTimeout = 30 * 60 * 1000;
  httpServer.headersTimeout = 60 * 1000;

  await new Promise((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(bridgePort, "127.0.0.1", resolve);
  });

  const shutdown = () => {
    try { httpServer.close(); } catch { /* already closed */ }
    try { server.close(); } catch { /* already closed */ }
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  return { bridgePort, opencodePort, httpServer, server: server, client };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const { bridgePort, opencodePort } = await startBridge(args);
  process.stdout.write(
    `velora-opencode-bridge listening on http://127.0.0.1:${bridgePort}\n` +
    `opencode instance on http://127.0.0.1:${opencodePort} (provider: ${PROVIDER_ID})\n`);
}

const isMain = process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  main().catch((err) => {
    process.stderr.write(`bridge failed to start: ${err?.message || err}\n`);
    process.exit(1);
  });
}
