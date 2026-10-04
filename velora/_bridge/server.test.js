import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  parseArgs,
  parseModel,
  authProviderIds,
  enabledProviders,
  composeModels,
  handleChat,
  contentOf,
  flattenMessages,
  buildSystem,
  estimateTokens,
  openaiResponse,
  openaiError,
} from "./server.js";

test("parseArgs handles flags with and without values", () => {
  assert.deepEqual(
    parseArgs(["--port", "8400", "--opencode-port", "4600", "--tools", "off", "--verbose"]),
    { port: "8400", "opencode-port": "4600", tools: "off", verbose: true },
  );
});

test("parseModel: 2-segment unchanged, 3-segment maps to connected provider", () => {
  assert.deepEqual(parseModel("opencode/mimo-v2.6-flash-free"),
    { providerID: "opencode", modelID: "mimo-v2.6-flash-free" });
  assert.deepEqual(parseModel("opencode/google/gemini-2.5-flash"),
    { providerID: "google", modelID: "gemini-2.5-flash" });
  // mid keeps further slashes so ids like openrouter/qwen/qwen3-coder work
  assert.deepEqual(parseModel("opencode/openrouter/qwen/qwen3-coder"),
    { providerID: "openrouter", modelID: "qwen/qwen3-coder" });
  assert.throws(() => parseModel("openrouter/foo"),
    (e) => e.status === 404 && e.code === "model_not_found");
  assert.throws(() => parseModel("opencode/"), (e) => e.status === 404);
  assert.throws(() => parseModel("opencode//m"), (e) => e.status === 404);
  assert.throws(() => parseModel("opencode/google/"), (e) => e.status === 404);
  assert.throws(() => parseModel(undefined), (e) => e.status === 404);
});

test("parseModel: unknown provider in enabled list fails OpenAI-shaped 404", () => {
  assert.throws(() => parseModel("opencode/google/gemini-2.5-flash", ["opencode"]),
    (e) => e.status === 404 && e.code === "model_not_found"
      && /unknown provider 'google'/.test(e.message));
  assert.deepEqual(parseModel("opencode/google/gemini-2.5-flash", ["google", "opencode"]),
    { providerID: "google", modelID: "gemini-2.5-flash" });
  // without an enabled list no membership check (legacy call shape)
  assert.deepEqual(parseModel("opencode/google/gemini-2.5-flash"),
    { providerID: "google", modelID: "gemini-2.5-flash" });
});

test("authProviderIds: sorted keys from auth.json, [] on any failure", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "velora-auth-"));
  const p = path.join(dir, "auth.json");
  fs.writeFileSync(p, JSON.stringify({
    google: { type: "api", key: "x" },
    zen: "y",
    openrouter: { type: "oauth" },
    "": { type: "api", key: "nope" },
  }));
  assert.deepEqual(authProviderIds(p), ["google", "openrouter", "zen"]);
  fs.writeFileSync(p, "{not json");
  assert.deepEqual(authProviderIds(p), []);
  assert.deepEqual(authProviderIds(path.join(dir, "missing.json")), []);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("enabledProviders: derives from auth.json, falls back to [opencode]", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "velora-enab-"));
  const p = path.join(dir, "auth.json");
  fs.writeFileSync(p, JSON.stringify({ google: { type: "api", key: "x" }, opencode: {} }));
  assert.deepEqual(enabledProviders(p), ["opencode", "google"]);
  assert.deepEqual(enabledProviders(path.join(dir, "missing.json")), ["opencode"]);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("composeModels: free provider bare ids, connected prefixed, sorted", () => {
  const rows = composeModels([
    { id: "opencode", models: { "mimo-v2.6-flash-free": {}, "big-pickle": {} } },
    { id: "google", models: { "gemini-2.5-pro": {}, "gemini-2.5-flash": {} } },
    { id: "empty", models: {} },
  ]);
  assert.deepEqual(rows.map((r) => r.id), [
    "opencode/big-pickle",
    "opencode/google/gemini-2.5-flash",
    "opencode/google/gemini-2.5-pro",
    "opencode/mimo-v2.6-flash-free",
  ]);
  assert.ok(rows.every((r) => r.object === "model"));
  assert.equal(rows.find((r) => r.id.endsWith("gemini-2.5-flash")).owned_by, "google");
  assert.equal(rows.find((r) => r.id.endsWith("big-pickle")).owned_by, "opencode");
  assert.deepEqual(composeModels([]), []);
  assert.deepEqual(composeModels(undefined), []);
});

test("handleChat routes providerID/modelID through to opencode", async () => {
  const calls = [];
  const client = {
    session: {
      create: async () => ({ data: { id: "s1" } }),
      prompt: async ({ body }) => {
        calls.push(body);
        return { data: { info: {}, parts: [{ type: "text", text: "pong" }] } };
      },
      delete: async () => ({ data: {} }),
    },
  };
  const res = await handleChat(client, {
    model: "opencode/google/gemini-2.5-flash",
    messages: [{ role: "user", content: "hi" }],
  }, ["opencode", "google"]);
  assert.deepEqual(calls[0].model, { providerID: "google", modelID: "gemini-2.5-flash" });
  assert.equal(res.model, "opencode/google/gemini-2.5-flash");
  assert.equal(res.choices[0].message.content, "pong");
  await assert.rejects(
    () => handleChat(client, {
      model: "opencode/nope/m",
      messages: [{ role: "user", content: "x" }],
    }, ["opencode", "google"]),
    (e) => e.status === 404,
  );
  assert.equal(calls.length, 1); // rejected before any session was created
});

test("contentOf handles strings and content-part arrays", () => {
  assert.equal(contentOf({ content: "hi" }), "hi");
  assert.equal(contentOf({ content: [{ type: "text", text: "a" }, { type: "text", text: "b" }] }), "ab");
  assert.equal(contentOf({ content: [{ type: "image_url", image_url: {} }] }), "");
  assert.equal(contentOf({}), "");
});

test("flattenMessages skips system, labels roles, notes tool calls", () => {
  const transcript = flattenMessages([
    { role: "system", content: "sys" },
    { role: "user", content: "hello" },
    { role: "assistant", content: "thinking", tool_calls: [{ function: { name: "bash" } }] },
    { role: "tool", name: "bash", content: "ok" },
  ]);
  assert.ok(!transcript.includes("sys"));
  assert.ok(transcript.includes("USER:\nhello"));
  assert.ok(transcript.includes("ASSISTANT:\nthinking\n[requested tool calls: bash]"));
  assert.ok(transcript.includes("TOOL RESULT (bash):\nok"));
});

test("buildSystem joins non-empty system messages", () => {
  assert.equal(buildSystem([
    { role: "system", content: "one" },
    { role: "user", content: "nope" },
    { role: "system", content: "  " },
    { role: "system", content: "two" },
  ]), "one\n\ntwo");
  assert.equal(buildSystem([]), "");
  assert.equal(buildSystem(undefined), "");
});

test("estimateTokens is at least 1 and roughly length/4", () => {
  assert.equal(estimateTokens(""), 1);
  assert.equal(estimateTokens("a".repeat(40)), 10);
});

test("openaiResponse has OpenAI chat.completion shape", () => {
  const body = openaiResponse("opencode/mimo-v2.6-flash-free", "PONG", "prompt");
  assert.equal(body.object, "chat.completion");
  assert.equal(body.model, "opencode/mimo-v2.6-flash-free");
  assert.equal(body.choices.length, 1);
  assert.equal(body.choices[0].message.role, "assistant");
  assert.equal(body.choices[0].message.content, "PONG");
  assert.equal(body.choices[0].finish_reason, "stop");
  assert.ok(body.usage.total_tokens === body.usage.prompt_tokens + body.usage.completion_tokens);
  assert.ok(body.id.startsWith("chatcmpl-"));
});

test("openaiError wraps message/type/code", () => {
  const e = openaiError(404, "nope", "invalid_request_error", "model_not_found");
  assert.equal(e.status, 404);
  assert.deepEqual(e.body.error, { message: "nope", type: "invalid_request_error", code: "model_not_found" });
});
