import test from "node:test";
import assert from "node:assert/strict";
import {
  parseArgs,
  parseModel,
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

test("parseModel accepts opencode/<id> only", () => {
  assert.equal(parseModel("opencode/mimo-v2.6-flash-free"), "mimo-v2.6-flash-free");
  assert.throws(() => parseModel("openrouter/foo"), (e) => e.status === 404 && e.code === "model_not_found");
  assert.throws(() => parseModel("opencode/"), (e) => e.status === 404);
  assert.throws(() => parseModel("opencode/a/b"), (e) => e.status === 404);
  assert.throws(() => parseModel(undefined), (e) => e.status === 404);
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
