#!/usr/bin/env node

import { createServer } from "node:http";
import { open, rename, unlink, writeFile } from "node:fs/promises";

const [portFile, evidenceFile] = process.argv.slice(2);
if (!portFile || !evidenceFile) {
  throw new Error("usage: phase3-model-otlp-fixture.mjs PORT_FILE EVIDENCE_JSON");
}
const expectedKey = process.env.BOXD_MODEL_FIXTURE_KEY;
if (!expectedKey) throw new Error("BOXD_MODEL_FIXTURE_KEY is required");

const state = {
  schema: "boxd-phase3-model-otlp-fixture-v1",
  model_requests: { extract: 0, observe: 0, act: 0, run: 0 },
  model_authorization_verified: true,
  otlp_requests: 0,
  otlp_protobuf_bytes: 0,
};

async function persistEvidence() {
  const temporary = `${evidenceFile}.tmp`;
  await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, evidenceFile);
}

function json(res, status, body) {
  const bytes = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(bytes.length),
    connection: "close",
  });
  res.end(bytes);
}

async function readBody(req, maximumBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maximumBytes) throw new Error("request body exceeds fixture limit");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function classify(system) {
  if (system.startsWith("Extract data")) return ["extract", { title: "Example Domain" }];
  if (system.startsWith("Select actionable")) return ["observe", { elements: [] }];
  if (system.startsWith("Plan the minimum")) {
    return ["act", {
      message: "waited",
      action_description: "wait safely",
      actions: [{
        method: "wait",
        selector: "",
        arguments: ["25"],
        description: "bounded wait",
      }],
    }];
  }
  if (system.startsWith("Complete the user task")) {
    return ["run", {
      completed: true,
      result: "fixture task complete",
      data: { ok: true },
      reasoning: "the fixture page is already in the requested state",
      action: null,
    }];
  }
  return null;
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/evidence") {
      json(res, 200, state);
      return;
    }
    if (req.method === "POST" && req.url === "/v1/traces") {
      const contentType = String(req.headers["content-type"] ?? "").toLowerCase();
      if (!contentType.startsWith("application/x-protobuf")) {
        json(res, 415, { error: "expected OTLP protobuf" });
        return;
      }
      const body = await readBody(req, 16 * 1024 * 1024);
      if (body.length === 0) throw new Error("empty OTLP payload");
      state.otlp_requests += 1;
      state.otlp_protobuf_bytes += body.length;
      await persistEvidence();
      res.writeHead(200, { "content-length": "0", connection: "close" });
      res.end();
      return;
    }
    if (req.method !== "POST" || req.url !== "/v1/chat/completions") {
      json(res, 404, { error: "not found" });
      return;
    }
    if (req.headers.authorization !== `Bearer ${expectedKey}`) {
      state.model_authorization_verified = false;
      await persistEvidence();
      json(res, 401, { error: "invalid fixture credential" });
      return;
    }
    const body = JSON.parse((await readBody(req, 1024 * 1024)).toString("utf8"));
    const system = body?.messages?.find((message) => message?.role === "system")?.content;
    const classified = typeof system === "string" ? classify(system) : null;
    if (!classified) {
      json(res, 422, { error: "unknown browser model request" });
      return;
    }
    const [kind, output] = classified;
    state.model_requests[kind] += 1;
    await persistEvidence();
    json(res, 200, {
      choices: [{ message: { content: JSON.stringify(output) } }],
      usage: { prompt_tokens: 7, completion_tokens: 3 },
    });
  } catch (error) {
    json(res, 500, { error: error instanceof Error ? error.message : "fixture failure" });
  }
});

server.listen(0, "127.0.0.1", async () => {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture address unavailable");
  const handle = await open(portFile, "wx", 0o600);
  await handle.writeFile(`${address.port}\n`, "utf8");
  await handle.sync();
  await handle.close();
  await persistEvidence();
});

async function shutdown() {
  await new Promise((resolve) => server.close(resolve));
  await persistEvidence();
}

process.once("SIGINT", () => void shutdown().then(() => process.exit(0)));
process.once("SIGTERM", () => void shutdown().then(() => process.exit(0)));
process.once("uncaughtException", async (error) => {
  await unlink(portFile).catch(() => {});
  process.stderr.write(`${error instanceof Error ? error.stack : error}\n`);
  process.exit(1);
});
