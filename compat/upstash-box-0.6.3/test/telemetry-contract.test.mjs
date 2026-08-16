import assert from "node:assert/strict";
import test from "node:test";
import { Box } from "@upstash/box";

function restoreEnv(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

test("public SDK sends the pinned telemetry headers only when enableTelemetry is true", async () => {
  const priorFetch = globalThis.fetch;
  const priorDisable = process.env.UPSTASH_DISABLE_TELEMETRY;
  const priorCi = process.env.CI;
  const calls = [];
  delete process.env.UPSTASH_DISABLE_TELEMETRY;
  process.env.CI = "fixture-ci";
  globalThis.fetch = async (_url, init = {}) => {
    calls.push(new Headers(init.headers));
    return Response.json({ id: "box_fixture", status: "running", labels: [], enabled_skills: [] });
  };

  try {
    await Box.create({
      name: "fixture-enabled",
      apiKey: "fixture-api-key",
      baseUrl: "http://contract.invalid",
      enableTelemetry: true,
    });
    await Box.create({
      name: "fixture-disabled",
      apiKey: "fixture-api-key",
      baseUrl: "http://contract.invalid",
      enableTelemetry: false,
    });

    assert.equal(calls.length, 2);
    for (const headers of calls) assert.equal(headers.get("X-Box-Api-Key"), "fixture-api-key");
    assert.equal(calls[0].get("Upstash-Telemetry-Sdk"), "@upstash/box@0.6.3");
    assert.equal(calls[0].get("Upstash-Telemetry-Runtime"), `node@${process.version}`);
    assert.equal(calls[0].get("Upstash-Telemetry-Platform"), "ci");
    assert.equal(calls[1].get("Upstash-Telemetry-Sdk"), null);
    assert.equal(calls[1].get("Upstash-Telemetry-Runtime"), null);
    assert.equal(calls[1].get("Upstash-Telemetry-Platform"), null);
  } finally {
    globalThis.fetch = priorFetch;
    restoreEnv("UPSTASH_DISABLE_TELEMETRY", priorDisable);
    restoreEnv("CI", priorCi);
  }
});
