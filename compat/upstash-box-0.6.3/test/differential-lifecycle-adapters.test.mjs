import assert from "node:assert/strict";
import test from "node:test";
import { lifecycleAdapters } from "../differential/adapters/lifecycle.mjs";

const target = { apiKey: "fixture-key", baseUrl: "http://127.0.0.1:9", prefix: "DIFF" };
const config = { runtime: "node", providerApiKey: "provider-key" };

function fakeBox(calls, id = "box_fixture") {
  const box = {
    id,
    async delete() { calls.push(["box.delete", id]); },
    async snapshot(options) { calls.push(["box.snapshot", options]); return { id: "snapshot_fixture", status: "ready" }; },
    async deleteSnapshot(snapshotId) { calls.push(["box.deleteSnapshot", snapshotId]); },
    async listSnapshots() { calls.push(["box.listSnapshots"]); return []; },
    async getStatus() { calls.push(["box.getStatus"]); return { status: "ready" }; },
    async pause() { calls.push(["box.pause"]); }, async resume() { calls.push(["box.resume"]); },
    async getInitCommand() { calls.push(["box.getInitCommand"]); return ""; },
    async setInitCommand(value) { calls.push(["box.setInitCommand", value]); }, async deleteInitCommand() { calls.push(["box.deleteInitCommand"]); },
    async configureModel(value) { calls.push(["box.configureModel", value]); },
    async configureCustomHarness(value) { calls.push(["box.configureCustomHarness", value]); },
    async updateNetworkPolicy(value) { calls.push(["box.updateNetworkPolicy", value]); },
    getPublicURL: async (port) => { calls.push(["box.getPublicURL", port]); return { port }; },
    async listPublicURLs() { calls.push(["box.listPublicURLs"]); return { publicURLs: [] }; },
    async deletePublicURL(port) { calls.push(["box.deletePublicURL", port]); },
    skills: { async add(value) { calls.push(["skills.add", value]); }, async remove(value) { calls.push(["skills.remove", value]); }, async list() { calls.push(["skills.list"]); return []; } },
    labels: { async add(value) { calls.push(["labels.add", value]); return []; }, async remove(value) { calls.push(["labels.remove", value]); return []; }, async list() { calls.push(["labels.list"]); return []; } },
    schedule: {
      async exec(value) { calls.push(["schedule.exec", value]); return { id: "schedule_fixture" }; }, async agent(value) { calls.push(["schedule.agent", value]); return { id: "schedule_fixture" }; },
      async list() { calls.push(["schedule.list"]); return []; }, async get(value) { calls.push(["schedule.get", value]); return {}; }, async update(id, value) { calls.push(["schedule.update", id, value]); return {}; },
      async pause(value) { calls.push(["schedule.pause", value]); }, async resume(value) { calls.push(["schedule.resume", value]); }, async delete(value) { calls.push(["schedule.delete", value]); },
    },
  };
  return box;
}

const ids = [
  "DELETE /v2/box", "DELETE /v2/box/{box_id}", "DELETE /v2/box/snapshots", "GET /v2/box/{box_id}", "GET /v2/box/{box_id}/status", "POST /v2/box/{box_id}/pause", "POST /v2/box/{box_id}/resume",
  "GET /v2/box/{box_id}/startup", "PUT /v2/box/{box_id}/startup", "DELETE /v2/box/{box_id}/startup", "PUT /v2/box/{box_id}/config/model",
  "PUT /v2/box/{box_id}/config/custom-runner", "PUT /v2/box/{box_id}/config/network-policy", "PUT /v2/box/settings/env", "DELETE /v2/box/settings/env/{key}",
  "POST /v2/box/from-snapshot", "POST /v2/box/from-snapshot#ephemeral", "POST /v2/box#ephemeral", "POST /v2/box/{box_id}/snapshots",
  "GET /v2/box/{box_id}/snapshots", "DELETE /v2/box/{box_id}/snapshots/{snapshot_id}", "POST /v2/box/{box_id}/config/skills", "DELETE /v2/box/{box_id}/config/skills/{skill_id+}",
  "GET /v2/box/{box_id}#skills", "POST /v2/box/{box_id}/config/labels", "DELETE /v2/box/{box_id}/config/labels/{label}", "GET /v2/box/{box_id}#labels",
  "POST /v2/box/{box_id}/schedules#exec", "POST /v2/box/{box_id}/schedules#agent", "GET /v2/box/{box_id}/schedules", "GET /v2/box/{box_id}/schedules/{id}",
  "PATCH /v2/box/{box_id}/schedules/{id}", "POST /v2/box/{box_id}/schedules/{id}/pause", "POST /v2/box/{box_id}/schedules/{id}/resume", "DELETE /v2/box/{box_id}/schedules/{id}",
  "POST /v2/box/{box_id}/preview", "GET /v2/box/{box_id}/preview", "DELETE /v2/box/{box_id}/preview/{port}",
];

test("lifecycle registry covers the assigned pinned SDK cases", () => {
  assert.equal(lifecycleAdapters.size, ids.length);
  for (const id of ids) assert.ok(lifecycleAdapters.has(id), id);
});

test("every lifecycle adapter creates real resources and cleans them", async () => {
  for (const [id, adapter] of lifecycleAdapters) {
    const calls = [];
    const make = () => fakeBox(calls);
    const sdk = {
      Box: {
        async create(options) { calls.push(["Box.create", options]); return make(); },
        async get(value) { calls.push(["Box.get", value]); return make(); },
        async fromSnapshot(value) { calls.push(["Box.fromSnapshot", value]); return make(calls, "restored_fixture"); },
        async delete(options) { calls.push(["Box.delete", options]); }, async deleteSnapshots(options) { calls.push(["Box.deleteSnapshots", options]); return { deleted: 1 }; },
        async setEnv(key, value) { calls.push(["Box.setEnv", key, value]); }, async deleteEnv(key) { calls.push(["Box.deleteEnv", key]); },
        async setAllEnv(value) { calls.push(["Box.setAllEnv", value]); }, async listEnv() { calls.push(["Box.listEnv"]); return {}; },
      },
      EphemeralBox: { async create(options) { calls.push(["EphemeralBox.create", options]); return make(); }, async fromSnapshot(value) { calls.push(["EphemeralBox.fromSnapshot", value]); return make(calls, "ephemeral_fixture"); } },
    };
    const state = await adapter.prepare({ target, config });
    await adapter.execute({ sdk, target, state, config });
    await adapter.cleanup({ sdk, target, state, config });
    assert.ok(calls.length >= 2, id);
    if (id !== "GET /v2/box/settings/env") assert.ok(calls.some(([name]) => name.endsWith("delete") || name === "box.delete" || name === "Box.deleteEnv"), id);
    if (id === "POST /v2/box/{box_id}/resume") assert.deepEqual(calls.map(([name]) => name).filter((name) => ["box.pause", "box.resume"].includes(name)), ["box.pause", "box.resume"]);
    if (id === "DELETE /v2/box/{box_id}/startup") assert.deepEqual(calls.map(([name]) => name).filter((name) => ["box.setInitCommand", "box.deleteInitCommand"].includes(name)), ["box.setInitCommand", "box.deleteInitCommand"]);
    if (id.endsWith("config/network-policy")) assert.deepEqual(calls.find(([name]) => name === "box.updateNetworkPolicy")[1], {});
    if (id === "POST /v2/box/{box_id}/snapshots") assert.ok(calls.some(([name, value]) => name === "box.deleteSnapshot" && value === "snapshot_fixture"));
    if (id === "DELETE /v2/box/{box_id}/snapshots/{snapshot_id}") assert.equal(calls.filter(([name]) => name === "box.deleteSnapshot").length, 1);
    if (id === "POST /v2/box/{box_id}/config/skills") assert.ok(calls.some(([name]) => name === "skills.remove"));
    if (id === "POST /v2/box/{box_id}/config/labels") assert.ok(calls.some(([name]) => name === "labels.remove"));
    if (id.includes("schedules") && !id.endsWith("/schedules")) assert.ok(calls.some(([name]) => name === "schedule.delete"), id);
    if (id === "POST /v2/box/{box_id}/preview") assert.ok(calls.some(([name]) => name === "box.deletePublicURL"));
  }
});

test("delete and env adapters preserve their cleanup call sequence", async () => {
  const calls = [];
  const adapter = lifecycleAdapters.get("DELETE /v2/box/settings/env/{key}");
  const sdk = { Box: { async setEnv(...args) { calls.push(["set", ...args]); }, async deleteEnv(...args) { calls.push(["delete", ...args]); } } };
  const state = await adapter.prepare({ target, config });
  await adapter.execute({ sdk, target, state, config });
  await adapter.cleanup({ sdk, target, state, config });
  assert.deepEqual(calls.map(([name]) => name), ["set", "delete"]);
});

test("setAllEnv explicitly declares the dedicated-account requirement", () => {
  assert.equal(lifecycleAdapters.get("PUT /v2/box/settings/env").dedicatedAccount, true);
});

test("agent schedule creates an agent-enabled Box", async () => {
  const calls = [];
  const box = fakeBox(calls);
  const sdk = { Box: { async create(options) { calls.push(["Box.create", options]); return box; } } };
  const adapter = lifecycleAdapters.get("POST /v2/box/{box_id}/schedules#agent");
  const state = await adapter.prepare({ target, config });
  await adapter.execute({ sdk, target, state, config });
  await adapter.cleanup({ sdk, target, state, config });
  assert.equal(calls[0][1].agent.apiKey, config.providerApiKey);
});
