import assert from "node:assert/strict";
import test from "node:test";
import { execFileGitAdapters } from "../differential/adapters/exec-file-git.mjs";

const target = { apiKey: "fixture-key", baseUrl: "http://127.0.0.1:9", prefix: "DIFF", git: { repo: "https://github.com/fixture/repository.git", branch: "phase4-head", baseBranch: "main", token: "fixture-token" } };
const config = { runtime: "node" };

function fakeBox(calls) {
  const box = {
    id: "box_fixture",
    async delete() { calls.push(["delete"]); },
    async cd(path) { calls.push(["cd", path]); },
    exec: {
      async command(value) { calls.push(["exec.command", value]); return { result: value }; },
      async code(value) { calls.push(["exec.code", value]); return { result: value }; },
      async stream(value) { calls.push(["exec.stream", value]); return (async function* () { yield { type: "output", data: value }; })(); },
      async streamCode(value) { calls.push(["exec.streamCode", value]); return (async function* () { yield { type: "output", data: value.code }; })(); },
    },
    files: {
      async read(path, options) { calls.push(["files.read", path, options]); return "fixture"; },
      async write(options) { calls.push(["files.write", options]); },
      async list(path) { calls.push(["files.list", path]); return [{ name: "fixture.txt", path, is_dir: false }]; },
      async upload(files) { calls.push(["files.upload", files]); },
      async download(options) { calls.push(["files.download", options]); },
    },
    git: {
      async clone(options) { calls.push(["git.clone", options]); },
      async diff() { calls.push(["git.diff"]); return ""; },
      async status() { calls.push(["git.status"]); return ""; },
      async commit(options) { calls.push(["git.commit", options]); return { committed: true }; },
      async updateConfig(options) { calls.push(["git.updateConfig", options]); return options; },
      async push(options) { calls.push(["git.push", options]); },
      async createPR(options) { calls.push(["git.createPR", options]); return { number: 1 }; },
      async exec(options) { calls.push(["git.exec", options]); return { output: "" }; },
      async checkout(options) { calls.push(["git.checkout", options]); },
    },
  };
  return box;
}

test("exec/file/git registry covers every assigned public case", () => {
  assert.equal(execFileGitAdapters.size, 19);
  for (const id of [
    "POST /v2/box/{box_id}/exec", "POST /v2/box/{box_id}/exec-stream", "POST /v2/box/{box_id}/code",
    "POST /v2/box/{box_id}/code-stream", "POST /v2/box/{box_id}/exec#cd", "GET /v2/box/{box_id}/files/read",
    "POST /v2/box/{box_id}/files/write", "GET /v2/box/{box_id}/files/list", "POST /v2/box/{box_id}/files/upload",
    "GET /v2/box/{box_id}/files/download", "POST /v2/box/{box_id}/git/clone", "GET /v2/box/{box_id}/git/diff",
    "GET /v2/box/{box_id}/git/status", "POST /v2/box/{box_id}/git/commit", "PUT /v2/box/{box_id}/git-config",
    "POST /v2/box/{box_id}/git/push", "POST /v2/box/{box_id}/git/create-pr", "POST /v2/box/{box_id}/git/exec",
    "POST /v2/box/{box_id}/git/checkout",
  ]) assert.ok(execFileGitAdapters.has(id), id);
});

test("each adapter uses a real Box lifecycle and sends pinned-client-shaped arguments", async () => {
  const originalFetch = globalThis.fetch;
  const fetchCalls = [];
  globalThis.fetch = async (url, init) => { fetchCalls.push([url, init]); return new Response("{}", { status: 200, headers: { "content-type": "application/json" } }); };
  try {
    for (const [id, adapter] of execFileGitAdapters) {
      const calls = [];
      const box = fakeBox(calls);
      const sdk = { Box: { async create(options) { calls.push(["create", options]); return box; } } };
      const state = await adapter.prepare({ target, config });
      await adapter.execute({ sdk, target, state, config });
      await adapter.cleanup({ sdk, target, state, config });
      assert.equal(calls.filter(([name]) => name === "create").length, 1, id);
      assert.equal(calls.filter(([name]) => name === "delete").length, 1, id);
      assert.ok(calls.length >= 2, id);
      if (id.includes("/git/" ) || id.endsWith("/git-config")) {
        assert.equal(calls.find(([name]) => name === "create")[1].git.token, target.git.token, id);
        assert.equal("gitToken" in calls.find(([name]) => name === "create")[1], false, id);
      }
      if (id === "POST /v2/box/{box_id}/exec#cd") assert.match(calls.find(([name]) => name === "exec.command")[1], /mkdir -p phase4-cd/);
      if (id === "GET /v2/box/{box_id}/git/status") assert.match(calls.find(([name]) => name === "exec.command")[1], /git -C phase4-git init/);
      if (id === "POST /v2/box/{box_id}/git/clone") assert.deepEqual(calls.find(([name]) => name === "git.clone")[1], { repo: target.git.repo, branch: target.git.branch, depth: 1 });
    }
    assert.equal(fetchCalls.length, 1);
    assert.equal(fetchCalls[0][0], "https://api.github.com/repos/fixture/repository/pulls/1");
    assert.equal(fetchCalls[0][1].method, "PATCH");
  } finally { globalThis.fetch = originalFetch; }
});

test("git mutating adapters fail closed without a configured repository", async () => {
  for (const id of [
    "POST /v2/box/{box_id}/git/clone", "POST /v2/box/{box_id}/git/push", "POST /v2/box/{box_id}/git/create-pr",
  ]) {
    const adapter = execFileGitAdapters.get(id);
    const calls = [];
    const sdk = { Box: { async create(options) { calls.push(options); return fakeBox(calls); } } };
    const missingTarget = { apiKey: target.apiKey, baseUrl: target.baseUrl, prefix: target.prefix, git: {} };
    const state = await adapter.prepare({ target: missingTarget, config: { runtime: "node" } });
    await assert.rejects(adapter.execute({ sdk, target: missingTarget, state, config: { runtime: "node" } }), /Git repository/);
    await adapter.cleanup({ state });
    assert.equal(calls.length, 2);
  }
});
