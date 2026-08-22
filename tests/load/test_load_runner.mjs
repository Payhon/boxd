import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import { aggregateProcessRows, fetchPreview, ResourceSampler, resourceCeiling, validateLoadProfile } from "../../scripts/phase4-load-runner.mjs";

test("resourceCeiling records the maximum value from every sample", () => {
  assert.deepEqual(resourceCeiling([
    { cpu_percent: 1, rss_bytes: 20, fd_count: 3, disk_bytes: 40 },
    { cpu_percent: 7, rss_bytes: 10, fd_count: 9, disk_bytes: 30 },
  ]), { cpu_percent: 7, rss_bytes: 20, fd_count: 9, disk_bytes: 40 });
  assert.throws(() => resourceCeiling([]), /no samples/);
});

test("process-tree metrics include transitive VMM workers but exclude unrelated processes", () => {
  const aggregate = aggregateProcessRows([
    "100 1 1.5 1000",
    "101 100 2.5 2000",
    "102 101 3.0 3000",
    "200 1 99.0 9999",
  ], "100");
  assert.deepEqual(aggregate.pids, [100, 101, 102]);
  assert.equal(aggregate.cpu_percent, 7);
  assert.equal(aggregate.rss_bytes, 6000 * 1024);
});

test("ResourceSampler continuously records an immediate sample and interval samples", async () => {
  let calls = 0;
  const sampler = new ResourceSampler("123", "/tmp", 50, async () => ({
    cpu_percent: ++calls,
    rss_bytes: calls * 10,
    fd_count: calls,
    disk_bytes: calls * 100,
  }));
  await sampler.start();
  await new Promise((resolve) => setTimeout(resolve, 125));
  const result = await sampler.stop();
  assert.ok(result.sample_count >= 2);
  assert.equal(result.ceiling.cpu_percent, result.sample_count);
  assert.equal(result.ceiling.disk_bytes, result.sample_count * 100);
});

test("load profile rejects a low-resource configuration for the complete matrix", () => {
  const configured = { max_running_boxes: 64, max_total_memory_mib: 262144, max_total_vcpus: 128, default_disk_gib: 20, tenant_max_boxes: 64, tenant_max_disk_gib: 1280, tenant_max_concurrent_runs: 64 };
  const profile = validateLoadProfile("phase4-64", configured);
  assert.equal(profile.runtime_asserted, true);
  assert.deepEqual(profile.requirements, configured);
  assert.throws(() => validateLoadProfile("phase4-16", configured, 64), /cannot prove/);
  assert.throws(() => validateLoadProfile("phase4-64", { ...configured, max_running_boxes: 4 }), /max_running_boxes/);
  assert.throws(() => validateLoadProfile("phase4-64", configured, 64, "python"), /RUNTIME=node/);
});

test("fetchPreview consumes a successful loopback response body", async (t) => {
  const server = createServer((_request, response) => response.end("phase4-preview"));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const address = server.address();
  assert.equal(typeof address, "object");
  assert.equal(await fetchPreview({ url: `http://127.0.0.1:${address.port}/` }), 14);
  await assert.rejects(() => fetchPreview({ url: "https://example.com/" }), /loopback/);
});
