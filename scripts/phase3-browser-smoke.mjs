#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdtemp, open, readFile, rm, stat, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "../compat/upstash-box-0.6.3/node_modules/zod/index.js";

const [sdkEntry, evidencePath] = process.argv.slice(2);
if (!sdkEntry || !evidencePath) {
  throw new Error("usage: phase3-browser-smoke.mjs SDK_ENTRY EVIDENCE_JSON");
}
for (const variable of [
  "UPSTASH_BOX_API_KEY",
  "UPSTASH_BOX_BASE_URL",
  "BOXD_ADMIN_PASSWORD",
  "BOXD_MODEL_FIXTURE_KEY",
  "BOXD_MODEL_FIXTURE_URL",
]) {
  if (!process.env[variable]) throw new Error(`${variable} is required`);
}

const resolvedSdkEntry = sdkEntry.startsWith("file:") ? sdkEntry : pathToFileURL(sdkEntry).href;
const { Box } = await import(resolvedSdkEntry);
const sourceCommit = "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934";
const baseUrl = process.env.UPSTASH_BOX_BASE_URL.replace(/\/$/, "");
const apiKey = process.env.UPSTASH_BOX_API_KEY;
const networkMode = process.env.BOXD_BROWSER_SMOKE_NETWORK_MODE ?? "allow-all";
const quotaBurst = Number(process.env.BOXD_BROWSER_SMOKE_QUOTA_BURST ?? "8");
const retainForRestart = process.env.BOXD_BROWSER_SMOKE_RETAIN === "true";
if (!new Set(["allow-all", "deny-all", "restricted-default"]).has(networkMode)) {
  throw new Error("BOXD_BROWSER_SMOKE_NETWORK_MODE must be allow-all, deny-all, or restricted-default");
}
if (!Number.isSafeInteger(quotaBurst) || quotaBurst < 2 || quotaBurst > 1000) {
  throw new Error("BOXD_BROWSER_SMOKE_QUOTA_BURST must be an integer from 2 to 1000");
}

let box;
let schedule;
let quotaKeyId;
let committed = false;
const evidenceFile = await open(evidencePath, "wx", 0o600);
const downloads = await mkdtemp(join(tmpdir(), "boxd-phase3-recording-"));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function closeWebSocket(socket) {
  if (socket.readyState === WebSocket.CLOSED) return;
  await new Promise((resolve) => {
    const timeout = setTimeout(resolve, 5_000);
    socket.addEventListener("close", () => {
      clearTimeout(timeout);
      resolve();
    }, { once: true });
    socket.close();
  });
}

async function browserVersion(cdpUrl) {
  const socket = new WebSocket(cdpUrl);
  const timeout = AbortSignal.timeout(15_000);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true, signal: timeout });
    socket.addEventListener("error", () => reject(new Error("browser CDP websocket failed")), {
      once: true,
      signal: timeout,
    });
    timeout.addEventListener("abort", () => reject(new Error("browser CDP websocket timed out")), {
      once: true,
    });
  });
  try {
    const response = new Promise((resolve, reject) => {
      socket.addEventListener("message", (event) => {
        try {
          resolve(JSON.parse(String(event.data)));
        } catch (error) {
          reject(error);
        }
      }, { once: true, signal: timeout });
      socket.addEventListener("error", () => reject(new Error("browser CDP response failed")), {
        once: true,
        signal: timeout,
      });
    });
    socket.send(JSON.stringify({ id: 7, method: "Browser.getVersion" }));
    const message = await response;
    if (message.id !== 7 || typeof message.result?.product !== "string") {
      throw new Error("browser CDP Browser.getVersion contract mismatch");
    }
    return message.result.product;
  } finally {
    await closeWebSocket(socket);
  }
}

async function seedFixturePage(cdpUrl) {
  const socket = new WebSocket(cdpUrl);
  const timeout = AbortSignal.timeout(15_000);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true, signal: timeout });
    socket.addEventListener("error", () => reject(new Error("browser CDP websocket failed")), {
      once: true,
      signal: timeout,
    });
    timeout.addEventListener("abort", () => reject(new Error("browser CDP websocket timed out")), {
      once: true,
    });
  });
  let id = 100;
  const command = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const commandId = id++;
    const onMessage = (event) => {
      try {
        const message = JSON.parse(String(event.data));
        if (message.id !== commandId) return;
        socket.removeEventListener("message", onMessage);
        if (message.error) reject(new Error(`CDP ${method} failed: ${message.error.message}`));
        else resolve(message.result ?? {});
      } catch (error) {
        socket.removeEventListener("message", onMessage);
        reject(error);
      }
    };
    socket.addEventListener("message", onMessage, { signal: timeout });
    socket.send(JSON.stringify({ id: commandId, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  try {
    const { targetInfos = [] } = await command("Target.getTargets");
    const pages = targetInfos.filter((target) => target.type === "page" && target.url === "about:blank");
    if (pages.length === 0) throw new Error("CDP fixture found no about:blank page");
    const html = "<!doctype html><html><head><title>Example Domain</title></head><body><main><h1>Example Domain</h1><p>Deterministic Phase 3 browser fixture.</p></main></body></html>";
    for (const page of pages) {
      const { sessionId } = await command("Target.attachToTarget", { targetId: page.targetId, flatten: true });
      await command("Runtime.evaluate", {
        expression: `document.open();document.write(${JSON.stringify(html)});document.close();`,
        awaitPromise: true,
      }, sessionId);
    }
  } finally {
    await closeWebSocket(socket);
  }
}

async function screencastFrame(viewUrl) {
  const page = await fetch(viewUrl);
  if (!page.ok || !(await page.text()).includes("Live browser view")) {
    throw new Error("browser screencast view page contract mismatch");
  }
  const websocketUrl = new URL(viewUrl);
  websocketUrl.protocol = websocketUrl.protocol === "https:" ? "wss:" : "ws:";
  websocketUrl.pathname = websocketUrl.pathname.replace(/\/view$/, "/ws");
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(websocketUrl);
    socket.binaryType = "arraybuffer";
    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error("browser screencast frame timed out"));
    }, 20_000);
    socket.addEventListener("message", async (event) => {
      clearTimeout(timeout);
      const frame = new Uint8Array(event.data);
      await closeWebSocket(socket);
      if (frame.length < 4 || frame[0] !== 0xff || frame[1] !== 0xd8 || frame.at(-2) !== 0xff || frame.at(-1) !== 0xd9) {
        reject(new Error("browser screencast frame is not JPEG"));
        return;
      }
      resolve(frame.length);
    }, { once: true });
    socket.addEventListener("error", () => {
      clearTimeout(timeout);
      reject(new Error("browser screencast websocket failed"));
    }, { once: true });
  });
}

async function adminSession() {
  const response = await fetch(`${baseUrl}/api/admin/v1/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "admin", password: process.env.BOXD_ADMIN_PASSWORD }),
  });
  if (!response.ok) throw new Error(`admin login failed: ${response.status}`);
  const body = await response.json();
  const cookie = response.headers.get("set-cookie")?.split(";", 1)[0];
  if (!cookie || typeof body.csrf_token !== "string") throw new Error("admin session contract mismatch");
  return { cookie, csrf: body.csrf_token };
}

async function adminFetch(session, path, init = {}) {
  const response = await fetch(`${baseUrl}/api/admin/v1${path}`, {
    ...init,
    headers: {
      cookie: session.cookie,
      "x-csrf-token": session.csrf,
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...init.headers,
    },
  });
  if (!response.ok) throw new Error(`admin request ${path} failed: ${response.status}`);
  return response;
}

async function waitForSchedule() {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    try {
      const value = await box.files.read("phase3-schedule.txt");
      if (value === "phase3-schedule-ran") return;
    } catch (error) {
      // A due schedule briefly owns the per-box lifecycle lease while its
      // guest exec is running. Treat that bounded 503 exactly like the file's
      // pre-run 404 and keep polling until the committed side effect appears.
      if (![404, 409, 503].includes(error?.statusCode)) throw error;
    }
    await sleep(1000);
  }
  throw new Error("scheduled exec did not produce its guest side effect within 90 seconds");
}

try {
  const started = Date.now();
  box = await Box.create({
    runtime: "node",
    browser: true,
    keepAlive: true,
    name: "phase3-browser-complete",
    env: { FIXTURE_MODEL_KEY: process.env.BOXD_MODEL_FIXTURE_KEY },
    ...(networkMode === "restricted-default" ? {} : { networkPolicy: { mode: networkMode } }),
    timeout: 300_000,
  });
  const createElapsedMs = Date.now() - started;
  schedule = await box.schedule.exec({
    cron: "* * * * *",
    command: ["/bin/sh", "-c", "printf phase3-schedule-ran > /workspace/home/phase3-schedule.txt"],
  });
  if (schedule.type !== "exec" || schedule.status !== "active" || schedule.total_runs !== 0) {
    throw new Error("schedule create contract mismatch");
  }

  const created = await box.browser.tab.create("about:blank", { waitUntil: "load", timeout: 30_000 });
  await seedFixturePage(await box.browser.cdpUrl());
  if (!/^tab_[A-Za-z0-9_-]+$/.test(created.id) || created.id.length < 24) {
    throw new Error("browser tab id is not an opaque server id");
  }
  if (!(await box.browser.listTabs()).some((tab) => tab.id === created.id)) {
    throw new Error("created browser tab was not listed");
  }
  const content = await created.content();
  if (content.url !== "about:blank" || content.title !== "Example Domain") {
    throw new Error("browser content contract mismatch");
  }
  await created.goto("about:blank");
  await seedFixturePage(await box.browser.cdpUrl());
  const navigated = await created.content();
  if (navigated.url !== "about:blank" || !navigated.text.includes("Example Domain")) {
    throw new Error("browser goto contract mismatch");
  }
  const screenshot = await created.screenshot({ type: "png", fullPage: true });
  if (screenshot.length < 8 || screenshot[0] !== 0x89 || screenshot[1] !== 0x50 || screenshot[2] !== 0x4e || screenshot[3] !== 0x47) {
    throw new Error("browser screenshot is not PNG");
  }

  const extracted = await created.extract("Return the page title", z.object({ title: z.string() }), { model: "fixture/browser-v1" });
  if (extracted.title !== "Example Domain") throw new Error("browser extract mismatch");
  const observed = await created.observe("Find relevant controls", { model: "fixture/browser-v1" });
  if (!Array.isArray(observed.elements) || observed.elements.length !== 0) throw new Error("browser observe mismatch");
  const acted = await created.act("Wait briefly", { model: "fixture/browser-v1" });
  if (!acted.success || acted.actions[0]?.method !== "wait" || acted.message !== "waited") {
    throw new Error("browser act mismatch");
  }
  const second = await box.browser.tab.create("about:blank", { waitUntil: "load", timeout: 30_000 });
  await seedFixturePage(await box.browser.cdpUrl());
  await sleep(1200);
  const cdpProduct = await browserVersion(await box.browser.cdpUrl());
  const screencastFrameBytes = await screencastFrame(await second.liveViewUrl());
  let privateUrlBlocked = false;
  try {
    await second.goto("http://169.254.169.254/latest/meta-data/");
  } catch (error) {
    privateUrlBlocked = error?.statusCode === 403;
    if (!privateUrlBlocked) throw error;
  }
  if (!privateUrlBlocked) throw new Error("metadata browser navigation was accepted");

  // Chromium only permits one Page.startScreencast consumer per target. Keep the
  // live-view assertion and navigation outside the recording interval, then use
  // the model run as the recorded interaction on the stable foreground tab.
  const recordingHandle = await box.browser.recordings.start({ maxDurationSeconds: 180 });
  // Page.startScreencast is change-driven. Force one deterministic repaint so
  // a static about:blank fixture still yields real video frames.
  await seedFixturePage(await box.browser.cdpUrl());
  const run = await second.run("Confirm the fixture page is ready", {
    model: "fixture/browser-v1",
    maxSteps: 2,
    schema: z.object({ ok: z.boolean() }),
  });
  if (!run.completed || run.data?.ok !== true || run.inputTokens !== 7 || run.outputTokens !== 3) {
    throw new Error("browser run mismatch");
  }
  await sleep(2500);

  const recording = await recordingHandle.stop();
  if (recording.status !== "completed" || recording.stoppedReason !== "requested" || !(recording.segmentCount > 0) || !(recording.sizeBytes > 0)) {
    throw new Error(`recording completion contract mismatch: ${JSON.stringify(recording)}`);
  }
  if (!recording.markers.some((marker) => marker.type === "run" && marker.endMs !== undefined)) {
    throw new Error("recording omitted completed run marker");
  }
  if (!recording.markers.some((marker) => marker.type === "tab_switch" && marker.tabId === second.id)) {
    throw new Error("recording omitted foreground tab switch marker");
  }
  const listedRecordings = await box.browser.recordings.list();
  const fetchedRecording = await box.browser.recordings.get(recording.id);
  if (!listedRecordings.some((item) => item.id === recording.id) || fetchedRecording.id !== recording.id) {
    throw new Error("recording list/get mismatch");
  }
  const playlist = await fetch(recording.playlistUrl, { headers: { "X-Box-Api-Key": apiKey } });
  if (!playlist.ok || !playlist.headers.get("content-type")?.startsWith("application/vnd.apple.mpegurl")) {
    throw new Error("recording playlist response mismatch");
  }
  const playlistText = await playlist.text();
  const segmentName = playlistText.match(/segment-[0-9]{5}\.ts/)?.[0];
  if (!playlistText.startsWith("#EXTM3U") || !segmentName) throw new Error("recording HLS playlist mismatch");
  const segmentUrl = new URL(recording.playlistUrl);
  segmentUrl.searchParams.set("segment", segmentName);
  const segment = await fetch(segmentUrl, { headers: { "X-Box-Api-Key": apiKey } });
  const segmentBytes = new Uint8Array(await segment.arrayBuffer());
  if (!segment.ok || segment.headers.get("content-type") !== "video/mp2t" || segmentBytes.length === 0) {
    throw new Error("recording segment response mismatch");
  }
  const recordingPath = join(downloads, "phase3-recording.mp4");
  const written = await box.browser.recordings.download(recording.id, { path: recordingPath });
  const recordingBytes = await readFile(written);
  if ((await stat(written)).size === 0) throw new Error("recording download is empty");

  await waitForSchedule();
  let scheduled = await box.schedule.get(schedule.id);
  if (scheduled.total_runs < 1 || scheduled.last_run_status !== "completed" || !scheduled.last_run_id) {
    throw new Error(`schedule execution contract mismatch: ${JSON.stringify(scheduled)}`);
  }
  scheduled = await box.schedule.update(schedule.id, { cron: "*/2 * * * *" });
  if (scheduled.cron !== "*/2 * * * *") throw new Error("schedule update contract mismatch");
  await box.schedule.pause(schedule.id);
  if ((await box.schedule.get(schedule.id)).status !== "paused") throw new Error("schedule pause mismatch");
  await box.schedule.resume(schedule.id);
  if ((await box.schedule.get(schedule.id)).status !== "active") throw new Error("schedule resume mismatch");
  if (!(await box.schedule.list()).some((item) => item.id === schedule.id)) throw new Error("schedule list omitted created schedule");
  await box.schedule.delete(schedule.id);
  schedule = undefined;

  await created.close();
  if ((await box.browser.listTabs()).some((tab) => tab.id === created.id)) {
    throw new Error("closed browser tab remains listed");
  }

  const modelEvidence = await fetch(`${process.env.BOXD_MODEL_FIXTURE_URL}/evidence`).then((response) => response.json());
  for (const kind of ["extract", "observe", "act", "run"]) {
    if (modelEvidence.model_requests?.[kind] !== 1) throw new Error(`model fixture did not observe ${kind}`);
  }
  if (!modelEvidence.model_authorization_verified) throw new Error("model provider credential was not verified");

  const admin = await adminSession();
  const audit = await adminFetch(admin, "/audit?limit=100").then((response) => response.json());
  const actions = audit.audit_logs?.map((entry) => entry.action) ?? [];
  if (!actions.some((action) => action.includes("/browser/recordings"))) {
    throw new Error("durable audit omitted browser recording mutation");
  }
  if (!actions.some((action) => action.includes("/schedules"))) {
    throw new Error("durable audit omitted schedule mutation");
  }
  if (JSON.stringify(audit).includes(process.env.BOXD_MODEL_FIXTURE_KEY)) {
    throw new Error("audit leaked a model credential");
  }

  const createdKey = await adminFetch(admin, "/api-keys", {
    method: "POST",
    body: JSON.stringify({ scopes: ["boxes_read"] }),
  }).then((response) => response.json());
  quotaKeyId = createdKey.id;
  const quotaResponses = await Promise.all(Array.from({ length: quotaBurst + 1 }, () => fetch(`${baseUrl}/v2/box`, {
    headers: { "X-Box-Api-Key": createdKey.api_key },
  })));
  const quotaStatuses = quotaResponses.map((response) => response.status);
  if (!quotaStatuses.includes(429) || quotaStatuses.some((status) => status !== 200 && status !== 429)) {
    throw new Error(`request quota contract mismatch: ${quotaStatuses.join(",")}`);
  }
  await adminFetch(admin, `/api-keys/${quotaKeyId}`, { method: "DELETE" });
  quotaKeyId = undefined;

  const metrics = await fetch(`${baseUrl}/metrics`).then((response) => response.text());
  for (const metric of [
    "boxd_http_requests_total",
    "boxd_active_boxes 1",
    "boxd_vm_boot_total",
    "boxd_scheduler_lag_milliseconds",
    "boxd_disk_bytes",
    "boxd_browser_commands_total",
  ]) {
    if (!metrics.includes(metric)) throw new Error(`Prometheus output omitted ${metric}`);
  }
  if (!/boxd_http_requests_total\{surface="compatibility",status="429"\} [1-9]/.test(metrics)) {
    throw new Error("Prometheus output omitted the observed quota rejection");
  }

  const evidence = {
    schema: "boxd-phase3-complete-hvf-v1",
    source_commit: sourceCommit,
    network_mode: networkMode,
    box_id: box.id,
    create_elapsed_ms: createElapsedMs,
    retained_for_restart: retainForRestart,
    opaque_tab_id: true,
    tab_create_list_goto_content_close: true,
    screenshot_png_bytes: screenshot.length,
    screenshot_sha256: sha256(screenshot),
    browser_actions: { extract: true, observe: true, act: true, run: true },
    model_fixture_requests: modelEvidence.model_requests,
    cdp_browser_get_version: true,
    cdp_product: cdpProduct,
    screencast_view_only_jpeg: true,
    screencast_frame_bytes: screencastFrameBytes,
    metadata_navigation_http_403: true,
    recording: {
      id: recording.id,
      status: recording.status,
      stopped_reason: recording.stoppedReason,
      duration_ms: recording.durationMs,
      segment_count: recording.segmentCount,
      hls_segment_bytes: segmentBytes.length,
      download_bytes: recordingBytes.length,
      download_sha256: sha256(recordingBytes),
      marker_types: [...new Set(recording.markers.map((marker) => marker.type))].sort(),
    },
    schedule_exec_real_guest_side_effect: true,
    schedule_total_runs: scheduled.total_runs,
    schedule_crud_pause_resume_delete: true,
    quota_http_429: true,
    durable_structural_audit: true,
    prometheus_phase3_metrics: true,
  };
  await evidenceFile.writeFile(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  await evidenceFile.sync();
  committed = true;
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
} finally {
  if (schedule && box) await box.schedule.delete(schedule.id).catch(() => {});
  if (quotaKeyId) {
    const session = await adminSession().catch(() => null);
    if (session) await adminFetch(session, `/api-keys/${quotaKeyId}`, { method: "DELETE" }).catch(() => {});
  }
  if (box && (!committed || !retainForRestart)) await Box.delete({ boxIds: [box.id] }).catch(() => {});
  await rm(downloads, { recursive: true, force: true });
  await evidenceFile.close();
  if (!committed) await unlink(evidencePath).catch(() => {});
}
