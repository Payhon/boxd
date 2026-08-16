#!/usr/bin/env node

import { createHash } from "node:crypto";
import { open, readFile, unlink } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const [sdkEntry, lifecycleEvidencePath, restartEvidencePath] = process.argv.slice(2);
if (!sdkEntry || !lifecycleEvidencePath || !restartEvidencePath) {
  throw new Error("usage: phase3-browser-restart-smoke.mjs SDK_ENTRY LIFECYCLE_JSON RESTART_JSON");
}
if (!process.env.UPSTASH_BOX_API_KEY || !process.env.UPSTASH_BOX_BASE_URL) {
  throw new Error("UPSTASH_BOX_API_KEY and UPSTASH_BOX_BASE_URL are required");
}

const resolvedSdkEntry = sdkEntry.startsWith("file:") ? sdkEntry : pathToFileURL(sdkEntry).href;
const { Box } = await import(resolvedSdkEntry);
const lifecycle = JSON.parse(await readFile(lifecycleEvidencePath, "utf8"));
if (lifecycle.schema !== "boxd-phase3-complete-hvf-v1" || !lifecycle.retained_for_restart) {
  throw new Error("lifecycle evidence was not retained for restart");
}

let box;
let committed = false;
const retainOnFailure = process.env.BOXD_RESTART_RETAIN_ON_FAILURE === "true";
const evidenceFile = await open(restartEvidencePath, "wx", 0o600);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function retryTransient(operation, label) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    try {
      return await operation();
    } catch (error) {
      if (![409, 503].includes(error?.statusCode)) throw error;
      await sleep(500);
    }
  }
  throw new Error(`${label} remained busy for 90 seconds after reconciliation`);
}

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
  let id = 200;
  const command = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const commandId = id++;
    const onMessage = (event) => {
      const message = JSON.parse(String(event.data));
      if (message.id !== commandId) return;
      socket.removeEventListener("message", onMessage);
      if (message.error) reject(new Error(`CDP ${method} failed: ${message.error.message}`));
      else resolve(message.result ?? {});
    };
    socket.addEventListener("message", onMessage, { signal: timeout });
    socket.send(JSON.stringify({ id: commandId, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  try {
    const { targetInfos = [] } = await command("Target.getTargets");
    const pages = targetInfos.filter((target) => target.type === "page" && target.url === "about:blank");
    if (pages.length === 0) throw new Error("CDP fixture found no about:blank page");
    const html = "<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>Restart fixture.</p></body></html>";
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

try {
  box = await Box.get(lifecycle.box_id);
  if ((await box.getStatus()).status !== "idle") {
    throw new Error("reconciled browser box is not idle");
  }
  const scheduleFile = await retryTransient(
    () => box.files.read("phase3-schedule.txt"),
    "persisted file read",
  );
  if (scheduleFile !== "phase3-schedule-ran") throw new Error("schedule side effect did not persist");
  const tab = await retryTransient(
    () => box.browser.tab.create("about:blank", { waitUntil: "load", timeout: 30_000 }),
    "browser tab create",
  );
  await seedFixturePage(await retryTransient(() => box.browser.cdpUrl(), "browser CDP ticket"));
  const content = await retryTransient(() => tab.content(), "browser content");
  const screenshot = await retryTransient(() => tab.screenshot({ type: "png" }), "browser screenshot");
  if (!content.text.includes("Example Domain") || screenshot[0] !== 0x89 || screenshot[1] !== 0x50) {
    throw new Error("browser did not recover after daemon restart");
  }
  const evidence = {
    schema: "boxd-phase3-complete-restart-v1",
    box_id: box.id,
    ready_after_reconciliation: true,
    persisted_schedule_side_effect: true,
    browser_tab_after_restart: true,
    screenshot_png_bytes: screenshot.length,
    screenshot_sha256: sha256(screenshot),
    bulk_delete_count: 1,
  };
  await retryTransient(() => Box.delete({ boxIds: [box.id] }), "bulk delete");
  box = undefined;
  await evidenceFile.writeFile(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  await evidenceFile.sync();
  committed = true;
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
} finally {
  if (box && !retainOnFailure) await Box.delete({ boxIds: [box.id] }).catch(() => {});
  await evidenceFile.close();
  if (!committed) await unlink(restartEvidencePath).catch(() => {});
}
