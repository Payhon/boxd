import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Box } from "@upstash/box";
import { deleteBoxQuietly, requireBoxdEnvironment } from "./_common.mjs";

requireBoxdEnvironment();

const targetUrl = process.env.BOXD_EXAMPLE_URL ?? "https://example.com";
const screenshotPath = resolve(
  process.env.BOXD_EXAMPLE_SCREENSHOT ?? "boxd-browser-example.png",
);
let box;
let tab;
try {
  box = await Box.create({
    runtime: "node",
    browser: true,
    name: "example-browser",
    labels: ["example", "browser"],
    timeout: 300_000,
  });
  tab = await box.browser.tab.create(targetUrl, { waitUntil: "load", timeout: 30_000 });

  const content = await tab.content();
  console.log("page:", { url: content.url, title: content.title });
  console.log("text preview:", content.text.slice(0, 160));

  const screenshot = await tab.screenshot({ type: "png", fullPage: true });
  await writeFile(screenshotPath, screenshot, { flag: "wx", mode: 0o600 });
  console.log("screenshot:", screenshotPath, `${screenshot.length} bytes`);

  const cdpUrl = await box.browser.cdpUrl();
  console.log("single-use CDP ticket issued:", new URL(cdpUrl).protocol);
} finally {
  if (tab) await tab.close().catch(() => {});
  await deleteBoxQuietly(box);
}
