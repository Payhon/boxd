import { Box } from "@upstash/box";
import { assertSuccessfulRun, deleteBoxQuietly, requireBoxdEnvironment } from "./_common.mjs";

requireBoxdEnvironment();

const targetUrl = new URL(process.env.BOXD_EXAMPLE_URL ?? "https://example.com");
if (!new Set(["http:", "https:"]).has(targetUrl.protocol)) {
  throw new Error("BOXD_EXAMPLE_URL must use HTTP or HTTPS");
}
const disallowedUrl =
  targetUrl.hostname === "www.iana.org" ? "https://example.net" : "https://www.iana.org";

let box;
try {
  box = await Box.create({
    runtime: "node",
    name: "example-custom-network-policy",
    labels: ["example", "network-policy"],
    networkPolicy: {
      mode: "custom",
      allowedDomains: [targetUrl.hostname],
      deniedCidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    },
    timeout: 300_000,
  });

  const run = await box.exec.code({
    language: "javascript",
    code: `
      const response = await fetch(${JSON.stringify(targetUrl.href)});
      console.log(JSON.stringify({ status: response.status, url: response.url }));
      if (!response.ok) process.exitCode = 1;
    `,
  });
  assertSuccessfulRun(run, "custom network request");
  console.log("allowed request:", run.stdout.trim());

  const blocked = await box.exec.code({
    language: "javascript",
    code: `
      try {
        await fetch(${JSON.stringify(disallowedUrl)}, { signal: AbortSignal.timeout(5000) });
        console.error("disallowed domain request unexpectedly succeeded");
        process.exitCode = 1;
      } catch {
        console.log("disallowed domain request blocked");
      }
    `,
  });
  assertSuccessfulRun(blocked, "blocked domain request");
  console.log(blocked.stdout.trim());
} finally {
  await deleteBoxQuietly(box);
}
