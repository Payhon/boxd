import { EphemeralBox } from "@upstash/box";
import { assertSuccessfulRun, requireBoxdEnvironment } from "./_common.mjs";

requireBoxdEnvironment();

let box;
try {
  box = await EphemeralBox.create({
    runtime: "node",
    ttl: 300,
    name: "example-ephemeral",
    labels: ["example", "ephemeral"],
    env: { BOXD_EPHEMERAL_MESSAGE: "short-lived" },
    networkPolicy: { mode: "deny-all" },
    timeout: 300_000,
  });
  console.log("ephemeral box:", box.id, "expires at", new Date(box.expiresAt * 1000));

  const run = await box.exec.command("printf '%s' \"$BOXD_EPHEMERAL_MESSAGE\"");
  assertSuccessfulRun(run, "ephemeral command");
  console.log("output:", run.stdout);

  await box.files.write({ path: "ephemeral.txt", content: "temporary data\n" });
  console.log("file:", (await box.files.read("ephemeral.txt")).trim());
} finally {
  if (box) await box.delete().catch((error) => console.error("cleanup failed:", error));
}
