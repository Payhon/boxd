import { Box } from "@upstash/box";
import { deleteBoxQuietly, requireBoxdEnvironment } from "./_common.mjs";

requireBoxdEnvironment();

let source;
let restored;
let snapshot;
try {
  source = await Box.create({
    runtime: "node",
    name: "example-snapshot-source",
    labels: ["example", "snapshot"],
    networkPolicy: { mode: "deny-all" },
    timeout: 300_000,
  });
  await source.files.write({
    path: "snapshot.txt",
    content: `created by ${source.id}\n`,
  });

  snapshot = await source.snapshot({ name: "example-snapshot" });
  console.log("snapshot ready:", snapshot.id, snapshot.status);

  restored = await Box.fromSnapshot(snapshot.id, {
    name: "example-snapshot-restored",
    labels: ["example", "restored"],
    timeout: 300_000,
  });
  console.log("restored box:", restored.id);
  console.log("restored content:", (await restored.files.read("snapshot.txt")).trim());
} finally {
  await deleteBoxQuietly(restored);
  if (source && snapshot) await source.deleteSnapshot(snapshot.id).catch(() => {});
  await deleteBoxQuietly(source);
}
