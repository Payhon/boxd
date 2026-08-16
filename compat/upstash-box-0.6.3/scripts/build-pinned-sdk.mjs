// Build the vendored pinned source in a throw-away directory.  This deliberately
// does not import node_modules/@upstash/box: contract execution must exercise the
// reviewed source snapshot.
import { createHash } from "node:crypto";
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";

const root = new URL("../", import.meta.url);
const provenance = JSON.parse(await readFile(new URL("../provenance.json", import.meta.url), "utf8"));
const files = {
  "client.ts": "packages/sdk/src/client.ts",
  "types.ts": "packages/sdk/src/types.ts",
  "custom-harness.ts": "packages/sdk/src/custom-harness.ts",
  "telemetry.ts": "packages/sdk/src/telemetry.ts",
  "version.ts": "packages/sdk/src/version.ts",
  "index.ts": "packages/sdk/src/index.ts",
};
for (const [local, upstream] of Object.entries(files)) {
  const actual = createHash("sha256").update(await readFile(new URL(`../upstream/${local}`, import.meta.url))).digest("hex");
  const expected = provenance.upstream.files[upstream];
  if (actual !== expected) throw new Error(`pinned source hash mismatch for ${upstream}: expected ${expected}, got ${actual}`);
}

const dir = await mkdtemp(join(tmpdir(), "boxd-pinned-sdk-"));
try {
  // Let Node resolve the pinned project's already locked dependencies while the
  // executable source itself remains the copied, hash-verified snapshot.
  await symlink(new URL("../node_modules", import.meta.url), join(dir, "node_modules"));
  for (const name of Object.keys(files)) await cp(new URL(`../upstream/${name}`, import.meta.url), join(dir, name));
  const source = Object.keys(files);
  for (const file of source) {
    const input = await readFile(join(dir, file), "utf8");
    const output = ts.transpileModule(input, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, esModuleInterop: true }, fileName: file });
    await writeFile(join(dir, file.replace(/\.ts$/, ".js")), output.outputText);
  }
  const entry = pathToFileURL(join(dir, "index.js")).href;
  const sdk = await import(entry);
  if (!sdk.Box || !sdk.EphemeralBox) throw new Error("pinned SDK build did not export Box and EphemeralBox");
  // A build is intentionally retained only until its consumer imports it. The
  // parent runner owns cleanup and receives an opaque token tied to this dir.
  // This avoids both a use-after-cleanup race and leaked throw-away trees.
  const cleanup = { dir, token: createHash("sha256").update(dir).digest("hex") };
  if (process.argv.includes("--json")) console.log(JSON.stringify({ dir, entry, cleanup, source_commit: provenance.upstream.commit }));
  else console.log(entry);
  // Consumers import before the process exits; keeping a process-local temp tree
  // is intentional.  Do not clean it here.
} catch (error) {
  await rm(dir, { recursive: true, force: true });
  throw new Error(`failed to compile vendored pinned SDK with local TypeScript: ${error instanceof Error ? error.message : error}`);
}
