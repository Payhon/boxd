import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
const proof = JSON.parse(await readFile(new URL("../provenance.json", import.meta.url)));
const dir = new URL("../upstream/", import.meta.url);
await mkdir(dir, { recursive: true });
for (const [file, expected] of Object.entries(proof.upstream.files)) {
  const url = `https://raw.githubusercontent.com/upstash/box/${proof.upstream.commit}/${file}`;
  const response = await fetch(url);
  if (!response.ok) throw new Error(`fetch ${url}: ${response.status}`);
  const text = await response.text();
  const hash = createHash("sha256").update(text).digest("hex");
  if (hash !== expected) throw new Error(`hash mismatch ${file}`);
  await writeFile(new URL(file.split("/").pop(), dir), text);
}
const licenseResponse = await fetch(`https://raw.githubusercontent.com/upstash/box/${proof.upstream.commit}/LICENSE`);
if (!licenseResponse.ok) throw new Error(`fetch LICENSE: ${licenseResponse.status}`);
const license = await licenseResponse.text();
await writeFile(new URL("LICENSE", dir), license);
await writeFile(new URL("SOURCE.md", dir), `Vendored unchanged from https://github.com/upstash/box commit ${proof.upstream.commit}.\nFiles are verified by provenance.json SHA-256, including telemetry.ts and its local version.ts dependency.\nupstream/index.ts is included as the real package entrypoint used by the pinned build. Upstream LICENSE is included in this directory.\n`);
