import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { extractDispatches, extractStreamProtocol, extractTypes } from "./extract-source.mjs";

const stdout = process.argv.includes("--stdout");
const { sources, rows } = await extractDispatches();
const overrides = JSON.parse(await readFile(new URL("../route-overrides.json", import.meta.url), "utf8"));
const matchedOverrides = new Set();
for (const override of overrides.overrides ?? []) {
  const match = rows.find((row) => row.source.line === override.source_line && row.source.node_hash === override.node_hash);
  if (!match) throw new Error(`stale or unknown override at ${override.source_line}:${override.node_hash}`);
  if (!override.route?.method || !override.route?.path) throw new Error(`incomplete override at ${override.source_line}`);
  if (matchedOverrides.has(match.dispatch_id)) throw new Error(`duplicate override for ${match.dispatch_id}`);
  matchedOverrides.add(match.dispatch_id);
  Object.assign(match, { method: override.route.method, canonical_path: override.route.path, query: override.route.query ?? match.query, body_kind: override.route.body_kind ?? match.body_kind, response_kind: override.route.response_kind ?? match.response_kind, override: { source_line: override.source_line, node_hash: override.node_hash } });
}
if (matchedOverrides.size !== (overrides.overrides ?? []).length) throw new Error("override consumption mismatch");
const normalized = rows.filter((row) => row.role === "operation");
if (normalized.length !== 80) throw new Error(`expected 80 normalized operation dispatches, found ${normalized.length}`);
const grouped = new Map();
for (const row of rows) { const key = `${row.method} ${row.canonical_path}`; const entry = grouped.get(key) ?? { method: row.method, path: row.canonical_path, query: row.query, dispatch_ids: [], operation_variants: [] }; entry.dispatch_ids.push(row.dispatch_id); entry.operation_variants.push({ owner: row.owner, source_line: row.source.line, body_kind: row.body_kind, response_kind: row.response_kind, role: row.role, ...(row.normalized_into ? { normalized_into: row.normalized_into, normalization_reason: row.normalization_reason } : {}) }); grouped.set(key, entry); }
const directContracts = grouped.size;
// playlist is a response-linked recording capability: the SDK does not fetch it,
// but recording metadata exposes this stable service URL. It is intentionally not
// counted as a raw dispatch.
grouped.set("GET /v2/box/{box_id}/browser/recordings/{id}/playlist", { method: "GET", path: "/v2/box/{box_id}/browser/recordings/{id}/playlist", query: [], dispatch_ids: [], operation_variants: [{ owner: { class: "Box", method: "_recordingGet" }, source_line: 2533, body_kind: "none", response_kind: "hls", role: "response_linked_capability", relation: "response_linked_capability" }] });
const extraction = { raw_call_sites: rows.length, normalized_operation_dispatches: normalized.length, direct_method_path_contracts: directContracts, response_linked_contracts: 1, total_server_contracts: directContracts + 1, transport_counts: rows.reduce((counts, row) => ({ ...counts, [row.transport]: (counts[row.transport] ?? 0) + 1 }), {}) };
const raw = { sdk: "@upstash/box@0.6.3", source_commit: "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934", source_sha256: Object.fromEntries(Object.entries(sources).map(([k, v]) => [k, createHash("sha256").update(v).digest("hex")])), extraction, normalization: rows.filter((row) => row.role !== "operation").map(({ dispatch_id, source, role, normalized_into, normalization_reason }) => ({ dispatch_id, source_line: source.line, role, normalized_into, reason: normalization_reason })), dispatches: rows };
const route = { sdk: raw.sdk, source_commit: raw.source_commit, source_sha256: raw.source_sha256, extraction, routes: [...grouped.values()].sort((a,b) => `${a.method} ${a.path}`.localeCompare(`${b.method} ${b.path}`)) };
if (directContracts !== 77 || route.extraction.total_server_contracts !== 78) throw new Error(`expected 77 direct and 78 total contracts, found ${directContracts}/${route.extraction.total_server_contracts}`);
const types = { sdk: raw.sdk, source_commit: raw.source_commit, source_sha256: raw.source_sha256, declarations: await extractTypes() };
const streams = { sdk: raw.sdk, source_commit: raw.source_commit, source_sha256: raw.source_sha256, protocol: await extractStreamProtocol() };
const files = [["raw-dispatch-manifest.json", raw], ["route-manifest.json", route], ["types-manifest.json", types], ["stream-manifest.json", streams]];
const output = Object.fromEntries(files.map(([name, value]) => [name, `${JSON.stringify(value, null, 2)}\n`]));
if (stdout) process.stdout.write(JSON.stringify(output)); else for (const [name, value] of Object.entries(output)) await writeFile(new URL(`../${name}`, import.meta.url), value);
