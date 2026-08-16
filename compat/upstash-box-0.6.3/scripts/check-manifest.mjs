import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
const generated = JSON.parse(execFileSync(process.execPath, [new URL("./generate-manifest.mjs", import.meta.url).pathname, "--stdout"], { encoding: "utf8" }));
for (const name of Object.keys(generated)) { const committed = await readFile(new URL(`../${name}`, import.meta.url), "utf8"); if (committed !== generated[name]) throw new Error(`${name} is stale; run npm run generate:manifest and review the source-derived diff`); }
const raw = JSON.parse(generated["raw-dispatch-manifest.json"]); const routes = JSON.parse(generated["route-manifest.json"]);
if (raw.dispatches.length !== 86 || raw.extraction.raw_call_sites !== 86 || raw.extraction.normalized_operation_dispatches !== 80 || raw.extraction.direct_method_path_contracts !== 77 || raw.extraction.response_linked_contracts !== 1 || raw.extraction.total_server_contracts !== 78 || raw.extraction.transport_counts._request !== 64 || raw.extraction.transport_counts.fetch !== 22 || routes.extraction.raw_call_sites !== 86 || routes.extraction.normalized_operation_dispatches !== 80 || routes.extraction.direct_method_path_contracts !== 77 || routes.extraction.response_linked_contracts !== 1 || routes.extraction.total_server_contracts !== 78 || routes.extraction.transport_counts._request !== 64 || routes.extraction.transport_counts.fetch !== 22 || routes.routes.length !== 78) throw new Error("dispatch count gate failed");
const routeDispatches = new Set(routes.routes.flatMap((route) => route.dispatch_ids));
for (const dispatch of raw.dispatches) if (!routeDispatches.has(dispatch.dispatch_id)) throw new Error(`raw dispatch is not consumed by a route ${dispatch.dispatch_id}`);
const operations = new Set(raw.dispatches.filter((dispatch) => dispatch.role === "operation").map((dispatch) => dispatch.dispatch_id));
if (raw.normalization.length !== 6) throw new Error("normalization rule count gate failed");
for (const normalization of raw.normalization) if (!operations.has(normalization.normalized_into)) throw new Error(`normalization target is not an operation ${normalization.dispatch_id}`);
for (const route of routes.routes) if (route.path.includes("${") || route.path.includes("?")) throw new Error(`non-canonical route ${route.path}`);
for (const route of routes.routes) if (/\{(?:this|params|optional)/.test(route.path)) throw new Error(`non-stable placeholder ${route.path}`);
console.log(JSON.stringify(routes.extraction, null, 2));
