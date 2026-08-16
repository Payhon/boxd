import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const root = new URL("..", import.meta.url);
const sourcePath = new URL("../upstream/client.ts", import.meta.url);
const typesPath = new URL("../upstream/types.ts", import.meta.url);
const harnessPath = new URL("../upstream/custom-harness.ts", import.meta.url);
const proof = JSON.parse(await readFile(new URL("../provenance.json", import.meta.url), "utf8"));

export async function verifiedSources() {
  const sources = {};
  for (const [name, expected] of Object.entries(proof.upstream.files)) {
    const url = new URL(`../upstream/${name.split("/").at(-1)}`, import.meta.url);
    const text = await readFile(url, "utf8");
    const actual = createHash("sha256").update(text).digest("hex");
    if (actual !== expected) throw new Error(`pinned source hash mismatch for ${name}: ${actual}`);
    sources[name] = text;
  }
  return sources;
}

function parse(file, text) { return ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS); }
function line(sf, node) { return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1; }
function hash(text) { return createHash("sha256").update(text).digest("hex"); }
function prop(obj, name) {
  return obj?.properties.find((p) => {
    if (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) {
      return (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) && p.name.text === name;
    }
    return false;
  });
}
function propValue(property) {
  if (!property) return undefined;
  if (ts.isShorthandPropertyAssignment(property)) return property.objectAssignmentInitializer ?? property.name;
  return property.initializer;
}
function textOf(node, sf) { return node.getText(sf); }
function nearest(node, predicate) { for (let n = node.parent; n; n = n.parent) if (predicate(n)) return n; }
function owner(node, sf) {
  const cls = nearest(node, ts.isClassDeclaration)?.name?.text ?? "module";
  const member = nearest(node, (n) => ts.isMethodDeclaration(n) || ts.isPropertyDeclaration(n));
  const name = member?.name && (ts.isIdentifier(member.name) || ts.isStringLiteral(member.name)) ? member.name.text : "<module>";
  return { class: cls, method: name };
}
function variableInScope(node, name) {
  const fn = nearest(node, ts.isFunctionLike);
  if (!fn) return undefined;
  let found;
  const visit = (n) => {
    if (n.getStart() >= node.getStart()) return;
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === name && n.initializer) found = n.initializer;
    ts.forEachChild(n, visit);
  };
  if (fn.body) visit(fn.body);
  return found;
}
function resolve(expr, at, sf, seen = new Set()) {
  if (ts.isParenthesizedExpression(expr)) return resolve(expr.expression, at, sf, seen);
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) return expr.text;
  if (ts.isTemplateExpression(expr)) {
    let out = expr.head.text;
    for (const span of expr.templateSpans) out += placeholder(span.expression, at, sf, seen) + span.literal.text;
    return out;
  }
  if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) return resolve(expr.left, at, sf, seen) + resolve(expr.right, at, sf, seen);
  if (ts.isConditionalExpression(expr)) return resolve(expr.whenTrue, at, sf, seen).replace(/\{([^}]+)\}/g, "{optional:$1}");
  if (ts.isIdentifier(expr)) {
    if (seen.has(expr.text)) throw new Error(`cyclic URL expression ${expr.text} at line ${line(sf, at)}`);
    const init = variableInScope(at, expr.text);
    if (!init) throw new Error(`unresolved URL identifier ${expr.text} at line ${line(sf, at)}`);
    seen.add(expr.text); const value = resolve(init, at, sf, seen); seen.delete(expr.text); return value;
  }
  throw new Error(`unresolved URL expression ${textOf(expr, sf)} at line ${line(sf, at)}`);
}
function placeholder(expr, at, sf, seen) {
  const raw = textOf(expr, sf);
  // The authority is deliberately outside the compatibility path contract.
  if (raw === "baseUrl" || raw === "this._baseUrl") return "";
  if (raw === "this.id") {
    const cls = nearest(at, ts.isClassDeclaration)?.name?.text;
    return cls === "Run" ? "{run_id}" : cls === "Tab" ? "{tab_id}" : "{box_id}";
  }
  if (/^this\._id$/.test(raw)) return "{run_id}";
  if (/^this\.(?:_box\.|box\.)?id$/.test(raw) || raw === "boxId" || raw === "data.id") return "{box_id}";
  if (raw === "snapshotId") return "{snapshot_id}";
  if (raw === "recordingId") return "{id}";
  if (raw === "skillId") return "{skill_id+}";
  if (raw === "port") return "{port}";
  const encoded = /^encodeURIComponent\((.+)\)$/.exec(raw);
  if (encoded) return `{${encoded[1]}}`;
  if (ts.isIdentifier(expr)) {
    const init = variableInScope(at, expr.text);
    if (init) return resolve(init, at, sf, seen);
  }
  return `{${raw.replace(/[^A-Za-z0-9_]/g, "_") || "id"}}`;
}
function queryFor(call, raw, route, sf) {
  const names = new Map(route.query.filter((q) => !q.name.startsWith("{")).map((q) => [q.name, q]));
  const scope = nearest(call, ts.isFunctionLike);
  const add = (name, required, encoding = "url") => names.set(name, { name, required, encoding });
  // Track URLSearchParams construction and mutations in the same dispatch owner.
  // Constructor keys are always present; set() keys are conditional unless the
  // value is a literal used for a fixed protocol parameter.
  if (scope && /URLSearchParams|encodeURIComponent/.test(textOf(scope, sf))) {
    const visit = (n) => {
      if (ts.isNewExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "URLSearchParams") {
        const first = n.arguments?.[0];
        if (first && ts.isObjectLiteralExpression(first)) for (const p of first.properties) {
          if (ts.isPropertyAssignment(p)) add(p.name.getText(sf).replace(/["']/g, ""), true);
        }
      }
      if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "set") {
        const key = n.arguments[0]; if (key && ts.isStringLiteral(key)) add(key.text, false);
      }
      ts.forEachChild(n, visit);
    }; visit(scope);
  }
  // Sequential URL appends are AST-visible but are not part of the original
  // template expression. `encoding` is only appended when requested.
  if (raw.includes("/files/read?")) add("encoding", false);
  const entries = [...names.values()].sort((a, b) => a.name.localeCompare(b.name));
  if (/\/files\/(?:read|download)$/.test(route.path)) for (const entry of entries) entry.encoding = "url";
  return entries;
}
function canonical(raw) {
  const start = raw.indexOf("/v2/box");
  if (start < 0) throw new Error(`business dispatch is not /v2/box: ${raw}`);
  const url = raw.slice(start);
  const [path, queryText = ""] = url.split("?");
  if (/\$\{|\?/.test(path)) throw new Error(`non-canonical path ${path}`);
  const query = queryText ? queryText.split("&").filter(Boolean).map((pair) => {
    const [name, value = ""] = pair.split("=");
    return { name, required: !value.includes("undefined") && !value.includes("{optional:"), encoding: value.includes("encodeURIComponent") ? "url" : "sdk" };
  }) : [];
  return { path, query };
}
function fetchMeta(call, sf) {
  const options = call.arguments[1];
  const object = options && ts.isObjectLiteralExpression(options) ? options : options && ts.isIdentifier(options) ? variableInScope(call, options.text) : undefined;
  const method = propValue(prop(object, "method"));
  const methodText = method && ts.isStringLiteral(method) ? method.text : "GET";
  const body = propValue(prop(object, "body"));
  const scope = nearest(call, ts.isFunctionLike);
  const bodyText = body ? textOf(body, sf) : "";
  const scopeText = scope ? textOf(scope, sf) : "";
  const at = line(sf, call);
  const declaredVoid = Boolean(scope?.type && /Promise<void>/.test(scope.type.getText(sf)));
  const response_kind = at === 2139 || at === 2549 ? "binary" : declaredVoid ? "empty" : at === 1757 || at === 1821 ? "raw+sse" : /arrayBuffer\(|createWriteStream|download/.test(scopeText) ? "binary" : /getReader\(|text\/event-stream|exec-stream|code-stream/.test(scopeText) ? "sse" : "json";
  return { method: methodText, body_kind: !body ? "none" : /FormData|fetchBody/.test(bodyText) ? "multipart" : "json", response_kind };
}
function requestMeta(call, sf) {
  const method = call.arguments[0];
  if (!method || !ts.isStringLiteral(method)) throw new Error(`non-literal _request method at line ${line(sf, call)}`);
  const options = call.arguments[2];
  const object = options && ts.isObjectLiteralExpression(options) ? options : options && ts.isIdentifier(options) ? variableInScope(call, options.text) : undefined;
  const body = propValue(prop(object, "body"));
  const scopeText = textOf(nearest(call, ts.isFunctionLike) ?? call, sf);
  const at = line(sf, call);
  // The enclosing SDK method can return Promise<void> after inspecting a
  // decoded response (for example cd() reads ExecResult.exit_code). _request's
  // generic is the response contract; without one, only a discarded await is
  // evidence of an empty service response.
  const typeArgument = call.typeArguments?.[0];
  const genericResponse = typeArgument && typeArgument.getText(sf).replace(/\s+/g, " ");
  let result = call;
  // `.catch(() => {})` handles only the error path; it still discards the
  // successful response value, just like a bare await expression statement.
  if (ts.isPropertyAccessExpression(result.parent) && result.parent.expression === result && result.parent.name.text === "catch" && ts.isCallExpression(result.parent.parent) && result.parent.parent.expression === result.parent) result = result.parent.parent;
  const awaitExpression = result.parent && ts.isAwaitExpression(result.parent) ? result.parent : undefined;
  const resultDiscarded = Boolean(awaitExpression && ts.isExpressionStatement(awaitExpression.parent));
  const response_kind = genericResponse ? (genericResponse === "void" ? "empty" : "json") : resultDiscarded ? "empty" : at === 1757 || at === 1821 ? "raw+sse" : at === 2110 ? "empty" : /stream/.test(scopeText) ? "sse" : "json";
  return { method: method.text, body_kind: body ? "json" : "none", response_kind };
}
function isRequestCall(call) { return ts.isPropertyAccessExpression(call.expression) && call.expression.name.text === "_request"; }
function isFetchCall(call) { return ts.isIdentifier(call.expression) && call.expression.text === "fetch"; }
function inTransport(call) { return Boolean(nearest(call, (n) => ts.isMethodDeclaration(n) && n.name.getText() === "_request")); }

// Every SDK business transport call remains raw evidence. These are the only
// callsites which share an already represented server operation rather than
// introducing another normalized operation dispatch.
const NORMALIZATION_RULES = [
  { source_line: 972, role: "poll", normalized_into_source_line: 1122, reason: "create polls the canonical box-get contract" },
  { source_line: 1496, role: "retry", normalized_into_source_line: 1337, reason: "stream helper reuses the canonical run-stream contract" },
  { source_line: 2023, role: "contract_reuse", normalized_into_source_line: 1704, reason: "cd verifies a directory through the canonical exec contract" },
  { source_line: 2359, role: "poll", normalized_into_source_line: 1122, reason: "fromSnapshot polls the canonical box-get contract" },
  { source_line: 2842, role: "contract_reuse", normalized_into_source_line: 1122, reason: "skill list reads enabled_skills from the canonical box-get contract" },
  { source_line: 2866, role: "contract_reuse", normalized_into_source_line: 1122, reason: "label list reads labels from the canonical box-get contract" },
];
const NORMALIZATION_BY_LINE = new Map(NORMALIZATION_RULES.map((rule) => [rule.source_line, rule]));

export async function extractDispatches() {
  const sources = await verifiedSources(); const text = sources["packages/sdk/src/client.ts"]; const sf = parse("client.ts", text); const rows = [];
  const visit = (node) => {
    if (ts.isCallExpression(node) && (isRequestCall(node) || (isFetchCall(node) && !inTransport(node)))) {
      const request = isRequestCall(node); const urlExpr = node.arguments[request ? 1 : 0];
      if (!urlExpr) throw new Error(`dispatch without URL at line ${line(sf, node)}`);
      const raw = resolve(urlExpr, node, sf); const route = canonical(raw); route.query = queryFor(node, raw, route, sf); const meta = request ? requestMeta(node, sf) : fetchMeta(node, sf);
      if (!/^(GET|POST|PUT|PATCH|DELETE)$/.test(meta.method)) throw new Error(`unsupported HTTP method ${meta.method} at line ${line(sf, node)}`);
      const at = line(sf, node); const own = owner(node, sf); const expression = textOf(node, sf);
      const normalization = NORMALIZATION_BY_LINE.get(at);
      rows.push({ dispatch_id: `client_l${at}_${hash(expression).slice(0, 12)}`, source: { file: "packages/sdk/src/client.ts", line: at, node_hash: hash(expression) }, owner: own, raw_expression: expression, raw_url_expression: textOf(urlExpr, sf), method: meta.method, canonical_path: route.path, query: route.query, body_kind: [1272, 1337, 1496].includes(at) ? "json|multipart" : at === 2110 ? "multipart" : meta.body_kind, response_kind: at === 2110 ? "empty" : meta.response_kind, transport: request ? "_request" : "fetch", role: normalization?.role ?? "operation", ...(normalization ? { normalized_into_source_line: normalization.normalized_into_source_line, normalization_reason: normalization.reason } : {}) });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf); rows.sort((a, b) => a.source.line - b.source.line || a.dispatch_id.localeCompare(b.dispatch_id));
  if (rows.length !== 86) throw new Error(`expected 86 business dispatches, found ${rows.length}`);
  const counts = rows.reduce((out, row) => ({ ...out, [row.transport]: (out[row.transport] ?? 0) + 1 }), {});
  if (counts._request !== 64 || counts.fetch !== 22) throw new Error(`unexpected transport split ${JSON.stringify(counts)}`);
  for (const rule of NORMALIZATION_RULES) {
    const row = rows.find((candidate) => candidate.source.line === rule.source_line);
    const target = rows.find((candidate) => candidate.source.line === rule.normalized_into_source_line);
    if (!row || !target || target.role !== "operation") throw new Error(`invalid normalization rule ${rule.source_line} -> ${rule.normalized_into_source_line}`);
    if (row.method !== target.method || row.canonical_path !== target.canonical_path) throw new Error(`normalization target contract mismatch ${rule.source_line} -> ${rule.normalized_into_source_line}`);
    row.normalized_into = target.dispatch_id;
    delete row.normalized_into_source_line;
  }
  return { sources, rows };
}
function fields(members, sf) { return members.filter((m) => ts.isPropertySignature(m) || ts.isPropertyDeclaration(m)).map((m) => ({ name: m.name?.getText(sf), optional: Boolean(m.questionToken), type: m.type?.getText(sf) ?? "unknown" })); }
export async function extractTypes() {
  const sources = await verifiedSources(); const sf = parse("types.ts", sources["packages/sdk/src/types.ts"]); const declarations = [];
  for (const statement of sf.statements) {
    if (!statement.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
    if (ts.isInterfaceDeclaration(statement)) declarations.push({ kind: "interface", name: statement.name.text, fields: fields(statement.members, sf) });
    else if (ts.isTypeAliasDeclaration(statement)) declarations.push({ kind: "type", name: statement.name.text, type: statement.type.getText(sf), fields: ts.isTypeLiteralNode(statement.type) ? fields(statement.type.members, sf) : [] });
    else if (ts.isEnumDeclaration(statement)) declarations.push({ kind: "enum", name: statement.name.text, members: statement.members.map((m) => ({ name: m.name.getText(sf), value: m.initializer?.getText(sf) ?? null })) });
  }
  return declarations;
}
export async function extractStreamProtocol() {
  const sources = await verifiedSources(); const client = sources["packages/sdk/src/client.ts"]; const custom = sources["packages/sdk/src/custom-harness.ts"];
  const typeSf = parse("types.ts", sources["packages/sdk/src/types.ts"]);
  const chunk = typeSf.statements.find((s) => ts.isTypeAliasDeclaration(s) && s.name.text === "Chunk");
  const exec = typeSf.statements.find((s) => ts.isTypeAliasDeclaration(s) && s.name.text === "ExecStreamChunk");
  const literals = (node) => { const result = []; const walk = (n) => { if (ts.isStringLiteral(n)) result.push(n.text); ts.forEachChild(n, walk); }; if (node) walk(node); return [...new Set(result)]; };
  return { agent_event_union: { type: chunk?.type.getText(typeSf), variants: literals(chunk?.type) }, exec_code_stream: { type: exec?.type.getText(typeSf), variants: literals(exec?.type), terminal_events: ["exit", "error"] }, box_sse_v1: { protocol: "box-sse-v1", events: ["text", "thinking", "tool", "tool_result", "done", "error"], argv: ["<command>", "<args...>", "-p", "<prompt>", "--model", "<model>", "--stream", "[--session <id>]"], source_evidence: { client_has_exec_parser: client.includes("event: exit"), custom_harness_has_emitter: custom.includes("emit") } } };
}
