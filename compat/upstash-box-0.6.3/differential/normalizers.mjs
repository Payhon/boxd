const DEFAULT_VOLATILE_KEYS = new Set([
  "box_id",
  "created_at",
  "customer_id",
  "expires_at",
  "finished_at",
  "id",
  "request_id",
  "run_id",
  "session_id",
  "snapshot_id",
  "started_at",
  "updated_at",
]);

const DEFAULT_SECRET_KEYS = /(?:api[_-]?key|authorization|cookie|credential|password|secret|token)/i;

export function normalizeJson(value, options = {}) {
  const volatileKeys = new Set(options.volatileKeys ?? DEFAULT_VOLATILE_KEYS);
  const secretKeys = options.secretKeys ?? DEFAULT_SECRET_KEYS;
  const visit = (item, key = "") => {
    if (secretKeys.test(key)) return "<redacted>";
    if (volatileKeys.has(key)) return `<${key}>`;
    if (Array.isArray(item)) return item.map((entry) => visit(entry));
    if (item && typeof item === "object") {
      return Object.fromEntries(
        Object.keys(item)
          .sort()
          .map((name) => [name, visit(item[name], name)]),
      );
    }
    return item;
  };
  return visit(value);
}

const COMPARABLE_HEADERS = new Set([
  "cache-control",
  "connection",
  "content-disposition",
  "content-type",
  "x-accel-buffering",
]);

export function normalizeHeaders(headers, options = {}) {
  const selected = new Set(options.comparable ?? COMPARABLE_HEADERS);
  const input = headers instanceof Headers ? [...headers.entries()] : Array.isArray(headers) ? headers : Object.entries(headers ?? {});
  return Object.fromEntries(
    input
      .map(([name, value]) => [String(name).toLowerCase(), String(value).trim()])
      .filter(([name]) => selected.has(name))
      .map(([name, value]) => [name, name === "content-type" ? value.replace(/boundary=[^;]+/i, "boundary=<generated>") : value])
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

function parseSseData(lines) {
  const text = lines.join("\n");
  try {
    return normalizeJson(JSON.parse(text));
  } catch {
    return text;
  }
}

export function normalizeSse(input) {
  const text = typeof input === "string" ? input : new TextDecoder().decode(input);
  const frames = [];
  let event = "message";
  let data = [];
  let id = null;
  const flush = () => {
    if (data.length === 0 && event === "message" && id === null) return;
    frames.push({ event, id: id === null ? null : "<event_id>", data: parseSseData(data) });
    event = "message";
    data = [];
    id = null;
  };
  for (const line of text.replace(/\r\n?/g, "\n").split("\n")) {
    if (line === "") {
      flush();
    } else if (!line.startsWith(":")) {
      const separator = line.indexOf(":");
      const field = separator < 0 ? line : line.slice(0, separator);
      const value = separator < 0 ? "" : line.slice(separator + 1).replace(/^ /, "");
      if (field === "event") event = value;
      else if (field === "data") data.push(value);
      else if (field === "id") id = value;
    }
  }
  flush();
  return frames;
}

export function normalizeResponse({ status, headers, json, sse }) {
  return {
    status,
    headers: normalizeHeaders(headers),
    body: sse === undefined ? normalizeJson(json) : normalizeSse(sse),
  };
}
