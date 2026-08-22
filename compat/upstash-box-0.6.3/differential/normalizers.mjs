const DEFAULT_VOLATILE_KEYS = new Set([
  "box_id",
  "agent_id",
  "created_at",
  "completed_at",
  "customer_id",
  "expires_at",
  "finished_at",
  "id",
  "input_tokens",
  "output_tokens",
  "cached_input_tokens",
  "total_cost_usd",
  "cost_usd",
  "duration_ms",
  "ended_at",
  "compute_ms",
  "cpu_ns",
  "memory_peak_bytes",
  "mod_time",
  "number",
  "qstash_schedule_id",
  "request_id",
  "run_id",
  "session_id",
  "snapshot_id",
  "started_at",
  "timestamp",
  "last_activity_at",
  "last_run_at",
  "last_run_id",
  "total_input_tokens",
  "total_output_tokens",
  "total_prompts",
  "total_cpu_ns",
  "total_compute_cost_usd",
  "total_token_cost_usd",
  "total_usd",
  "compute_cost_usd",
  "size_bytes",
  "segment_count",
  "mp4_size_bytes",
  "at_ms",
  "end_ms",
  "tab_id",
  "updated_at",
]);

const DEFAULT_SECRET_KEYS = /(?:api[_-]?key|authorization|cookie|credential|password|secret|token)/i;

export function normalizeJson(value, options = {}) {
  const volatileKeys = new Set(options.volatileKeys ?? DEFAULT_VOLATILE_KEYS);
  const secretKeys = options.secretKeys ?? DEFAULT_SECRET_KEYS;
  const visit = (item, key = "") => {
    if (secretKeys.test(key)) return "<redacted>";
    if (volatileKeys.has(key)) return `<${key}>`;
    if (typeof item === "string" && /^(?:url|[a-z0-9]+_url)$/i.test(key)) {
      try {
        new URL(item);
        return "<url>";
      } catch {
        return item;
      }
    }
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

export function normalizeBinary(input, contentType = "") {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const type = contentType.split(";", 1)[0].trim().toLowerCase();
  let format = "opaque";
  if (type === "video/mp4" && bytes.length >= 8 && new TextDecoder().decode(bytes.slice(4, 8)) === "ftyp") format = "mp4";
  else if (type === "video/mp2t" && bytes[0] === 0x47) format = "mpeg-ts";
  else if (type === "image/png" && bytes.length >= 8 && [137, 80, 78, 71, 13, 10, 26, 10].every((value, index) => bytes[index] === value)) format = "png";
  return { kind: "binary", format, nonempty: bytes.length > 0 };
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
