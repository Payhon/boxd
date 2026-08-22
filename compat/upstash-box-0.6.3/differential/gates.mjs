const SECRET_KEY = /(?:api[_-]?key|authorization|cookie|credential|password|secret|token)/i;

export function redactEvidence(value, key = "") {
  if (SECRET_KEY.test(key)) return "<redacted>";
  if (Array.isArray(value)) return value.map((item) => redactEvidence(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactEvidence(item, name)]));
  }
  return value;
}

export function redactUrl(value) {
  const url = new URL(value);
  url.username = "";
  url.password = "";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

function validUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

export function differentialConfig(env = process.env) {
  const number = (name, fallback) => {
    const value = Number(env[name] ?? fallback);
    return Number.isFinite(value) && value > 0 ? value : fallback;
  };
  const budget = env.BOXD_DIFF_BUDGET_USD === undefined ? null : Number(env.BOXD_DIFF_BUDGET_USD);
  const baseUrl = (value) => value?.replace(/\/+$/, "");
  return {
    official: {
      baseUrl: baseUrl(env.BOXD_DIFF_OFFICIAL_BASE_URL),
      apiKey: env.BOXD_DIFF_OFFICIAL_API_KEY,
      prefix: env.BOXD_DIFF_OFFICIAL_PREFIX,
    },
    local: {
      baseUrl: baseUrl(env.BOXD_DIFF_LOCAL_BASE_URL),
      apiKey: env.BOXD_DIFF_LOCAL_API_KEY,
      prefix: env.BOXD_DIFF_LOCAL_PREFIX,
    },
    runtime: env.BOXD_DIFF_RUNTIME,
    providerApiKey: env.BOXD_DIFF_PROVIDER_API_KEY,
    externalOptIn: env.BOXD_DIFF_EXTERNALLY_MUTATING_OPT_IN === "1",
    costOptIn: env.BOXD_DIFF_COST_OPT_IN === "1",
    budgetUsd: Number.isFinite(budget) && budget >= 0 ? budget : null,
    requestTimeoutMs: Math.trunc(number("BOXD_DIFF_REQUEST_TIMEOUT_MS", 30_000)),
    globalTimeoutMs: Math.trunc(number("BOXD_DIFF_GLOBAL_TIMEOUT_MS", 900_000)),
    concurrency: Math.min(8, Math.trunc(number("BOXD_DIFF_CONCURRENCY", 1))),
  };
}

export function evaluateDifferentialGates(cases, config) {
  const blockers = [];
  if (!config.official.apiKey || !config.local.apiKey || config.official.apiKey === config.local.apiKey) {
    blockers.push({ gate: "credential", reason: "distinct BOXD_DIFF_OFFICIAL_API_KEY and BOXD_DIFF_LOCAL_API_KEY are required" });
  }
  if (!validUrl(config.official.baseUrl) || !validUrl(config.local.baseUrl) || config.official.baseUrl === config.local.baseUrl) {
    blockers.push({ gate: "base_url", reason: "distinct explicit HTTP(S) official and local base URLs are required" });
  }
  if (!/^[A-Za-z][A-Za-z0-9_-]{2,31}$/.test(config.official.prefix ?? "") || !/^[A-Za-z][A-Za-z0-9_-]{2,31}$/.test(config.local.prefix ?? "") || config.official.prefix === config.local.prefix) {
    blockers.push({ gate: "resource_prefix", reason: "distinct safe official and local resource prefixes are required" });
  }
  if (cases.some((item) => item.setup === "Box.create" || /POST \/v2\/box(?:#|$|\/from-snapshot)/.test(item.case_id)) && !config.runtime) {
    blockers.push({ gate: "runtime", reason: "selected cases require BOXD_DIFF_RUNTIME" });
  }
  if (cases.some((item) => /\/run|#agent|config\/model|custom-runner/.test(item.case_id)) && !config.providerApiKey) {
    blockers.push({ gate: "provider", reason: "selected cases require BOXD_DIFF_PROVIDER_API_KEY" });
  }
  if (cases.some((item) => item.risk.classification === "externally_mutating") && !config.externalOptIn) {
    blockers.push({ gate: "externally_mutating_opt_in", reason: "set BOXD_DIFF_EXTERNALLY_MUTATING_OPT_IN=1" });
  }
  const costCases = cases.filter((item) => item.risk.classification === "cost_incurring");
  if (costCases.length > 0 && !config.costOptIn) {
    blockers.push({ gate: "cost_opt_in", reason: "set BOXD_DIFF_COST_OPT_IN=1" });
  }
  const estimatedCost = costCases.length * 0.05;
  if (costCases.length > 0 && (config.budgetUsd === null || config.budgetUsd < estimatedCost)) {
    blockers.push({ gate: "budget", reason: `budget must be at least ${estimatedCost.toFixed(2)} USD for selected cases` });
  }
  return { allowed: blockers.length === 0, blockers };
}
