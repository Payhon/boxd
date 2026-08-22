#!/usr/bin/env node
// Bootstrap and revoke the short-lived compatibility key for a fresh Phase 4
// SQLite database. Plaintext credentials never go to stdout or evidence.
import { open, readFile, unlink } from "node:fs/promises";
import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

const requiredEnv = ["BOXD_BASE_URL", "BOXD_ADMIN_USER", "BOXD_ADMIN_PASSWORD"];
// AuthScope::Admin is intentionally rejected by the compatibility authenticator;
// these are the minimum scopes needed by the load matrix.
export const LOAD_SCOPES = ["boxes_read", "boxes_write", "runs_write"];

export function baseUrl() {
  const value = process.env.BOXD_BASE_URL;
  if (!value) throw new Error("BOXD_BASE_URL is required");
  const match = value.match(/^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})\/?$/);
  if (!match || Number(match[1]) < 1 || Number(match[1]) > 65_535) {
    throw new Error("BOXD_BASE_URL must include an explicit loopback port without query or fragment");
  }
  const url = new URL(value);
  if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) || url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    throw new Error("BOXD_BASE_URL must be a credential-free loopback HTTP origin");
  }
  return url;
}

function requireCredentials() {
  const missing = requiredEnv.filter((key) => !process.env[key]);
  if (missing.length) throw new Error(`missing bootstrap environment: ${missing.join(", ")}`);
}

async function jsonRequest(url, init, label) {
  const response = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(10_000) });
  let body;
  try { body = await response.json(); } catch { throw new Error(`${label} returned non-JSON HTTP ${response.status}`); }
  if (!response.ok) throw new Error(`${label} failed with HTTP ${response.status}`);
  return { response, body };
}

async function login() {
  const { response, body } = await jsonRequest(new URL("/api/admin/v1/auth/login", baseUrl()), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: process.env.BOXD_ADMIN_USER, password: process.env.BOXD_ADMIN_PASSWORD }),
  }, "admin login");
  const setCookie = response.headers.get("set-cookie") ?? "";
  const cookie = setCookie.split(";", 1)[0];
  if (!/^boxd_session=\S+$/.test(cookie) || !/HttpOnly/i.test(setCookie) || typeof body.csrf_token !== "string" || body.csrf_token.length < 16) {
    throw new Error("admin session contract mismatch");
  }
  return { cookie, csrf: body.csrf_token };
}

async function adminRequest(session, path, init = {}, label = "admin request") {
  return jsonRequest(new URL(`/api/admin/v1${path}`, baseUrl()), {
    ...init,
    headers: {
      cookie: session.cookie,
      "x-csrf-token": session.csrf,
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...(init.headers ?? {}),
    },
  }, label);
}

export async function safeOutputPath(value, { mustExist = false } = {}) {
  if (!value || !isAbsolute(value)) throw new Error("BOXD_API_KEY_FILE must be an absolute path");
  if (!process.env.RUNNER_TEMP) throw new Error("RUNNER_TEMP is required");
  const root = resolve(process.env.RUNNER_TEMP);
  const path = resolve(value);
  const rootInfo = await lstat(root).catch(() => { throw new Error("RUNNER_TEMP must be an existing directory"); });
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error("RUNNER_TEMP must be a real directory");
  const rootReal = await realpath(root);
  const child = relative(root, path);
  if (!child || child === ".." || child.startsWith(`..${sep}`) || isAbsolute(child)) throw new Error("BOXD_API_KEY_FILE must be below RUNNER_TEMP");
  let cursor = root;
  const parts = child.split(sep);
  for (const part of parts.slice(0, -1)) {
    cursor = resolve(cursor, part);
    const info = await lstat(cursor).catch(() => { throw new Error("BOXD_API_KEY_FILE parent must exist"); });
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error("BOXD_API_KEY_FILE parent must be a real directory");
  }
  const parent = resolve(path, "..");
  const parentInfo = await lstat(parent).catch(() => { throw new Error("BOXD_API_KEY_FILE parent must exist"); });
  if (parentInfo.isSymbolicLink() || !parentInfo.isDirectory()) throw new Error("BOXD_API_KEY_FILE parent must be a real directory");
  const parentReal = await realpath(parent);
  const parentRelative = relative(rootReal, parentReal);
  if (parentRelative === ".." || parentRelative.startsWith(`..${sep}`) || isAbsolute(parentRelative)) throw new Error("BOXD_API_KEY_FILE parent escaped RUNNER_TEMP");
  const existing = await lstat(path).catch(() => undefined);
  if (existing) {
    if (!mustExist) throw new Error("BOXD_API_KEY_FILE must not already exist");
    if (existing.isSymbolicLink() || !existing.isFile() || existing.nlink !== 1) throw new Error("BOXD_API_KEY_FILE must be a unique regular file");
  } else if (mustExist) {
    throw new Error("BOXD_API_KEY_FILE does not exist");
  }
  return path;
}

async function writeRecord(path, record) {
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(JSON.stringify(record) + "\n", { encoding: "utf8" });
    await handle.chmod(0o600);
  } finally {
    await handle.close();
  }
}

export async function bootstrapApiKey(outputPath) {
  requireCredentials();
  const path = await safeOutputPath(outputPath);
  const session = await login();
  const { body } = await adminRequest(session, "/api-keys", {
    method: "POST",
    body: JSON.stringify({ scopes: LOAD_SCOPES, expires_at: Date.now() + 2 * 60 * 60 * 1000 }),
  }, "admin API key creation");
  const validId = typeof body.id === "string" && /^[0-9a-f-]{36}$/.test(body.id);
  const validBody = validId && LOAD_SCOPES.every((scope) => body.scopes?.includes(scope)) && !body.scopes?.includes("admin") && typeof body.api_key === "string" && /^boxd_compat_[A-Za-z0-9_-]+$/.test(body.api_key);
  if (!validBody) {
    if (validId) await adminRequest(session, `/api-keys/${body.id}`, { method: "DELETE" }, "admin API key rollback").catch(() => {});
    throw new Error("admin API key creation contract mismatch");
  }
  try {
    await writeRecord(path, { id: body.id, api_key: body.api_key });
  } catch (error) {
    await adminRequest(session, `/api-keys/${body.id}`, { method: "DELETE" }, "admin API key rollback").catch(() => {});
    throw error;
  }
  return path;
}

export async function revokeApiKey(inputPath) {
  requireCredentials();
  const path = await safeOutputPath(inputPath, { mustExist: true });
  let record;
  try {
    record = JSON.parse(await readFile(path, "utf8"));
    if (!record || typeof record.id !== "string" || !/^[0-9a-f-]{36}$/.test(record.id)) throw new Error("API key record is invalid");
    const session = await login();
    await adminRequest(session, `/api-keys/${record.id}`, { method: "DELETE" }, "admin API key revocation");
  } finally {
    await unlink(path).catch(() => {});
  }
}

async function main() {
  const mode = process.argv[2];
  if (mode === "create" && process.argv[3]) await bootstrapApiKey(process.argv[3]);
  else if (mode === "revoke" && process.argv[3]) await revokeApiKey(process.argv[3]);
  else throw new Error("usage: phase4-bootstrap-api-key.mjs create|revoke /absolute/RUNNER_TEMP/key.json");
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)) {
  main().catch((error) => { process.stderr.write(`phase4 API-key bootstrap failed: ${error.message}\n`); process.exitCode = 1; });
}
