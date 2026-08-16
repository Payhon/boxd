export function requireBoxdEnvironment() {
  const apiKey = process.env.UPSTASH_BOX_API_KEY;
  const baseUrl = process.env.UPSTASH_BOX_BASE_URL;
  if (!apiKey) {
    throw new Error("UPSTASH_BOX_API_KEY is required");
  }
  if (!baseUrl) {
    throw new Error(
      "UPSTASH_BOX_BASE_URL is required; set it explicitly so an example cannot accidentally use another service",
    );
  }
  const parsed = new URL(baseUrl);
  if (!new Set(["http:", "https:"]).has(parsed.protocol)) {
    throw new Error("UPSTASH_BOX_BASE_URL must be an HTTP(S) origin");
  }
  return { apiKey, baseUrl: baseUrl.replace(/\/$/, "") };
}

export function assertSuccessfulRun(run, label) {
  if (run.exitCode !== 0) {
    throw new Error(`${label} failed with exit ${run.exitCode}: ${run.stderr || run.stdout}`);
  }
}

export async function deleteBoxQuietly(box) {
  if (!box) return;
  try {
    await box.delete();
  } catch (error) {
    console.error(`cleanup failed for box ${box.id}:`, error);
  }
}

export const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
