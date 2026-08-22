export function connection(target) {
  return { apiKey: target.apiKey, baseUrl: target.baseUrl };
}

export function boxConfig(target, config, options = {}) {
  return {
    ...connection(target),
    name: options.name ?? "boxd-phase4-differential",
    runtime: config.runtime,
    keepAlive: options.keepAlive ?? true,
    browser: options.browser ?? false,
    ...options.extra,
  };
}

export function managedAgent(config) {
  return {
    harness: "codex",
    model: "openai/gpt-5",
    apiKey: config.providerApiKey,
  };
}

export async function settleCleanup(steps) {
  const errors = [];
  for (const step of steps) {
    try { await step(); }
    catch (error) { errors.push(error); }
  }
  if (errors.length > 0) throw new AggregateError(errors, "one or more differential cleanup steps failed");
}

export function withBox(operation, options = {}) {
  return {
    requiresRuntime: true,
    mayIncurCost: true,
    prepare: () => ({ box: null, deleted: false, resources: {} }),
    async execute(context) {
      const { sdk, target, config, state } = context;
      state.box = await sdk.Box.create(boxConfig(target, config, {
        name: options.name,
        keepAlive: options.keepAlive,
        browser: options.browser,
        extra: typeof options.extra === "function" ? options.extra(context) : options.extra,
      }));
      return operation({ ...context, box: state.box });
    },
    async cleanup(context) {
      const { state } = context;
      await settleCleanup([
        ...(typeof options.cleanup === "function" ? [() => options.cleanup(state, context)] : []),
        ...(state.box && !state.deleted ? [() => state.box.delete()] : []),
      ]);
    },
  };
}

export async function consume(iterable) {
  for await (const _chunk of iterable) {
    // Exhaust the pinned SDK stream so its wire contract is captured.
  }
}
