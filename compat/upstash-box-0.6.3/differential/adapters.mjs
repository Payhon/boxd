export const differentialAdapters = new Map([
  [
    "GET /v2/box",
    {
      prepare: () => null,
      execute: ({ sdk, target }) => sdk.Box.list({ apiKey: target.apiKey, baseUrl: target.baseUrl }),
    },
  ],
  [
    "GET /v2/box/settings/env",
    {
      prepare: () => null,
      execute: ({ sdk, target }) => sdk.Box.listEnv({ apiKey: target.apiKey, baseUrl: target.baseUrl }),
    },
  ],
  [
    "PUT /v2/box/settings/env/{key}",
    {
      prepare: ({ target }) => ({ key: `${target.prefix}_DIFF_ENV`, value: "boxd-differential-value" }),
      execute: ({ sdk, target, state }) => sdk.Box.setEnv(state.key, state.value, { apiKey: target.apiKey, baseUrl: target.baseUrl }),
      cleanup: ({ sdk, target, state }) => sdk.Box.deleteEnv(state.key, { apiKey: target.apiKey, baseUrl: target.baseUrl }),
    },
  ],
]);

export function adapterCaseIds() {
  return [...differentialAdapters.keys()].sort();
}
