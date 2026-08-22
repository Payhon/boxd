import { boxConfig, connection, managedAgent, settleCleanup, withBox } from "./common.mjs";

const lifecycleAdapters = new Map();

const managed = (caseId, operation, options = {}) => lifecycleAdapters.set(caseId, withBox(operation, options));

managed("GET /v2/box/{box_id}", ({ sdk, target, box }) => sdk.Box.get(box.id, connection(target)));
managed("DELETE /v2/box/{box_id}", async ({ box, state }) => { await box.delete(); state.deleted = true; });
managed("DELETE /v2/box", async ({ sdk, target, box, state }) => { await sdk.Box.delete({ ...connection(target), boxIds: [box.id] }); state.deleted = true; });
managed("GET /v2/box/{box_id}/status", ({ box }) => box.getStatus());
managed("POST /v2/box/{box_id}/pause", ({ box }) => box.pause(), { keepAlive: false });
managed("POST /v2/box/{box_id}/resume", async ({ box }) => { await box.pause(); return box.resume(); }, { keepAlive: false });
managed("GET /v2/box/{box_id}/startup", ({ box }) => box.getInitCommand(), { keepAlive: true });
managed("PUT /v2/box/{box_id}/startup", ({ box }) => box.setInitCommand("echo boxd-differential-init"), { keepAlive: true });
managed("DELETE /v2/box/{box_id}/startup", async ({ box }) => { await box.setInitCommand("echo boxd-differential-init"); return box.deleteInitCommand(); }, { keepAlive: true });
managed("PUT /v2/box/{box_id}/config/model", ({ box }) => box.configureModel("openai/gpt-5"));
managed(
  "PUT /v2/box/{box_id}/config/custom-runner",
  ({ box }) => box.configureCustomHarness({ command: "runner" }),
  { extra: { agent: { harness: "custom", model: "custom", customHarness: { command: "runner" } } } },
);
managed("PUT /v2/box/{box_id}/config/network-policy", ({ box }) => box.updateNetworkPolicy({}));

const env = (caseId, execute, options = {}) => lifecycleAdapters.set(caseId, {
  ...options,
  prepare: ({ target }) => ({ key: `${target.prefix}_DIFF_ENV_ALL`, value: "boxd-differential-value", deleted: false }),
  execute,
  cleanup: async ({ sdk, target, state }) => {
    if (!state.deleted) await sdk.Box.deleteEnv(state.key, connection(target));
  },
});
env("PUT /v2/box/settings/env", ({ sdk, target, state }) => sdk.Box.setAllEnv({ [state.key]: state.value }, connection(target)), { dedicatedAccount: true });
env("DELETE /v2/box/settings/env/{key}", async ({ sdk, target, state }) => {
  await sdk.Box.setEnv(state.key, state.value, connection(target));
  await sdk.Box.deleteEnv(state.key, connection(target));
  state.deleted = true;
});

const snapshot = (caseId, execute) => lifecycleAdapters.set(caseId, {
  prepare: () => ({ box: null, snapshot: null, restored: null, deleted: false, resources: {} }),
  async execute(context) {
    const { sdk, target, config, state } = context;
    state.box = await sdk.Box.create(boxConfig(target, config, { name: "boxd-differential-snapshot", keepAlive: true }));
    state.resources.sourceBox = state.box;
    state.snapshot = await state.box.snapshot({ name: "boxd-differential-snapshot" });
    state.resources.snapshot = state.snapshot;
    const result = await execute({ ...context, box: state.box, snapshot: state.snapshot });
    if (result && typeof result.delete === "function") {
      state.restored = result;
      state.resources.restoredBox = result;
    }
    return result;
  },
  async cleanup({ state }) {
    await settleCleanup([
      ...(state.restored && typeof state.restored.delete === "function" ? [() => state.restored.delete()] : []),
      ...(state.box && typeof state.box.deleteSnapshot === "function" && state.snapshotTarget?.id ? [() => state.box.deleteSnapshot(state.snapshotTarget.id)] : []),
      ...(state.box && typeof state.box.deleteSnapshot === "function" && state.snapshot?.id && !state.snapshotDeleted ? [() => state.box.deleteSnapshot(state.snapshot.id)] : []),
      ...(state.box && !state.deleted ? [() => state.box.delete()] : []),
    ]);
  },
});
snapshot("POST /v2/box/{box_id}/snapshots", async ({ box, state }) => { state.snapshotTarget = await box.snapshot({ name: "boxd-differential-snapshot-target" }); return state.snapshotTarget; });
snapshot("GET /v2/box/{box_id}/snapshots", ({ box }) => box.listSnapshots());
snapshot("DELETE /v2/box/{box_id}/snapshots/{snapshot_id}", async ({ box, snapshot, state }) => { await box.deleteSnapshot(snapshot.id); state.snapshotDeleted = true; });
lifecycleAdapters.set("DELETE /v2/box/snapshots", {
  requiresRuntime: true,
  mayIncurCost: true,
  prepare: () => ({ box: null, snapshot: null, deleted: false, resources: {} }),
  async execute({ sdk, target, config, state }) {
    state.box = await sdk.Box.create(boxConfig(target, config, { name: "boxd-differential-snapshot-delete", keepAlive: true }));
    state.snapshot = await state.box.snapshot({ name: "boxd-differential-snapshot-delete" });
    state.resources = { sourceBox: state.box, snapshot: state.snapshot };
    return sdk.Box.deleteSnapshots({ ...connection(target), snapshotIds: state.snapshot.id });
  },
  async cleanup({ sdk, target, state }) {
    await settleCleanup([
      ...(state.box?.delete && state.snapshot?.id ? [() => sdk.Box.deleteSnapshots({ ...connection(target), snapshotIds: state.snapshot.id })] : []),
      ...(state.box && !state.deleted ? [() => state.box.delete()] : []),
    ]);
  },
});

const fromSnapshot = (caseId, factory) => lifecycleAdapters.set(caseId, {
  prepare: () => ({ source: null, snapshot: null, restored: null, deleted: false, resources: {} }),
  async execute(context) {
    const { sdk, target, config, state } = context;
    state.source = await sdk.Box.create(boxConfig(target, config, { name: "boxd-differential-from-snapshot", keepAlive: true }));
    state.resources.sourceBox = state.source;
    state.snapshot = await state.source.snapshot({ name: "boxd-differential-from-snapshot" });
    state.resources.snapshot = state.snapshot;
    state.restored = await factory({ sdk, target, config, state, snapshot: state.snapshot });
    state.resources.restoredBox = state.restored;
    return state.restored;
  },
  async cleanup({ state }) {
    await settleCleanup([
      ...(state.restored?.delete ? [() => state.restored.delete()] : []),
      ...(state.source?.deleteSnapshot && state.snapshot?.id ? [() => state.source.deleteSnapshot(state.snapshot.id)] : []),
      ...(state.source && !state.deleted ? [() => state.source.delete()] : []),
    ]);
  },
});
fromSnapshot("POST /v2/box/from-snapshot", ({ sdk, target, config, snapshot }) => sdk.Box.fromSnapshot(snapshot.id, boxConfig(target, config, { name: "boxd-differential-restored", keepAlive: true })));
fromSnapshot("POST /v2/box/from-snapshot#ephemeral", ({ sdk, target, config, snapshot }) => sdk.EphemeralBox.fromSnapshot(snapshot.id, { ...connection(target), ttl: 60 }));

lifecycleAdapters.set("POST /v2/box#ephemeral", {
  prepare: () => ({ box: null, deleted: false, resources: {} }),
  async execute({ sdk, target, state }) {
    state.box = await sdk.EphemeralBox.create({ ...connection(target), ttl: 60 });
    state.resources.ephemeralBox = state.box;
    return state.box;
  },
  async cleanup({ state }) { if (state.box && !state.deleted) await state.box.delete(); },
});

managed("POST /v2/box/{box_id}/config/skills", async ({ box, state }) => { await box.skills.add("owner/repo/skill"); state.resources.skill = "owner/repo/skill"; }, { cleanup: async (state) => { if (state.resources.skill) await state.box.skills.remove(state.resources.skill); } });
managed("DELETE /v2/box/{box_id}/config/skills/{skill_id+}", async ({ box }) => {
  await box.skills.add("owner/repo/skill");
  return box.skills.remove("owner/repo/skill");
});
managed("GET /v2/box/{box_id}#skills", ({ box }) => box.skills.list());
managed("POST /v2/box/{box_id}/config/labels", async ({ box, state }) => { await box.labels.add("boxd-differential-label"); state.resources.label = "boxd-differential-label"; }, { cleanup: async (state) => { if (state.resources.label) await state.box.labels.remove(state.resources.label); } });
managed("DELETE /v2/box/{box_id}/config/labels/{label}", async ({ box }) => {
  await box.labels.add("boxd-differential-label");
  return box.labels.remove("boxd-differential-label");
});
managed("GET /v2/box/{box_id}#labels", ({ box }) => box.labels.list());

managed("POST /v2/box/{box_id}/schedules#exec", async ({ box, state }) => { state.resources.schedule = await box.schedule.exec({ cron: "* * * * *", command: "echo boxd" }); return state.resources.schedule; }, { cleanup: async (state) => { if (state.resources.schedule?.id) await state.box.schedule.delete(state.resources.schedule.id); } });
managed("POST /v2/box/{box_id}/schedules#agent", async ({ box, state }) => { state.resources.schedule = await box.schedule.agent({ cron: "* * * * *", prompt: "hello" }); return state.resources.schedule; }, {
  extra: ({ config }) => ({ agent: managedAgent(config) }),
  cleanup: async (state) => { if (state.resources.schedule?.id) await state.box.schedule.delete(state.resources.schedule.id); },
});
managed("GET /v2/box/{box_id}/schedules", ({ box }) => box.schedule.list());
const withSchedule = (method) => async ({ box, state }) => {
  state.resources.schedule = await box.schedule.exec({ cron: "* * * * *", command: "echo boxd" });
  return method(box, state.resources.schedule.id);
};
const scheduleCleanup = { cleanup: async (state) => { if (state.resources.schedule?.id) await state.box.schedule.delete(state.resources.schedule.id); } };
managed("GET /v2/box/{box_id}/schedules/{id}", withSchedule((box, id) => box.schedule.get(id)), scheduleCleanup);
managed("PATCH /v2/box/{box_id}/schedules/{id}", withSchedule((box, id) => box.schedule.update(id, { cron: "*/2 * * * *" })), scheduleCleanup);
managed("POST /v2/box/{box_id}/schedules/{id}/pause", withSchedule((box, id) => box.schedule.pause(id)), scheduleCleanup);
managed("POST /v2/box/{box_id}/schedules/{id}/resume", withSchedule((box, id) => box.schedule.resume(id)), scheduleCleanup);
managed("DELETE /v2/box/{box_id}/schedules/{id}", async ({ box }) => {
  const schedule = await box.schedule.exec({ cron: "* * * * *", command: "echo boxd" });
  return box.schedule.delete(schedule.id);
});

managed("POST /v2/box/{box_id}/preview", async ({ box, state }) => { state.resources.preview = await box.getPublicURL(3000); return state.resources.preview; }, { cleanup: async (state) => { if (state.resources.preview) await state.box.deletePublicURL(3000); } });
managed("GET /v2/box/{box_id}/preview", ({ box }) => box.listPublicURLs());
managed("DELETE /v2/box/{box_id}/preview/{port}", async ({ box, state }) => {
  state.resources.preview = await box.getPublicURL(3000);
  return box.deletePublicURL(3000);
});

export { lifecycleAdapters };
