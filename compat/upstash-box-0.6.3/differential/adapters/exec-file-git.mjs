import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { consume, withBox } from "./common.mjs";

const command = withBox(({ box }) => box.exec.command("printf phase4-exec"));
const stream = withBox(async ({ box }) => consume(await box.exec.stream("printf phase4-stream")));
const code = withBox(({ box }) => box.exec.code({ code: "1 + 1", lang: "javascript" }));
const codeStream = withBox(async ({ box }) => consume(await box.exec.streamCode({ code: "1 + 1", lang: "javascript" })));
const cd = withBox(async ({ box }) => {
  await box.exec.command("mkdir -p phase4-cd");
  return box.cd("phase4-cd");
});

const fileWrite = withBox(async ({ box }) => {
  await box.files.write({ path: "phase4/fixture.txt", content: "phase4-file" });
});
const fileRead = withBox(async ({ box }) => {
  await box.files.write({ path: "phase4/read.txt", content: "phase4-read" });
  return box.files.read("phase4/read.txt");
});
const fileList = withBox(async ({ box }) => {
  await box.files.write({ path: "phase4/list.txt", content: "phase4-list" });
  return box.files.list("phase4");
});
const fileUpload = withBox(async ({ box, state }) => {
  state.uploadDir = await mkdtemp(join(tmpdir(), "boxd-diff-upload-"));
  state.uploadPath = join(state.uploadDir, "fixture.txt");
  await writeFile(state.uploadPath, "phase4-upload");
  return box.files.upload([{ path: state.uploadPath, destination: "phase4/upload.txt" }]);
}, { cleanup: async (state) => {
  if (state.uploadDir) await rm(state.uploadDir, { recursive: true, force: true });
} });
let downloadChain = Promise.resolve();
const fileDownload = withBox(async ({ box, state }) => {
  state.downloadDir = await mkdtemp(join(tmpdir(), "boxd-diff-download-"));
  await box.files.write({ path: "phase4/download.txt", content: "phase4-download" });
  const run = downloadChain.then(async () => {
    const oldCwd = process.cwd();
    process.chdir(state.downloadDir);
    try {
      return await box.files.download({ folder: "phase4" });
    } finally {
      process.chdir(oldCwd);
    }
  });
  downloadChain = run.catch(() => undefined);
  return run;
}, { cleanup: async (state) => {
  if (state.downloadDir) await rm(state.downloadDir, { recursive: true, force: true });
} });

const gitExtra = ({ target }) => target.git?.token ? { git: { token: target.git.token } } : {};
const git = (operation) => withBox(async (context) => {
  const { box } = context;
  await box.exec.command("rm -rf phase4-git && mkdir -p phase4-git && git -C phase4-git init -q && git -C phase4-git config user.name boxd && git -C phase4-git config user.email boxd@example.invalid && printf phase4-baseline > phase4-git/fixture.txt && git -C phase4-git add fixture.txt && GIT_AUTHOR_DATE=2000-01-01T00:00:00Z GIT_COMMITTER_DATE=2000-01-01T00:00:00Z git -C phase4-git commit -q -m phase4-baseline && git -C phase4-git checkout -q -b phase4-differential");
  await box.cd("phase4-git");
  return operation(context);
}, { extra: gitExtra });
const gitClone = withBox(({ box, target }) => {
  const repo = target.git?.repo;
  if (!repo) throw new Error("target Git repository is required for git clone differential case");
  return box.git.clone({ repo, branch: target.git.branch, depth: 1 });
}, { extra: gitExtra });
const gitDiff = git(({ box }) => box.git.diff());
const gitStatus = git(({ box }) => box.git.status());
const gitCommit = git(async ({ box }) => {
  await box.files.write({ path: "phase4-git/fixture.txt", content: "phase4 changed" });
  await box.git.exec({ args: ["add", "fixture.txt"] });
  return box.git.commit({ message: "boxd differential fixture", authorName: "boxd", authorEmail: "boxd@example.invalid" });
});
const gitConfig = git(({ box }) => box.git.updateConfig({ userName: "boxd", userEmail: "boxd@example.invalid" }));
const gitPush = withBox(async ({ box, target }) => {
  if (!target.git?.repo) throw new Error("target Git repository is required for git push differential case");
  await box.git.clone({ repo: target.git.repo, branch: target.git.branch, depth: 1 });
  return box.git.push({ branch: target.git.branch });
}, { extra: gitExtra });
function githubSlug(repo) {
  const match = /^(?:https:\/\/github\.com\/|git@github\.com:)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)$/.exec((repo ?? "").replace(/\.git$/, ""));
  if (!match) throw new Error("git create-pr cleanup requires an explicit GitHub owner/repository fixture");
  return match[1];
}
const gitPr = withBox(async ({ box, target, state }) => {
  if (!target.git?.repo || !target.git.branch) throw new Error("target Git repository and branch are required for git create-pr differential case");
  state.gitHubSlug = githubSlug(target.git.repo);
  await box.git.clone({ repo: target.git.repo, branch: target.git.branch, depth: 1 });
  state.pullRequest = await box.git.createPR({ title: "boxd differential fixture", body: "boxd differential fixture", base: target.git.baseBranch ?? "main" });
  return state.pullRequest;
}, {
  extra: gitExtra,
  cleanup: async (state, { target }) => {
    if (!state.pullRequest?.number) return;
    const response = await fetch(`https://api.github.com/repos/${state.gitHubSlug}/pulls/${state.pullRequest.number}`, {
      method: "PATCH",
      headers: { accept: "application/vnd.github+json", authorization: `Bearer ${target.git.token}`, "content-type": "application/json", "user-agent": "boxd-phase4-differential" },
      body: JSON.stringify({ state: "closed" }),
    });
    if (!response.ok) throw new Error("GitHub pull request cleanup failed");
  },
});
const gitExec = git(({ box }) => box.git.exec({ args: ["status", "--short"] }));
const gitCheckout = git(({ box }) => box.git.checkout({ branch: "phase4-differential" }));

export const execFileGitAdapters = new Map([
  ["POST /v2/box/{box_id}/exec", command],
  ["POST /v2/box/{box_id}/exec-stream", stream],
  ["POST /v2/box/{box_id}/code", code],
  ["POST /v2/box/{box_id}/code-stream", codeStream],
  ["POST /v2/box/{box_id}/exec#cd", cd],
  ["GET /v2/box/{box_id}/files/read", fileRead],
  ["POST /v2/box/{box_id}/files/write", fileWrite],
  ["GET /v2/box/{box_id}/files/list", fileList],
  ["POST /v2/box/{box_id}/files/upload", fileUpload],
  ["GET /v2/box/{box_id}/files/download", fileDownload],
  ["POST /v2/box/{box_id}/git/clone", gitClone],
  ["GET /v2/box/{box_id}/git/diff", gitDiff],
  ["GET /v2/box/{box_id}/git/status", gitStatus],
  ["POST /v2/box/{box_id}/git/commit", gitCommit],
  ["PUT /v2/box/{box_id}/git-config", gitConfig],
  ["POST /v2/box/{box_id}/git/push", gitPush],
  ["POST /v2/box/{box_id}/git/create-pr", gitPr],
  ["POST /v2/box/{box_id}/git/exec", gitExec],
  ["POST /v2/box/{box_id}/git/checkout", gitCheckout],
]);
