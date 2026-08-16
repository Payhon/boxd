import { Box } from "@upstash/box";
import { assertSuccessfulRun, deleteBoxQuietly, requireBoxdEnvironment } from "./_common.mjs";

requireBoxdEnvironment();

let box;
try {
  box = await Box.create({
    runtime: "node",
    size: "small",
    name: "example-lifecycle",
    labels: ["example", "lifecycle"],
    env: { BOXD_EXAMPLE_MESSAGE: "hello-from-boxd" },
    networkPolicy: { mode: "deny-all" },
    timeout: 300_000,
  });
  console.log("created box:", box.id);

  const command = await box.exec.command(
    "printf '%s\\n' \"$BOXD_EXAMPLE_MESSAGE\" && node --version && pwd",
  );
  assertSuccessfulRun(command, "command");
  console.log(command.stdout.trim());

  const code = await box.exec.code({
    language: "javascript",
    code: "console.log(JSON.stringify({ answer: 6 * 7 }))",
  });
  assertSuccessfulRun(code, "JavaScript code");
  console.log("code output:", code.stdout.trim());

  await box.files.write({ path: "hello.txt", content: "hello from @upstash/box\n" });
  console.log("file:", (await box.files.read("hello.txt")).trim());
  console.log("entries:", await box.files.list());

  await box.labels.add("verified");
  console.log("labels:", await box.labels.list());

  await box.pause();
  console.log("box paused");
  await box.resume();
  console.log("box resumed");

  const afterResume = await box.exec.command("cat hello.txt");
  assertSuccessfulRun(afterResume, "post-resume command");
  console.log("persisted after resume:", afterResume.stdout.trim());
} finally {
  await deleteBoxQuietly(box);
}
