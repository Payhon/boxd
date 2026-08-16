import { Box } from "@upstash/box";
import { deleteBoxQuietly, requireBoxdEnvironment, sleep } from "./_common.mjs";

requireBoxdEnvironment();

let box;
let schedule;
try {
  box = await Box.create({
    runtime: "node",
    keepAlive: true,
    name: "example-schedule",
    labels: ["example", "schedule"],
    networkPolicy: { mode: "deny-all" },
    timeout: 300_000,
  });
  schedule = await box.schedule.exec({
    cron: "* * * * *",
    command: [
      "/bin/sh",
      "-c",
      "date -u +%FT%TZ > /workspace/home/schedule-fired.txt",
    ],
  });
  console.log("created schedule:", schedule.id, schedule.status);

  await box.schedule.pause(schedule.id);
  console.log("paused:", (await box.schedule.get(schedule.id)).status);
  await box.schedule.resume(schedule.id);
  console.log("resumed:", (await box.schedule.get(schedule.id)).status);

  const deadline = Date.now() + 90_000;
  let result;
  while (Date.now() < deadline) {
    try {
      result = await box.files.read("schedule-fired.txt");
      break;
    } catch (error) {
      if (![404, 409, 503].includes(error?.statusCode)) throw error;
      await sleep(1_000);
    }
  }
  if (!result) throw new Error("schedule did not run within 90 seconds");
  console.log("schedule output:", result.trim());
  console.log("schedule metadata:", await box.schedule.get(schedule.id));
} finally {
  if (box && schedule) await box.schedule.delete(schedule.id).catch(() => {});
  await deleteBoxQuietly(box);
}
