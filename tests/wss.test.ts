import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";
const exec = promisify(execFile);
it("executes production WSS URL, upgrade, frame and stream implementation on Java", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "crossgram-wss-"));
  const source = "features/server-switch/files/java/org/telegram/messenger/server_switch";
  try {
    await exec("javac", ["-d", dir, ...["WssUrl", "WssWire", "WssTls"].map(n => `${source}/${n}.java`), "tests/fixtures/wss/WssHarness.java"]);
    const result = await exec("java", ["-cp", dir, "WssHarness"]);
    expect(result.stdout).toContain("checks passed");
  } finally { await rm(dir, { recursive: true, force: true }); }
});
it("executes the production native account binding gate", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "crossgram-wss-binding-"));
  try {
    await exec("g++", ["-std=c++17", "-Ifeatures/server-switch/files/native", "tests/fixtures/wss/binding.cpp", "-o", `${dir}/binding`]);
    await exec(`${dir}/binding`, []);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
