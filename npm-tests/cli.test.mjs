import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "bin", "cli.mjs");

function run(args, options = {}) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: "utf8",
    ...options,
    env: { ...process.env, ...options.env },
  });
}

test("path reports the bundled Codex skill directory", () => {
  const result = run(["path"]);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(resolve(result.stdout.trim()), join(root, "building-website-mcps"));
});

test("install copies the skill to an explicit empty destination", () => {
  const temporary = mkdtempSync(join(tmpdir(), "building-website-mcps-npm-"));
  const destination = join(temporary, "skills");

  try {
    const result = run(["install", "--dest", destination]);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Installed building-website-mcps/);
    const installed = join(destination, "building-website-mcps", "SKILL.md");
    assert.equal(run(["path"]).status, 0);
    assert.equal(Boolean(spawnSync("test", ["-f", installed]).status === 0), true);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("install refuses to overwrite an existing skill without force", () => {
  const temporary = mkdtempSync(join(tmpdir(), "building-website-mcps-npm-"));
  const destination = join(temporary, "skills");

  try {
    assert.equal(run(["install", "--dest", destination]).status, 0);
    const result = run(["install", "--dest", destination]);

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /already exists/);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("install targets Claude Code's personal skills directory", () => {
  const home = mkdtempSync(join(tmpdir(), "building-website-mcps-claude-"));

  try {
    const result = run(["install", "--target", "claude"], { env: { HOME: home } });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Claude Code/);
    const installed = join(home, ".claude", "skills", "building-website-mcps", "SKILL.md");
    assert.equal(Boolean(spawnSync("test", ["-f", installed]).status === 0), true);
    assert.match(readFileSync(installed, "utf8"), /^---\nname: building-website-mcps\n/m);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
