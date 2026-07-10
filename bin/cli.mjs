#!/usr/bin/env node

import { cpSync, existsSync, mkdirSync, renameSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const skillName = "building-website-mcps";
const bundledSkill = join(packageRoot, skillName);

function fail(message) {
  process.stderr.write(`Error: ${message}\n`);
  process.exitCode = 1;
}

function usage() {
  return `Usage:
  building-website-mcps path
  building-website-mcps install [--target codex|claude] [--dest <skills-dir>] [--force]

Installs the bundled ${skillName} skill. Codex is the default target.`;
}

function parseInstallArgs(args) {
  const options = { target: "codex", destination: null, force: false };

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--target") {
      options.target = args[++index];
    } else if (argument === "--dest") {
      options.destination = args[++index];
    } else if (argument === "--force") {
      options.force = true;
    } else {
      throw new Error(`unknown option ${argument}`);
    }
    if ((argument === "--target" || argument === "--dest") && !args[index]) {
      throw new Error(`${argument} requires a value`);
    }
  }

  if (!["codex", "claude"].includes(options.target)) {
    throw new Error("--target must be codex or claude");
  }
  return options;
}

function defaultSkillsDirectory(target) {
  if (target === "codex") {
    return join(process.env.CODEX_HOME || join(homedir(), ".codex"), "skills");
  }
  return join(homedir(), ".claude", "skills");
}

function install(options) {
  if (!existsSync(bundledSkill)) {
    throw new Error("bundled skill directory is missing");
  }

  const skillsDirectory = resolve(options.destination || defaultSkillsDirectory(options.target));
  const destination = join(skillsDirectory, skillName);
  if (existsSync(destination) && !options.force) {
    throw new Error(`${destination} already exists; pass --force to replace it`);
  }

  mkdirSync(skillsDirectory, { recursive: true });
  const temporary = `${destination}.tmp-${process.pid}-${Date.now()}`;
  rmSync(temporary, { recursive: true, force: true });
  cpSync(bundledSkill, temporary, { recursive: true });
  if (existsSync(destination)) {
    rmSync(destination, { recursive: true, force: true });
  }
  renameSync(temporary, destination);

  const targetLabel = options.target === "claude" ? "Claude Code" : "Codex";
  process.stdout.write(`Installed ${skillName} for ${targetLabel} at ${destination}\n`);
}

const [command = "help", ...args] = process.argv.slice(2);
try {
  if (command === "path") {
    process.stdout.write(`${bundledSkill}\n`);
  } else if (command === "install") {
    install(parseInstallArgs(args));
  } else if (command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(`${usage()}\n`);
  } else {
    throw new Error(`unknown command ${command}`);
  }
} catch (error) {
  fail(error.message);
}
