#!/usr/bin/env node
import {readdir, readFile, stat} from "node:fs/promises";
import {resolve, relative, sep} from "node:path";
import {auditPackage, limits} from "./audit.mjs";

const root = resolve(process.argv[2] || "");
if (!process.argv[2]) {
  console.error("Usage: node src/cli.mjs <plugin-directory> [--json]");
  process.exit(2);
}

async function collect(directory, state = {files: [], readBytes: 0}) {
  const entries = await readdir(directory, {withFileTypes: true});
  for (const entry of entries) {
    if (state.files.length > limits.maxFiles) break;
    const absolute = resolve(directory, entry.name);
    if (!absolute.startsWith(`${root}${sep}`)) throw new Error("Path escaped the selected root");
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) await collect(absolute, state);
    if (entry.isFile()) {
      const info = await stat(absolute);
      const withinBudget = info.size <= limits.maxFileBytes && state.readBytes + info.size <= limits.maxTotalBytes;
      state.files.push({
        path: relative(root, absolute).split(sep).join("/"),
        size: info.size,
        text: withinBudget ? await readFile(absolute, "utf8") : ""
      });
      if (withinBudget) state.readBytes += info.size;
    }
  }
  return state.files;
}

try {
  const report = auditPackage(await collect(root));
  if (process.argv.includes("--json")) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    console.log(`Plugin Package Inspector: ${report.verdict}`);
    console.log(`${report.scope.fileCount} files · ${report.counts.fail} blockers · ${report.counts.warn} review items`);
    for (const item of report.findings) console.log(`[${item.status.toUpperCase()}] ${item.title}: ${item.detail}`);
  }
  process.exitCode = report.counts.fail ? 1 : 0;
} catch (error) {
  console.error(`Inspection failed: ${error instanceof Error ? error.message : "unknown error"}`);
  process.exitCode = 2;
}
