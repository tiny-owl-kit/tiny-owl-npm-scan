#!/usr/bin/env node
/**
 * Regenerates list/package-list.csv from the OSV.dev npm ecosystem export,
 * keeping only malicious package reports (OSV ids prefixed with "MAL-").
 * Source: https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import AdmZip from "adm-zip";

const OSV_NPM_EXPORT_URL =
  "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";
const OUTPUT_CSV_PATH = path.resolve(process.cwd(), "list/package-list.csv");

async function downloadZip(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(
      `Failed to download OSV export: ${response.status} ${response.statusText}`,
    );
  }
  return Buffer.from(await response.arrayBuffer());
}

function extractMaliciousEntries(zipBuffer) {
  const zip = new AdmZip(zipBuffer);
  const entries = new Set();

  for (const entry of zip.getEntries()) {
    if (entry.isDirectory || !entry.entryName.endsWith(".json")) continue;

    const record = JSON.parse(entry.getData().toString("utf8"));
    if (!record.id || !record.id.startsWith("MAL-")) continue;

    for (const affected of record.affected ?? []) {
      const name = affected.package?.name;
      if (!name) continue;

      for (const version of affected.versions ?? []) {
        entries.add(`${name},${version}`);
      }
    }
  }

  return entries;
}

function toCsv(entries) {
  const rows = ["package_name,package_version", ...Array.from(entries).sort()];
  return rows.join("\n") + "\n";
}

async function main() {
  const tempDir = await mkdtemp(path.join(tmpdir(), "osv-npm-"));
  try {
    console.log(`Downloading OSV npm export from ${OSV_NPM_EXPORT_URL} ...`);
    const zipBuffer = await downloadZip(OSV_NPM_EXPORT_URL);

    console.log("Extracting malicious package reports (MAL-*) ...");
    const entries = extractMaliciousEntries(zipBuffer);
    console.log(`Found ${entries.size} malicious package/version entries.`);

    await writeFile(OUTPUT_CSV_PATH, toCsv(entries), "utf8");
    console.log(`Wrote ${OUTPUT_CSV_PATH}`);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
