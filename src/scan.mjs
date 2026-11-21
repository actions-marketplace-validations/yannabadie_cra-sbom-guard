#!/usr/bin/env node
/**
 * CRA-SBOM-Guard (v1.0.0)
 * Zero-dependency EU Cyber Resilience Act (Regulation (EU) 2024/2847 — Art. 14 active since 2026-09-11)
 * CycloneDX 1.5 SBOM generator + live OSV.dev & CISA KEV scanner.
 *
 * Works both as a standalone Node 20/22+ CLI and natively as a GitHub Action (`using: node20`).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const TOOL_NAME = "cra-sbom-guard";
export const TOOL_VERSION = "1.0.0";
export const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
export const OSV_VULN_URL = "https://api.osv.dev/v1/vulns/";
export const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "target",
  "vendor",
  "venv",
  ".venv",
  "__pycache__",
  ".next",
  ".nuxt",
  "coverage",
]);

const SUPPORTED_MANIFESTS = new Set([
  "package-lock.json",
  "package.json",
  "requirements.txt",
  "pyproject.toml",
  "go.mod",
  "Cargo.lock",
]);

/**
 * Clean common version range prefixes into an exact semver/PEP440 string for OSV queries.
 */
export function cleanVersion(raw) {
  if (!raw || typeof raw !== "string") return "";
  let v = raw.trim().replace(/^["']|["']$/g, "");
  if (
    !v ||
    v === "*" ||
    v === "latest" ||
    v.startsWith("workspace:") ||
    v.startsWith("file:") ||
    v.startsWith("link:") ||
    v.startsWith("git+") ||
    v.startsWith("http://") ||
    v.startsWith("https://")
  ) {
    return "";
  }
  // Take first comparator if comma/space separated (e.g. ">=1.2.3, <2.0.0")
  v = v.split(/[,\s|]+/)[0] || "";
  v = v.replace(/^(?:===|==|~=|>=|<=|!=|>|<|\^|~|=)/, "").trim();
  if (!v || /^[xX*]+$/.test(v) || v.includes("*")) return "";
  // Normalize partial x-ranges like 1.2.x -> 1.2.0
  v = v.replace(/\.[xX]$/g, ".0");
  return /^[0-9vV]/.test(v) ? v : "";
}

/**
 * Build a Package URL (purl) per CycloneDX / purl-spec.
 */
export function buildPurl(ecosystem, name, version) {
  const ver = version ? `@${encodeURIComponent(version)}` : "";
  switch (ecosystem) {
    case "npm": {
      if (name.startsWith("@") && name.includes("/")) {
        const [scope, pkg] = name.split("/", 2);
        return `pkg:npm/${encodeURIComponent(scope)}/${encodeURIComponent(pkg)}${ver}`;
      }
      return `pkg:npm/${encodeURIComponent(name)}${ver}`;
    }
    case "PyPI":
      return `pkg:pypi/${encodeURIComponent(name.toLowerCase())}${ver}`;
    case "Go":
      return `pkg:golang/${name}${version ? `@v${version.replace(/^v/, "")}` : ""}`;
    case "crates.io":
      return `pkg:cargo/${encodeURIComponent(name)}${ver}`;
    default:
      return `pkg:generic/${encodeURIComponent(name)}${ver}`;
  }
}

/**
 * Parse npm package-lock.json (v1, v2, v3).
 */
export function parsePackageLockJson(text, sourceFile = "package-lock.json") {
  const components = [];
  const data = JSON.parse(text);

  if (data.packages && typeof data.packages === "object") {
    for (const [pkgPath, meta] of Object.entries(data.packages)) {
      if (!pkgPath || !meta || typeof meta !== "object") continue;
      let name = meta.name;
      if (!name) {
        const idx = pkgPath.lastIndexOf("node_modules/");
        if (idx === -1) continue;
        name = pkgPath.slice(idx + "node_modules/".length);
      }
      const version = cleanVersion(meta.version);
      if (name && version) {
        components.push({
          ecosystem: "npm",
          name,
          version,
          manifest: sourceFile,
        });
      }
    }
  } else if (data.dependencies && typeof data.dependencies === "object") {
    const walk = (deps) => {
      for (const [name, meta] of Object.entries(deps)) {
        if (!meta || typeof meta !== "object") continue;
        const version = cleanVersion(meta.version);
        if (name && version) {
          components.push({
            ecosystem: "npm",
            name,
            version,
            manifest: sourceFile,
          });
        }
        if (meta.dependencies) walk(meta.dependencies);
      }
    };
    walk(data.dependencies);
  }
  return components;
}

/**
 * Parse npm package.json dependencies + devDependencies.
 */
export function parsePackageJson(text, sourceFile = "package.json") {
  const components = [];
  const data = JSON.parse(text);
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const deps = data[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, spec] of Object.entries(deps)) {
      const version = cleanVersion(String(spec));
      if (name && version) {
        components.push({
          ecosystem: "npm",
          name,
          version,
          manifest: sourceFile,
        });
      }
    }
  }
  return components;
}

/**
 * Parse Python requirements.txt.
 */
export function parseRequirementsTxt(text, sourceFile = "requirements.txt") {
  const components = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.split("#")[0].split(";")[0].trim();
    if (!line || line.startsWith("-") || line.startsWith("http://") || line.startsWith("https://")) {
      continue;
    }
    const m = line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:===|==|~=|>=|<=|>|<)\s*([^\s,;\\]+)/);
    if (!m) continue;
    const name = m[1].trim();
    const version = cleanVersion(m[2]);
    if (name && version) {
      components.push({
        ecosystem: "PyPI",
        name,
        version,
        manifest: sourceFile,
      });
    }
  }
  return components;
}

/**
 * Parse Python pyproject.toml (PEP 621 [project] dependencies & Poetry [tool.poetry.dependencies]).
 */
export function parsePyprojectToml(text, sourceFile = "pyproject.toml") {
  const components = [];

  // 1. PEP 621 dependencies = [ "..." ] (quote-aware so extras like "pydantic[email]==2.9.2" do not terminate early)
  const depArrayMatch = text.match(/\bdependencies\s*=\s*\[((?:[^\]"']|"[^"]*"|'[^']*')*)\]/m);
  if (depArrayMatch) {
    const items = depArrayMatch[1].match(/["']([^"']+)["']/g) || [];
    for (const quoted of items) {
      const inner = quoted.slice(1, -1).split(";")[0].trim();
      const m = inner.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:===|==|~=|>=|<=|>|<)\s*([^\s,;]+)/);
      if (m) {
        const version = cleanVersion(m[2]);
        if (version) {
          components.push({
            ecosystem: "PyPI",
            name: m[1].trim(),
            version,
            manifest: sourceFile,
          });
        }
      }
    }
  }

  // 2. Poetry [tool.poetry.dependencies]
  const poetrySection = text.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/);
  if (poetrySection) {
    for (const rawLine of poetrySection[1].split(/\r?\n/)) {
      const line = rawLine.split("#")[0].trim();
      if (!line || line.startsWith("python")) continue;
      const simple = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*["']([^"']+)["']/);
      const inlineTable = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*\{[^}]*version\s*=\s*["']([^"']+)["']/);
      const m = simple || inlineTable;
      if (m) {
        const version = cleanVersion(m[2]);
        if (version) {
          components.push({
            ecosystem: "PyPI",
            name: m[1].trim(),
            version,
            manifest: sourceFile,
          });
        }
      }
    }
  }

  return components;
}

/**
 * Parse Go go.mod.
 */
export function parseGoMod(text, sourceFile = "go.mod") {
  const components = [];
  let inRequireBlock = false;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.split("//")[0].trim();
    if (!line) continue;
    if (/^require\s*\($/.test(line)) {
      inRequireBlock = true;
      continue;
    }
    if (inRequireBlock && line === ")") {
      inRequireBlock = false;
      continue;
    }
    let m = null;
    if (inRequireBlock) {
      m = line.match(/^([^\s]+)\s+(v[0-9][^\s]*)/);
    } else if (line.startsWith("require ")) {
      m = line.slice("require ".length).trim().match(/^([^\s]+)\s+(v[0-9][^\s]*)/);
    }
    if (m) {
      // OSV Go ecosystem expects semver without leading "v"
      const version = m[2].replace(/^v/, "");
      components.push({
        ecosystem: "Go",
        name: m[1].trim(),
        version,
        manifest: sourceFile,
      });
    }
  }
  return components;
}

/**
 * Parse Rust Cargo.lock.
 */
export function parseCargoLock(text, sourceFile = "Cargo.lock") {
  const components = [];
  const blocks = text.split(/\[\[package\]\]/).slice(1);
  for (const block of blocks) {
    const nameMatch = block.match(/^\s*name\s*=\s*"([^"]+)"/m);
    const verMatch = block.match(/^\s*version\s*=\s*"([^"]+)"/m);
    if (nameMatch && verMatch) {
      const version = cleanVersion(verMatch[1]);
      if (version) {
        components.push({
          ecosystem: "crates.io",
          name: nameMatch[1].trim(),
          version,
          manifest: sourceFile,
        });
      }
    }
  }
  return components;
}

/**
 * Parse a single manifest file by basename.
 */
export function parseManifestFile(filePath, rootDir = process.cwd()) {
  const base = path.basename(filePath);
  const rel = path.relative(rootDir, filePath) || base;
  const text = fs.readFileSync(filePath, "utf8");
  switch (base) {
    case "package-lock.json":
      return parsePackageLockJson(text, rel);
    case "package.json":
      return parsePackageJson(text, rel);
    case "requirements.txt":
      return parseRequirementsTxt(text, rel);
    case "pyproject.toml":
      return parsePyprojectToml(text, rel);
    case "go.mod":
      return parseGoMod(text, rel);
    case "Cargo.lock":
      return parseCargoLock(text, rel);
    default:
      return [];
  }
}

/**
 * Discover supported manifests under targetDir (or return [targetPath] if file).
 */
export function discoverManifests(targetPath, maxDepth = 4) {
  const resolved = path.resolve(targetPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Target path does not exist: ${resolved}`);
  }
  const stat = fs.statSync(resolved);
  if (stat.isFile()) return [resolved];

  const found = [];
  const walk = (dir, depth) => {
    if (depth > maxDepth) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const dirFileNames = new Set(entries.filter((e) => e.isFile()).map((e) => e.name));
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) {
          walk(path.join(dir, entry.name), depth + 1);
        }
      } else if (entry.isFile() && SUPPORTED_MANIFESTS.has(entry.name)) {
        // Prefer package-lock.json over package.json in the same directory to avoid unpinned range noise
        if (entry.name === "package.json" && dirFileNames.has("package-lock.json")) {
          continue;
        }
        found.push(path.join(dir, entry.name));
      }
    }
  };
  walk(resolved, 0);
  return found.sort();
}

/**
 * Deduplicate components by ecosystem + lowercased name + version.
 */
export function deduplicateComponents(rawComponents) {
  const seen = new Map();
  for (const c of rawComponents) {
    const key = `${c.ecosystem}::${c.name.toLowerCase()}::${c.version}`;
    if (!seen.has(key)) {
      seen.set(key, {
        ecosystem: c.ecosystem,
        name: c.name,
        version: c.version,
        purl: buildPurl(c.ecosystem, c.name, c.version),
        manifests: [c.manifest],
      });
    } else {
      const existing = seen.get(key);
      if (c.manifest && !existing.manifests.includes(c.manifest)) {
        existing.manifests.push(c.manifest);
      }
    }
  }
  return Array.from(seen.values()).sort((a, b) => a.purl.localeCompare(b.purl));
}

/**
 * Build a compliant CycloneDX 1.5 JSON SBOM.
 */
export function buildCycloneDxSbom(components, meta = {}) {
  const appName = meta.projectName || "scanned-project";
  const timestamp = meta.timestamp || new Date().toISOString();
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp,
      tools: {
        components: [
          {
            type: "application",
            name: TOOL_NAME,
            version: TOOL_VERSION,
            publisher: "Yann Abadie",
          },
        ],
      },
      component: {
        type: "application",
        name: appName,
      },
      properties: [
        { name: "eu:cra:regulation", value: "Regulation (EU) 2024/2847" },
        { name: "eu:cra:article14-effective", value: "2026-09-11" },
        { name: "eu:cra:full-sbom-effective", value: "2027-12-11" },
      ],
    },
    components: components.map((c) => ({
      type: "library",
      "bom-ref": c.purl,
      name: c.name,
      version: c.version,
      purl: c.purl,
      properties: [
        { name: "cra:ecosystem", value: c.ecosystem },
        { name: "cra:manifests", value: (c.manifests || []).join(", ") },
      ],
    })),
  };
}

async function fetchJsonWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "User-Agent": `${TOOL_NAME}/${TOOL_VERSION} (+https://github.com/yannabadie/cra-sbom-guard)`,
        ...(options.headers || {}),
      },
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} fetching ${url}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch live CISA KEV catalog (zero API keys) -> { map, catalogVersion, dateReleased, count }.
 */
export async function fetchCisaKev(url = CISA_KEV_URL) {
  const data = await fetchJsonWithTimeout(url, {}, 20000);
  const map = new Map();
  for (const item of data.vulnerabilities || []) {
    if (item && item.cveID) {
      map.set(item.cveID.toUpperCase(), {
        cveID: item.cveID.toUpperCase(),
        vendorProject: item.vendorProject || "",
        product: item.product || "",
        vulnerabilityName: item.vulnerabilityName || "",
        dateAdded: item.dateAdded || "",
        dueDate: item.dueDate || "",
        knownRansomwareCampaignUse: item.knownRansomwareCampaignUse || "Unknown",
        requiredAction: item.requiredAction || "",
      });
    }
  }
  return {
    map,
    catalogVersion: data.catalogVersion || "unknown",
    dateReleased: data.dateReleased || "",
    count: map.size,
  };
}

/**
 * Query OSV.dev batch API in chunks of 500 components.
 * Returns array aligned 1:1 with `components` of vuln ID lists.
 */
export async function queryOsvBatch(components, batchUrl = OSV_BATCH_URL) {
  if (!components.length) return [];
  const aligned = new Array(components.length).fill(null).map(() => []);
  const chunkSize = 500;

  for (let offset = 0; offset < components.length; offset += chunkSize) {
    const slice = components.slice(offset, offset + chunkSize);
    const body = {
      queries: slice.map((c) => ({
        package: { name: c.name, ecosystem: c.ecosystem },
        version: c.version,
      })),
    };
    const resp = await fetchJsonWithTimeout(
      batchUrl,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      },
      20000
    );
    const results = resp.results || [];
    for (let i = 0; i < slice.length; i++) {
      const vulns = (results[i] && results[i].vulns) || [];
      aligned[offset + i] = vulns.map((v) => v.id).filter(Boolean);
    }
  }
  return aligned;
}

/**
 * Fetch OSV vulnerability details (aliases, summary, severity, fixed version) with bounded concurrency.
 */
export async function fetchOsvVulnDetails(vulnIds, concurrency = 8, baseUrl = OSV_VULN_URL) {
  const uniqueIds = Array.from(new Set(vulnIds));
  const details = new Map();
  let cursor = 0;

  const worker = async () => {
    while (cursor < uniqueIds.length) {
      const id = uniqueIds[cursor++];
      try {
        const data = await fetchJsonWithTimeout(`${baseUrl}${encodeURIComponent(id)}`, {}, 15000);
        const fixedVersions = new Set();
        for (const aff of data.affected || []) {
          for (const rng of aff.ranges || []) {
            for (const ev of rng.events || []) {
              if (ev.fixed) fixedVersions.add(ev.fixed);
            }
          }
        }
        const dbSev =
          (data.database_specific && data.database_specific.severity) ||
          (Array.isArray(data.severity) && data.severity[0] && data.severity[0].score) ||
          "UNKNOWN";
        details.set(id, {
          id: data.id || id,
          aliases: Array.isArray(data.aliases) ? data.aliases : [],
          summary: data.summary || (data.details ? String(data.details).slice(0, 180) : ""),
          severity: String(dbSev).toUpperCase(),
          fixedVersions: Array.from(fixedVersions).slice(0, 5),
          reference:
            (Array.isArray(data.references) && data.references[0] && data.references[0].url) ||
            `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
        });
      } catch {
        details.set(id, {
          id,
          aliases: [],
          summary: "",
          severity: "UNKNOWN",
          fixedVersions: [],
          reference: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
        });
      }
    }
  };

  const workers = Array.from({ length: Math.min(concurrency, uniqueIds.length) }, () => worker());
  await Promise.all(workers);
  return details;
}

/**
 * Classify OSV findings against CISA KEV under EU Cyber Resilience Act Art. 14 rules.
 */
export function classifyCraFindings(components, alignedVulnIds, vulnDetailsMap, kevMap) {
  const criticalArt14Kev = [];
  const trackedNonKev = [];

  for (let i = 0; i < components.length; i++) {
    const comp = components[i];
    const ids = alignedVulnIds[i] || [];
    for (const id of ids) {
      const detail = vulnDetailsMap.get(id) || {
        id,
        aliases: [],
        summary: "",
        severity: "UNKNOWN",
        fixedVersions: [],
        reference: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
      };
      const candidateCves = [detail.id, ...(detail.aliases || [])]
        .map((x) => String(x).toUpperCase())
        .filter((x) => x.startsWith("CVE-"));

      let matchedKev = null;
      for (const cve of candidateCves) {
        if (kevMap.has(cve)) {
          matchedKev = kevMap.get(cve);
          break;
        }
      }

      const finding = {
        component: `${comp.name}@${comp.version}`,
        ecosystem: comp.ecosystem,
        purl: comp.purl,
        manifests: comp.manifests || [],
        osvId: detail.id,
        cves: candidateCves,
        severity: detail.severity,
        summary: detail.summary,
        fixedVersions: detail.fixedVersions,
        reference: detail.reference,
        isCisaKev: Boolean(matchedKev),
        craTier: matchedKev ? "CRITICAL_CRA_ART14_24H" : "HIGH_MEDIUM_72H_TRACK",
        craAction: matchedKev
          ? "EU CRA Art. 14: Actively exploited vulnerability (CISA KEV). Assess product exposure immediately; submit 24h early warning + 72h notification via ENISA Single Reporting Platform (SRP) if deployed in an in-scope digital product."
          : "Track remediation & evaluate severe-incident impact under EU CRA Art. 14 / Annex I.",
        kev: matchedKev,
      };

      if (matchedKev) {
        criticalArt14Kev.push(finding);
      } else {
        trackedNonKev.push(finding);
      }
    }
  }

  let score = 100;
  if (criticalArt14Kev.length > 0) {
    score -= Math.min(80, 45 + (criticalArt14Kev.length - 1) * 15);
  }
  for (const f of trackedNonKev) {
    if (f.severity.includes("CRITICAL") || f.severity.includes("HIGH")) {
      score -= 8;
    } else {
      score -= 3;
    }
  }
  score = Math.max(0, Math.min(100, score));
  if (criticalArt14Kev.length > 0 && score > 45) {
    score = 45;
  }

  return {
    criticalArt14Kev,
    trackedNonKev,
    readinessScore: score,
    craArt14Alert: criticalArt14Kev.length > 0,
  };
}

/**
 * Render concise GitHub Step Summary / CLI Markdown report.
 */
export function renderMarkdownReport(report) {
  const lines = [];
  const badge = report.summary.craArt14Alert
    ? "CRITICAL — CRA Art. 14 24h ENISA SRP Review Triggered"
    : report.summary.totalVulnerabilities > 0
      ? "WARNING — Non-KEV Vulnerabilities Detected (Track Remediation)"
      : "PASS — Zero Known Exploited or OSV Vulnerabilities Detected";

  lines.push("## CRA-SBOM-Guard — EU Cyber Resilience Act (Art. 14) Audit");
  lines.push("");
  lines.push(`**Status:** ${badge}`);
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|---|---|");
  lines.push(`| **EU CRA Regulation** | Regulation (EU) 2024/2847 (Art. 14 active since \`2026-09-11\`, full SBOM \`2027-12-11\`) |`);
  lines.push(`| **CRA Art. 14 Readiness Score** | **${report.summary.readinessScore} / 100** |`);
  lines.push(`| **Manifests Scanned** | ${report.summary.manifestsScanned} |`);
  lines.push(`| **Unique SBOM Components (CycloneDX 1.5)** | ${report.summary.componentsCount} |`);
  lines.push(`| **CRITICAL CRA Art. 14 (CISA KEV — 24h ENISA SRP)** | **${report.summary.kevCount}** |`);
  lines.push(`| **HIGH/MEDIUM OSV Findings (72h / Remediation)** | ${report.summary.nonKevCount} |`);
  lines.push(`| **CISA KEV Catalog** | \`${report.feeds.cisaKevCatalogVersion}\` (${report.feeds.cisaKevCount} entries) |`);
  lines.push("");

  if (report.criticalArt14Kev.length > 0) {
    lines.push("### CRITICAL — Actively Exploited Vulnerabilities (CISA KEV / EU CRA Art. 14 24h Clock)");
    lines.push("");
    lines.push("| Component | Ecosystem | CVE / OSV | KEV Added | Fixed In | Action |");
    lines.push("|---|---|---|---|---|---|");
    for (const f of report.criticalArt14Kev) {
      const cveLabel = f.kev ? f.kev.cveID : f.osvId;
      const fix = f.fixedVersions.length ? f.fixedVersions.join(", ") : "Check advisory";
      lines.push(
        `| \`${f.component}\` | ${f.ecosystem} | [${cveLabel}](${f.reference}) | ${f.kev?.dateAdded || "-"} | \`${fix}\` | 24h ENISA SRP early warning review |`
      );
    }
    lines.push("");
  }

  if (report.trackedNonKev.length > 0) {
    lines.push("### Tracked OSV Vulnerabilities (Non-KEV — Remediation Queue)");
    lines.push("");
    lines.push("| Component | Ecosystem | Advisory | Severity | Fixed In |");
    lines.push("|---|---|---|---|---|");
    for (const f of report.trackedNonKev.slice(0, 25)) {
      const fix = f.fixedVersions.length ? f.fixedVersions.join(", ") : "-";
      lines.push(
        `| \`${f.component}\` | ${f.ecosystem} | [${f.osvId}](${f.reference}) | ${f.severity} | \`${fix}\` |`
      );
    }
    if (report.trackedNonKev.length > 25) {
      lines.push(`\n_...and ${report.trackedNonKev.length - 25} additional non-KEV findings in \`${report.outputs.reportPath}\`._`);
    }
    lines.push("");
  }

  lines.push(
    "_Generated by [CRA-SBOM-Guard](https://yannabadie.github.io/cra-sbom-guard/) (MIT, zero-dependency CycloneDX 1.5 + OSV.dev + CISA KEV)._"
  );
  return lines.join("\n");
}

function parseCliAndActionConfig(argv, env) {
  const cfg = {
    target: env.INPUT_TARGET || ".",
    sbomOutput: env["INPUT_SBOM-OUTPUT"] || env.INPUT_SBOM_OUTPUT || "sbom.cdx.json",
    reportOutput: env["INPUT_REPORT-OUTPUT"] || env.INPUT_REPORT_OUTPUT || "cra-report.json",
    failOnKev: (env["INPUT_FAIL-ON-KEV"] || env.INPUT_FAIL_ON_KEV || "true").toLowerCase() !== "false",
    maxDepth: Number.parseInt(env["INPUT_MAX-DEPTH"] || env.INPUT_MAX_DEPTH || "4", 10) || 4,
    quiet: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--target" && argv[i + 1]) cfg.target = argv[++i];
    else if (arg === "--sbom" && argv[i + 1]) cfg.sbomOutput = argv[++i];
    else if (arg === "--report" && argv[i + 1]) cfg.reportOutput = argv[++i];
    else if (arg === "--max-depth" && argv[i + 1]) cfg.maxDepth = Number.parseInt(argv[++i], 10) || 4;
    else if (arg === "--fail-on-kev") cfg.failOnKev = true;
    else if (arg === "--no-fail-on-kev") cfg.failOnKev = false;
    else if (arg === "--quiet") cfg.quiet = true;
    else if (arg === "--help" || arg === "-h") {
      console.log(`CRA-SBOM-Guard v${TOOL_VERSION} — EU Cyber Resilience Act Art. 14 SBOM & KEV/OSV Scanner

Usage:
  node src/scan.mjs [target] [--sbom sbom.cdx.json] [--report cra-report.json] [--no-fail-on-kev]

Options:
  --target <path>       Directory or manifest file to scan (default: ".")
  --sbom <file>         CycloneDX 1.5 JSON output path (default: "sbom.cdx.json")
  --report <file>       JSON compliance report path (default: "cra-report.json")
  --max-depth <n>       Directory traversal max depth (default: 4)
  --fail-on-kev         Exit 1 if CISA KEV finding triggers CRA Art. 14 24h alert (default)
  --no-fail-on-kev      Always exit 0 after writing reports
`);
      process.exit(0);
    } else if (!arg.startsWith("-")) {
      cfg.target = arg;
    }
  }
  return cfg;
}

/**
 * Full end-to-end scan pipeline.
 */
export async function runScan(cfg) {
  const rootDir = path.resolve(cfg.target);
  const manifests = discoverManifests(rootDir, cfg.maxDepth);
  const rawComponents = [];
  for (const m of manifests) {
    rawComponents.push(...parseManifestFile(m, fs.statSync(rootDir).isDirectory() ? rootDir : path.dirname(rootDir)));
  }
  const components = deduplicateComponents(rawComponents);

  const projectName = path.basename(fs.statSync(rootDir).isDirectory() ? rootDir : path.dirname(rootDir));
  const sbom = buildCycloneDxSbom(components, { projectName });

  const [kevFeed, alignedVulnIds] = await Promise.all([
    fetchCisaKev(),
    queryOsvBatch(components),
  ]);

  const allVulnIds = alignedVulnIds.flat();
  const vulnDetailsMap = await fetchOsvVulnDetails(allVulnIds);
  const classification = classifyCraFindings(components, alignedVulnIds, vulnDetailsMap, kevFeed.map);

  const sbomPath = path.resolve(cfg.sbomOutput);
  const reportPath = path.resolve(cfg.reportOutput);

  const report = {
    tool: `${TOOL_NAME}@${TOOL_VERSION}`,
    scannedAt: new Date().toISOString(),
    regulation: {
      name: "EU Cyber Resilience Act — Regulation (EU) 2024/2847",
      article14EffectiveDate: "2026-09-11",
      fullComplianceDate: "2027-12-11",
      enisaSingleReportingPlatform: "24h early warning / 72h notification / 14d-1mo final report",
      maxPenaltyArticle64: "Up to EUR 15,000,000 or 2.5% of total worldwide annual turnover",
    },
    feeds: {
      osvEndpoint: OSV_BATCH_URL,
      cisaKevCatalogVersion: kevFeed.catalogVersion,
      cisaKevDateReleased: kevFeed.dateReleased,
      cisaKevCount: kevFeed.count,
    },
    manifests: manifests.map((m) => path.relative(process.cwd(), m) || path.basename(m)),
    outputs: {
      sbomPath: cfg.sbomOutput,
      reportPath: cfg.reportOutput,
    },
    summary: {
      manifestsScanned: manifests.length,
      componentsCount: components.length,
      kevCount: classification.criticalArt14Kev.length,
      nonKevCount: classification.trackedNonKev.length,
      totalVulnerabilities: classification.criticalArt14Kev.length + classification.trackedNonKev.length,
      readinessScore: classification.readinessScore,
      craArt14Alert: classification.craArt14Alert,
    },
    criticalArt14Kev: classification.criticalArt14Kev,
    trackedNonKev: classification.trackedNonKev,
  };

  fs.mkdirSync(path.dirname(sbomPath), { recursive: true });
  fs.writeFileSync(sbomPath, JSON.stringify(sbom, null, 2) + "\n", "utf8");

  fs.mkdirSync(path.dirname(reportPath), { recursive: true });
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");

  const markdown = renderMarkdownReport(report);

  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown + "\n", "utf8");
  }
  if (process.env.GITHUB_OUTPUT) {
    const outLines = [
      `sbom-path=${sbomPath}`,
      `report-path=${reportPath}`,
      `components-count=${report.summary.componentsCount}`,
      `kev-count=${report.summary.kevCount}`,
      `vuln-count=${report.summary.totalVulnerabilities}`,
      `readiness-score=${report.summary.readinessScore}`,
      `cra-art14-alert=${report.summary.craArt14Alert}`,
    ];
    fs.appendFileSync(process.env.GITHUB_OUTPUT, outLines.join("\n") + "\n", "utf8");
  }

  return { report, sbom, markdown };
}

const isMain =
  process.argv[1] && path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1]);

if (isMain) {
  const cfg = parseCliAndActionConfig(process.argv.slice(2), process.env);
  runScan(cfg)
    .then(({ report, markdown }) => {
      if (!cfg.quiet) {
        console.log(markdown);
      }
      if (cfg.failOnKev && report.summary.kevCount > 0) {
        console.error(
          `\n[CRA-SBOM-Guard] FAIL: ${report.summary.kevCount} actively exploited CISA KEV finding(s) detected — EU CRA Art. 14 24h ENISA SRP review required.`
        );
        process.exit(1);
      }
    })
    .catch((err) => {
      console.error(`[CRA-SBOM-Guard] ERROR: ${err.message}`);
      process.exit(2);
    });
}
