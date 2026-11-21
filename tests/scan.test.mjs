import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  buildCycloneDxSbom,
  buildPurl,
  classifyCraFindings,
  cleanVersion,
  deduplicateComponents,
  discoverManifests,
  fetchCisaKev,
  fetchOsvVulnDetails,
  parseCargoLock,
  parseGoMod,
  parsePackageJson,
  parsePackageLockJson,
  parsePyprojectToml,
  parseRequirementsTxt,
  queryOsvBatch,
  renderMarkdownReport,
  runScan,
} from "../src/scan.mjs";

test("cleanVersion normalizes common semver and PEP 440 ranges", () => {
  assert.equal(cleanVersion("^4.17.21"), "4.17.21");
  assert.equal(cleanVersion("~=2.31.0"), "2.31.0");
  assert.equal(cleanVersion(">=1.2.3, <2.0.0"), "1.2.3");
  assert.equal(cleanVersion("1.4.x"), "1.4.0");
  assert.equal(cleanVersion("workspace:*"), "");
  assert.equal(cleanVersion("*"), "");
});

test("parsePackageLockJson parses v2/v3 and v1 formats including scoped packages", () => {
  const lockV3 = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { name: "demo", version: "1.0.0" },
      "node_modules/lodash": { version: "4.17.20" },
      "node_modules/@scope/pkg": { version: "2.1.0" },
    },
  });
  const comps = parsePackageLockJson(lockV3);
  assert.equal(comps.length, 2);
  assert.deepEqual(
    comps.map((c) => `${c.name}@${c.version}`).sort(),
    ["@scope/pkg@2.1.0", "lodash@4.17.20"]
  );
  assert.equal(buildPurl("npm", "@scope/pkg", "2.1.0"), "pkg:npm/%40scope/pkg@2.1.0");
});

test("parsePackageJson extracts dependencies and devDependencies", () => {
  const pkg = JSON.stringify({
    name: "web-app",
    dependencies: { axios: "^1.6.0", local: "file:../local" },
    devDependencies: { typescript: "~5.6.2" },
  });
  const comps = parsePackageJson(pkg);
  assert.equal(comps.length, 2);
  assert.deepEqual(
    comps.map((c) => `${c.name}@${c.version}`).sort(),
    ["axios@1.6.0", "typescript@5.6.2"]
  );
});

test("parseRequirementsTxt & parsePyprojectToml parse Python dependencies", () => {
  const reqs = `
# comment
requests[security]==2.31.0 ; python_version >= "3.8"
urllib3>=1.26.5,<2.0.0
-r base.txt
`;
  const rComps = parseRequirementsTxt(reqs);
  assert.equal(rComps.length, 2);
  assert.equal(rComps[0].ecosystem, "PyPI");
  assert.equal(rComps[0].name, "requests");
  assert.equal(rComps[0].version, "2.31.0");

  const pyproject = `
[project]
name = "demo"
dependencies = [
  "fastapi>=0.115.0",
  "pydantic[email]==2.9.2",
]

[tool.poetry.dependencies]
python = "^3.12"
httpx = "^0.27.2"
uvicorn = { version = "^0.32.0", extras = ["standard"] }
`;
  const pComps = parsePyprojectToml(pyproject);
  assert.equal(pComps.length, 4);
  assert.ok(pComps.some((c) => c.name === "fastapi" && c.version === "0.115.0"));
  assert.ok(pComps.some((c) => c.name === "uvicorn" && c.version === "0.32.0"));
});

test("parseGoMod & parseCargoLock parse Go and Rust dependencies", () => {
  const goMod = `
module example.com/app

go 1.23

require github.com/gin-gonic/gin v1.9.1

require (
  golang.org/x/net v0.23.0 // indirect
  github.com/stretchr/testify v1.9.0
)
`;
  const goComps = parseGoMod(goMod);
  assert.equal(goComps.length, 3);
  assert.equal(goComps[0].ecosystem, "Go");
  assert.equal(goComps[0].version, "1.9.1");
  assert.equal(buildPurl("Go", "github.com/gin-gonic/gin", "1.9.1"), "pkg:golang/github.com/gin-gonic/gin@v1.9.1");

  const cargoLock = `
version = 3

[[package]]
name = "serde"
version = "1.0.210"

[[package]]
name = "tokio"
version = "1.40.0"
`;
  const rustComps = parseCargoLock(cargoLock);
  assert.equal(rustComps.length, 2);
  assert.equal(rustComps[0].ecosystem, "crates.io");
  assert.equal(buildPurl("crates.io", "serde", "1.0.210"), "pkg:cargo/serde@1.0.210");
});

test("buildCycloneDxSbom outputs valid CycloneDX 1.5 JSON structure", () => {
  const comps = deduplicateComponents([
    { ecosystem: "npm", name: "lodash", version: "4.17.21", manifest: "package-lock.json" },
    { ecosystem: "npm", name: "lodash", version: "4.17.21", manifest: "sub/package.json" },
  ]);
  assert.equal(comps.length, 1);
  assert.equal(comps[0].manifests.length, 2);

  const sbom = buildCycloneDxSbom(comps, { projectName: "demo-app" });
  assert.equal(sbom.bomFormat, "CycloneDX");
  assert.equal(sbom.specVersion, "1.5");
  assert.match(sbom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/i);
  assert.equal(sbom.components.length, 1);
  assert.equal(sbom.components[0].purl, "pkg:npm/lodash@4.17.21");
});

test("classifyCraFindings separates CISA KEV (CRA Art. 14 24h) from non-KEV OSV findings", () => {
  const components = deduplicateComponents([
    { ecosystem: "PyPI", name: "demo-kev", version: "1.0.0", manifest: "requirements.txt" },
    { ecosystem: "npm", name: "demo-nonkev", version: "2.0.0", manifest: "package.json" },
  ]);
  const alignedVulnIds = [["GHSA-nonkev-0001"], ["GHSA-kev-0001"]]; // sorted by purl: pkg:npm/... then pkg:pypi/...
  const details = new Map([
    [
      "GHSA-kev-0001",
      {
        id: "GHSA-kev-0001",
        aliases: ["CVE-2021-44228"],
        summary: "Actively exploited RCE",
        severity: "CRITICAL",
        fixedVersions: ["1.0.1"],
        reference: "https://osv.dev/vulnerability/GHSA-kev-0001",
      },
    ],
    [
      "GHSA-nonkev-0001",
      {
        id: "GHSA-nonkev-0001",
        aliases: ["CVE-2024-99999"],
        summary: "Moderate ReDoS",
        severity: "MODERATE",
        fixedVersions: ["2.0.1"],
        reference: "https://osv.dev/vulnerability/GHSA-nonkev-0001",
      },
    ],
  ]);
  const kevMap = new Map([
    [
      "CVE-2021-44228",
      {
        cveID: "CVE-2021-44228",
        vendorProject: "Apache",
        product: "Log4j",
        dateAdded: "2021-12-10",
      },
    ],
  ]);

  const res = classifyCraFindings(components, alignedVulnIds, details, kevMap);
  assert.equal(res.criticalArt14Kev.length, 1);
  assert.equal(res.criticalArt14Kev[0].craTier, "CRITICAL_CRA_ART14_24H");
  assert.equal(res.trackedNonKev.length, 1);
  assert.equal(res.trackedNonKev[0].craTier, "HIGH_MEDIUM_72H_TRACK");
  assert.equal(res.craArt14Alert, true);
  assert.ok(res.readinessScore <= 45);

  const md = renderMarkdownReport({
    feeds: { cisaKevCatalogVersion: "2026.11.21", cisaKevCount: 1 },
    outputs: { reportPath: "cra-report.json" },
    summary: {
      manifestsScanned: 2,
      componentsCount: 2,
      kevCount: 1,
      nonKevCount: 1,
      totalVulnerabilities: 2,
      readinessScore: res.readinessScore,
      craArt14Alert: res.craArt14Alert,
    },
    criticalArt14Kev: res.criticalArt14Kev,
    trackedNonKev: res.trackedNonKev,
  });
  assert.ok(md.includes("CRITICAL — CRA Art. 14 24h ENISA SRP Review Triggered"));
  assert.ok(md.includes("CVE-2021-44228"));
});

test("LIVE integration: OSV.dev querybatch + vuln details + CISA KEV catalog (zero API keys)", async () => {
  const kev = await fetchCisaKev();
  assert.ok(kev.count >= 1000, `Expected >=1000 CISA KEV entries, got ${kev.count}`);
  assert.ok(kev.map.has("CVE-2021-44228"), "Expected Log4Shell CVE-2021-44228 in CISA KEV");

  // Live query on known vulnerable lodash@4.17.20 & clean manifest scan in temp dir
  const testComps = deduplicateComponents([
    { ecosystem: "npm", name: "lodash", version: "4.17.20", manifest: "package.json" },
    { ecosystem: "PyPI", name: "Django", version: "3.2.4", manifest: "requirements.txt" },
  ]);
  const aligned = await queryOsvBatch(testComps);
  const allIds = aligned.flat();
  assert.ok(allIds.length > 0, "Expected live OSV.dev vulnerabilities for lodash@4.17.20 / Django@3.2.4");

  const details = await fetchOsvVulnDetails(allIds.slice(0, 5));
  assert.ok(details.size > 0);
  const firstDetail = details.values().next().value;
  assert.ok(firstDetail.id && Array.isArray(firstDetail.aliases));

  // End-to-end runScan on a clean temp repo
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cra-sbom-guard-"));
  try {
    fs.writeFileSync(
      path.join(tmpDir, "package.json"),
      JSON.stringify({ name: "clean-zero-dep", version: "1.0.0", dependencies: {} })
    );
    const sbomOut = path.join(tmpDir, "sbom.cdx.json");
    const reportOut = path.join(tmpDir, "cra-report.json");
    const manifests = discoverManifests(tmpDir);
    assert.equal(manifests.length, 1);

    const { report, sbom } = await runScan({
      target: tmpDir,
      sbomOutput: sbomOut,
      reportOutput: reportOut,
      failOnKev: true,
      maxDepth: 2,
      quiet: true,
    });
    assert.equal(sbom.specVersion, "1.5");
    assert.equal(report.summary.kevCount, 0);
    assert.equal(report.summary.readinessScore, 100);
    assert.ok(fs.existsSync(sbomOut));
    assert.ok(fs.existsSync(reportOut));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
