# CRA-SBOM-Guard — EU Cyber Resilience Act (Art. 14) SBOM & KEV Scanner

[![CI](https://github.com/yannabadie/cra-sbom-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/yannabadie/cra-sbom-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![EU CRA Art. 14](https://img.shields.io/badge/EU%20CRA%20Art.%2014-Active%20since%202026--09--11-047857)](https://yannabadie.github.io/cra-sbom-guard/)

**Zero-dependency** GitHub Action, Node 20/22+ CLI, and **100 % browser-side web scanner** built for the **EU Cyber Resilience Act (Regulation (EU) 2024/2847)**.

- **Free Instant Web Scanner (100 % Browser-Side, Zero Upload):** https://yannabadie.github.io/cra-sbom-guard/
- **Zero external npm dependencies** (`dependencies: {}`) — instant CI execution, zero supply-chain bloat.
- **Zero API keys required** — queries **OSV.dev** and the official **CISA KEV** catalog live.

---

## Why EU CRA Article 14 Matters Right Now (November 2026)

Under **Regulation (EU) 2024/2847 (Cyber Resilience Act)**:
- **11 September 2026 (ALREADY IN FORCE):** Mandatory **Article 14** vulnerability and severe-incident reporting via the **ENISA Single Reporting Platform (SRP)** + national CSIRT (**24h early warning** / **72h technical notification** / **14d–1mo final report**) for **actively exploited vulnerabilities** in products with digital elements — including legacy products already on the market.
- **11 December 2027:** Full CRA compliance, CE marking, and mandatory machine-readable **SBOM (CycloneDX / SPDX)** covering top-level dependencies (Annex I).
- **Article 64 Penalties:** Up to **€15 million or 2.5% of worldwide annual turnover** for breaches of core manufacturer obligations including Article 14 reporting.

`CRA-SBOM-Guard` generates a **CycloneDX 1.5 JSON SBOM** from your manifests and flags any dependency matching **CISA Known Exploited Vulnerabilities (KEV)** so your team knows within seconds whether the **24-hour ENISA SRP clock** may be triggered.

---

## Quick Start — GitHub Actions (5 Lines)

```yaml
name: EU CRA Art. 14 SBOM & KEV Check
on: [push, pull_request]

jobs:
  cra-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: yannabadie/cra-sbom-guard@v1.0.0
        with:
          target: "."
          sbom-output: "sbom.cdx.json"
          report-output: "cra-report.json"
          fail-on-kev: "true"
```

Every run writes a structured Markdown compliance summary directly to `$GITHUB_STEP_SUMMARY`, exports `sbom.cdx.json` (CycloneDX 1.5) and `cra-report.json`, and exposes Action outputs (`readiness-score`, `kev-count`, `vuln-count`, `components-count`, `cra-art14-alert`).

---

## Local CLI Usage (Node 20/22+, Zero Install)

```bash
node src/scan.mjs . --sbom sbom.cdx.json --report cra-report.json
```

Optional flag `--no-fail-on-kev` generates reports without exiting with status `1` on KEV findings.

---

## Supported Manifests & Ecosystems

| Ecosystem | Manifest Files | Package URL (`purl`) |
|---|---|---|
| **JavaScript / TypeScript** | `package-lock.json` (v1/v2/v3), `package.json` | `pkg:npm/...` |
| **Python** | `requirements.txt`, `pyproject.toml` (PEP 621 & Poetry) | `pkg:pypi/...` |
| **Go** | `go.mod` | `pkg:golang/...` |
| **Rust** | `Cargo.lock` | `pkg:cargo/...` |

---

## Inputs & Outputs

| Input | Default | Description |
|---|---|---|
| `target` | `.` | Directory or single manifest file to scan |
| `sbom-output` | `sbom.cdx.json` | Output path for CycloneDX 1.5 JSON SBOM |
| `report-output` | `cra-report.json` | Output path for structured JSON compliance report |
| `fail-on-kev` | `true` | Exit with code `1` when a CISA KEV finding triggers CRA Art. 14 review |
| `max-depth` | `4` | Maximum directory depth when discovering manifests |

Outputs: `sbom-path`, `report-path`, `components-count`, `kev-count`, `vuln-count`, `readiness-score`, `cra-art14-alert`.

---

## Companion EU Compliance & Open-Data Tools

- **Web Scanner (Zero Upload, EN/FR):** https://yannabadie.github.io/cra-sbom-guard/
- **FacturKit 2027 (French Factur-X 1.09.2 / EN 16931 Validator & Comparator):** https://yannabadie.github.io/facturkit-2027/
- **Factur-X France 2026–2027 Open-Source CLI & Action:** https://github.com/yannabadie/facturx-france-2027
- **EU/US Official Open-Data MCP Server:** https://github.com/yannabadie/eu-us-opendata-mcp

---

## License

MIT — see [LICENSE](LICENSE).
