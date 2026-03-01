# QuantumGuard CBOM Hub

**Cryptographic Bill of Materials Scanner & Visualizer**

> A full-stack application that scans, parses, and visualizes the cryptographic inventory of any software project — then assesses its readiness for the post-quantum era.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CycloneDX 1.7](https://img.shields.io/badge/CycloneDX-1.7-green.svg)](https://cyclonedx.org/)

---

## What Is This Project?

**QuantumGuard CBOM Hub** produces and visualizes a **Cryptographic Bill of Materials (CBOM)** — a structured inventory of every cryptographic algorithm, protocol, certificate, and key used by a software project.

Think of it like an SBOM (Software Bill of Materials), but specifically for cryptography. Instead of listing software dependencies, a CBOM lists every use of SHA-256, RSA-2048, AES-128, TLS 1.2, etc., and maps where each one is used in the codebase.

The application then evaluates every cryptographic asset against **Post-Quantum Cryptography (PQC) standards** — telling you which algorithms will be broken by quantum computers and what NIST-approved replacements you should migrate to.

---

## Features

| Feature | Description |
|---------|-------------|
| **CBOM Upload & Parse** | Upload CycloneDX 1.7 CBOM JSON files |
| **Code Scanning** | Regex-based scanning for 8 languages (Java, Python, JS/TS, C/C++, C#, Go, PHP, Rust) with 1000+ patterns |
| **Network TLS Scanner** | Scan live endpoints for TLS/cipher details |
| **xBOM Unified BOMs** | Merge SBOM + CBOM into a single document with cross-references |
| **Third-Party Dependency Scanning** | Detect crypto libraries in Maven, npm, pip, Go dependencies |
| **PQC Risk Engine** | Flag quantum-vulnerable algorithms with NIST-approved replacements |
| **Cryptographic Policies** | Define compliance rules with 10 NIST SP 800-57 presets |
| **Integrations Hub** | DigiCert TLM, GitHub CBOM Import, Network TLS Scanner connectors |
| **Ticket Tracking** | Create remediation tickets in JIRA, GitHub Issues, ServiceNow |
| **Interactive Dashboard** | Donut charts, bubble charts, asset lists, readiness scoring |
| **GitHub Action** | Integrate into CI/CD pipelines |
| **AI Suggested Fixes** | AWS Bedrock-powered PQC migration suggestions |

---

## Competitive Differentiators

| Feature | IBM CBOMkit | CycloneDX cdxgen | **QuantumGuard** |
|---------|-------------|-------------------|------------------|
| CBOM Upload & Visualize | ✅ | ❌ | ✅ |
| Code Scanning | ✅ | ✅ | ✅ (8 languages + config files) |
| **Network TLS Scanning** | ❌ | ❌ | ✅ |
| **xBOM (SBOM + CBOM)** | ❌ | ❌ | ✅ |
| **PQC Risk Scoring (0-100)** | ❌ | ❌ | ✅ |
| **PQC Replacement Recommendations** | ❌ | ❌ | ✅ |
| **Offline/Client-side Mode** | ❌ | ❌ | ✅ |
| **Cryptographic Policies** | ❌ | ❌ | ✅ |
| **50+ Algorithm PQC Database** | ❌ | ❌ | ✅ |

---

## Quick Start

```bash
# Clone
git clone https://github.com/your-org/cbom-analyser.git
cd cbom-analyser

# Install dependencies
npm install

# Run (backend: 3001, frontend: 5173)
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) — upload a CBOM JSON or click **"sample CBOM file"** to explore the dashboard.

For Docker deployment and full configuration, see [Getting Started](docs/getting-started.md).

---

## Documentation

All detailed documentation is organized in the [`docs/`](docs/) folder:

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation, Docker deployment, environment variables, sample data |
| [GitHub Actions](docs/github-actions.md) | CI/CD integration, inputs/outputs, SARIF, SonarQube, artifact download |
| [API Reference](docs/api-reference.md) | Complete REST API documentation — all endpoints, request/response formats |
| [Scanning](docs/scanning.md) | Code scanning (8 languages), network scanning, dependency scanning, PQC verdicts |
| [UI Guide](docs/ui-guide.md) | Dashboard, integrations, discovery pages, policies, tickets, quantum safety |
| [Database](docs/database.md) | MariaDB setup, Sequelize config, connection pooling, all 11 table schemas |
| [Architecture](docs/architecture.md) | System architecture, project structure, tech stack, sync scheduler, RTK Query |
| [PQC Standards](docs/pqc-standards.md) | Quantum threat, CycloneDX 1.7 spec, asset types, safety classification |
| [xBOM](docs/xbom.md) | Unified SBOM + CBOM — Trivy integration, merge engine, CI pipeline |

**External:**
| Resource | Link |
|----------|------|
| CycloneDX 1.7 Specification | [cyclonedx.org/docs/1.7/json](https://cyclonedx.org/docs/1.7/json/) |
| NIST Post-Quantum Cryptography | [csrc.nist.gov](https://csrc.nist.gov/projects/post-quantum-cryptography) |
| IBM sonar-cryptography | [github.com/cbomkit/sonar-cryptography](https://github.com/cbomkit/sonar-cryptography) |

---

## License

MIT

---

*Built for the post-quantum era.*
