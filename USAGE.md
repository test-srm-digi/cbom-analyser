# QuantumGuard CBOM Hub — Usage Guide

> This guide has been reorganized into focused documents for easier navigation. See the table below.

---

## Documentation Index

| Document | What's Inside |
|----------|---------------|
| [Getting Started](docs/getting-started.md) | Installation, Docker deployment, environment variables, Vite proxy, nginx, sample data & demo code |
| [GitHub Actions](docs/github-actions.md) | CI/CD integration, workflow setup, inputs/outputs, SARIF upload, SonarQube, exclude patterns, artifact download |
| [API Reference](docs/api-reference.md) | All REST API endpoints — CBOM management, uploads, network scanning, code scanning, AI suggestions, integrations, discovery data, policies, tickets, connectors, sync logs, scheduler |
| [Scanning](docs/scanning.md) | Code scanning (8 languages, 1000+ patterns), certificate file scanning, network TLS scanning, external tool integration (CodeQL, cbomkit-theia, CryptoAnalysis), variable resolution (7 strategies), config/artifact scanning, third-party dependency scanning, PQC readiness verdicts, informational asset filtering |
| [UI Guide](docs/ui-guide.md) | Dashboard, integrations hub, discovery pages, real connectors, cryptographic policies, violations, ticket tracking, quantum safety dashboard, project insight, AI suggested fixes |
| [Database](docs/database.md) | MariaDB setup, Sequelize configuration, connection pooling, schema auto-sync, all 11 table schemas with complete column definitions |
| [Architecture](docs/architecture.md) | System architecture diagram, project structure, technology stack, sync scheduler (cron jobs, connector registry, execution lifecycle), frontend state management (RTK Query, 60+ hooks, cache invalidation) |
| [PQC Standards](docs/pqc-standards.md) | Quantum threat overview, why CBOMs matter, core terminology, CycloneDX 1.7 specification (asset types, crypto properties, document structure), quantum safety classification |
| [xBOM](docs/xbom.md) | Unified SBOM + CBOM — concept, architecture, cross-reference linking, REST API, frontend pages, Trivy integration, CI pipeline, xBOM DB loader, file reference |

---

*Back to [README](README.md)*
