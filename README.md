# QuantumGuard CBOM Hub

**Cryptographic Bill of Materials Scanner & Visualizer**

> A full-stack application that scans, parses, and visualizes the cryptographic inventory of any software project — then assesses its readiness for the post-quantum era.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CycloneDX 1.6](https://img.shields.io/badge/CycloneDX-1.6-green.svg)](https://cyclonedx.org/)

---

## What Is This Project?

**QuantumGuard CBOM Hub** produces and visualizes a **Cryptographic Bill of Materials (CBOM)** — a structured inventory of every cryptographic algorithm, protocol, certificate, and key used by a software project.

Think of it like an SBOM (Software Bill of Materials), but specifically for cryptography. Instead of listing software dependencies, a CBOM lists every use of SHA-256, RSA-2048, AES-128, TLS 1.2, etc., and maps where each one is used in the codebase.

The application then evaluates every cryptographic asset against **Post-Quantum Cryptography (PQC) standards** — telling you which algorithms will be broken by quantum computers and what NIST-approved replacements you should migrate to.

### What It Does (End to End)

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────────┐
│  Upload CBOM    │     │  Scan Code/TLS   │     │  Load Sample Data    │
│  (.json file)   │     │  (live scan)     │     │  (demo mode)         │
└────────┬────────┘     └────────┬─────────┘     └──────────┬───────────┘
         │                       │                           │
         └───────────┬───────────┘───────────────────────────┘
                     ▼
         ┌───────────────────────┐
         │   Parse & Enrich      │  ← PQC Risk Engine classifies each asset
         │   CycloneDX 1.6 CBOM  │
         └───────────┬───────────┘
                     ▼
         ┌───────────────────────────────────────────────────┐
         │              Dashboard Visualization               │
         │  ┌──────────┬──────────┬──────────┬──────────┐   │
         │  │ Quantum  │ Bubble   │ Primit-  │ Crypto   │   │
         │  │ Safety   │ Chart    │ ives     │ Functions│   │
         │  │ Donut    │          │ Donut    │ Donut    │   │
         │  └──────────┴──────────┴──────────┴──────────┘   │
         │  ┌────────────────────┬──────────────────────┐   │
         │  │ Readiness Score    │ Network TLS Scanner  │   │
         │  │ (0–100 circular)   │ (live endpoint scan) │   │
         │  └────────────────────┴──────────────────────┘   │
         │  ┌────────────────────────────────────────────┐   │
         │  │ Asset List (sortable, filterable, paginated)│   │
         │  └────────────────────────────────────────────┘   │
         └───────────────────────────────────────────────────┘
```

---

## Why Does This Exist?

### The Quantum Threat

Quantum computers running **Shor's algorithm** will be able to break:
- **RSA** (all key sizes)
- **ECC/ECDSA/ECDH** (all curves)
- **DH** (Diffie-Hellman)
- **DSA**
- **Ed25519/EdDSA**

Quantum computers running **Grover's algorithm** will halve the effective security of:
- **AES-128** → effectively 64-bit (breakable)
- **AES-256** → effectively 128-bit (still safe)
- **SHA-256** → effectively 128-bit collision resistance (still safe)

### Why a CBOM?

Most organizations have **no idea** what cryptography their software uses. A typical enterprise application might use 30–60 different crypto algorithms scattered across hundreds of files and 50+ dependencies. When quantum computers arrive, these organizations won't know:

1. **What** crypto they use
2. **Where** it's used in the codebase
3. **Which** algorithms are vulnerable
4. **What** to replace them with

A CBOM answers all four questions.

### Why This Tool?

Existing options like IBM's CBOMkit are good but limited. QuantumGuard differentiates by:

- **Code + Network scanning** in one tool (not just static analysis)
- **Live TLS endpoint scanning** to discover runtime crypto
- **PQC risk scoring** with specific NIST-approved replacement recommendations
- **Beautiful dashboard** inspired by the IBM CBOMkit aesthetic
- **Offline capable** — the frontend works without the backend (client-side parsing)

---

## Features

| Feature | Description |
|---------|-------------|
| **CBOM Upload & Parse** | Upload CycloneDX 1.6 CBOM JSON files |
| **Code Scanning** | Regex-based scanning for Java, Python, TypeScript crypto APIs |
| **Network TLS Scanner** | Scan live endpoints for TLS/cipher details |
| **Sonar-Cryptography Integration** | Optional deep analysis via IBM's sonar plugin |
| **PQC Risk Engine** | Flag quantum-vulnerable algorithms and suggest replacements |
| **Interactive Dashboard** | Donut charts, bubble charts, asset lists, compliance banners |
| **GitHub Action** | Integrate into CI/CD pipelines |
| **Exclude Patterns** | Skip test files, mocks, and fixtures from scans |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    MONOREPO ROOT                         │
│  package.json (npm workspaces: backend, frontend)       │
├────────────────────────┬────────────────────────────────┤
│                        │                                │
│   BACKEND (Node.js)    │    FRONTEND (React + Vite)     │
│   Port 3001            │    Port 5173 (dev) / 80 (prod) │
│                        │                                │
│  ┌──────────────────┐  │  ┌──────────────────────────┐  │
│  │ Express Server   │  │  │ React 18 + TypeScript    │  │
│  │ ├─ CBOM Routes   │  │  │ ├─ Dashboard Layout      │  │
│  │ ├─ Network Routes│◄─┼──┤ ├─ 10 Components         │  │
│  │ └─ Scan Routes   │  │  │ ├─ 4 Chart Visualizations│  │
│  ├──────────────────┤  │  │ ├─ Upload/Scan UI        │  │
│  │ Services         │  │  │ └─ Client-side Fallback  │  │
│  │ ├─ PQC Risk Eng. │  │  └──────────────────────────┘  │
│  │ ├─ Network Scan  │  │                                │
│  │ └─ Aggregator    │  │  Tailwind CSS (dark theme)     │
│  ├──────────────────┤  │  Recharts (visualizations)     │
│  │ Types (CycloneDX)│  │  Lucide (icons)                │
│  └──────────────────┘  │                                │
│                        │                                │
├────────────────────────┴────────────────────────────────┤
│  Docker Compose (backend:3001, frontend:nginx:80)       │
└─────────────────────────────────────────────────────────┘
```

**Communication:** Frontend calls backend REST API at `/api/*`. In development, Vite proxies requests. In production, nginx reverse-proxies to the backend container. If the backend is unreachable, the frontend **falls back to client-side parsing**.

---

## Core Concepts & Terminology

| Term | Definition |
|------|-----------|
| **CBOM** | Cryptographic Bill of Materials — a machine-readable inventory of all cryptographic assets |
| **CycloneDX 1.6** | An OWASP-backed open standard for BOMs with crypto-specific properties |
| **PQC** | Post-Quantum Cryptography — algorithms designed to resist quantum computer attacks |
| **ML-KEM (Kyber)** | NIST FIPS 203. Replaces RSA/ECDH for key encapsulation |
| **ML-DSA (Dilithium)** | NIST FIPS 204. Replaces RSA/ECDSA/Ed25519 for digital signatures |
| **SLH-DSA (SPHINCS+)** | NIST FIPS 205. Hash-based signature scheme |
| **Quantum Safe** | An algorithm not known to be breakable by quantum computers |
| **Not Quantum Safe** | An algorithm that WILL be broken by a sufficiently powerful quantum computer |
| **Crypto Primitive** | The category: hash, block-cipher, signature, key-agreement, etc. |
| **Crypto Function** | The operation: Hash, Encrypt, Decrypt, Sign, Verify, Keygen, etc. |

---

## Project Structure

```
cbom-analyser/
├── backend/                        # Node.js + Express backend
│   └── src/
│       ├── index.ts                # Express entry point (port 3001)
│       ├── types/cbom.types.ts     # CycloneDX 1.6 TypeScript interfaces
│       ├── services/
│       │   ├── pqcRiskEngine.ts    # Quantum safety classification
│       │   ├── networkScanner.ts   # Live TLS endpoint scanning
│       │   └── scannerAggregator.ts# Code scanning + CBOM merging
│       └── routes/
│           ├── cbomRoutes.ts       # Upload, list, get CBOMs
│           ├── networkRoutes.ts    # Network TLS scanning
│           └── scanRoutes.ts       # Code scanning endpoints
│
├── frontend/                       # React + Vite frontend
│   └── src/
│       ├── App.tsx                 # Main app: state + dashboard layout
│       ├── sampleData.ts           # 58 crypto assets for demo
│       └── components/
│           ├── CBOMUploader.tsx    # Drag-and-drop JSON upload
│           ├── QuantumSafetyDonut.tsx
│           ├── PrimitivesDonut.tsx
│           ├── FunctionsDonut.tsx
│           ├── CryptoBubbleChart.tsx
│           ├── ReadinessScoreCard.tsx
│           ├── NetworkScanner.tsx
│           └── AssetListView.tsx
│
├── demo-code/                      # Demo source files with crypto API calls
│   ├── java/
│   ├── python/
│   └── typescript/
│
├── sample-data/                    # Example CBOM JSON files
│
├── .github/workflows/              # CI/CD pipelines
├── action.yml                      # GitHub Action definition
├── Dockerfile.action               # Docker image for GitHub Action
└── docker-compose.yml              # Container orchestration
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Runtime** | Node.js 20+ | JavaScript/TypeScript runtime |
| **Language** | TypeScript | Type-safe development |
| **Backend** | Express.js | REST API server |
| **Frontend** | React 18 + Vite | UI framework + build tool |
| **CSS** | Tailwind CSS | Utility-first dark theme |
| **Charts** | Recharts | Donut, scatter, pie charts |
| **Icons** | Lucide React | Shield, Alert, CheckCircle |
| **Containerization** | Docker + nginx | Production deployment |
| **Monorepo** | npm workspaces | Shared dependencies |

---

## Competitive Differentiators

| Feature | IBM CBOMkit | CycloneDX cdxgen | **QuantumGuard** |
|---------|-------------|-------------------|------------------|
| CBOM Upload & Visualize | ✅ | ❌ | ✅ |
| Code Scanning | ✅ | ✅ | ✅ (with regex fallback) |
| **Network TLS Scanning** | ❌ | ❌ | ✅ |
| **PQC Risk Scoring (0-100)** | ❌ | ❌ | ✅ |
| **PQC Replacement Recommendations** | ❌ | ❌ | ✅ |
| **Offline/Client-side Mode** | ❌ | ❌ | ✅ |
| **Code + Network in 1 tool** | ❌ | ❌ | ✅ |
| **50+ Algorithm PQC Database** | ❌ | ❌ | ✅ |

---

## CycloneDX 1.6 Standard

This project implements the **CycloneDX 1.6** specification for Cryptographic Bill of Materials:

- `cryptoProperties.assetType` — algorithm, protocol, certificate, related-crypto-material
- `cryptoProperties.algorithmProperties` — primitive, mode, padding, curve, cryptoFunctions
- `cryptoProperties.protocolProperties` — TLS version and cipher suites

**Resources:**
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [CycloneDX CBOM Guide](https://cyclonedx.org/capabilities/cbom/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- [IBM sonar-cryptography](https://github.com/IBM/sonar-cryptography)

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

---

## Documentation

| Document | Description |
|----------|-------------|
| **[USAGE.md](USAGE.md)** | Practical guide: GitHub Actions, Docker, API reference, scanning approaches |
| [CycloneDX Spec](https://cyclonedx.org/specification/overview/) | Official CBOM standard documentation |

---

## License

MIT

---

*Built for the post-quantum era.*
