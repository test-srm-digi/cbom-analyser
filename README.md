# QuantumGuard CBOM Hub

**Cryptographic Bill of Materials Scanner & Visualizer**

> Scan your codebase, generate a Cryptographic Bill of Materials (CBOM), and assess your post-quantum cryptography readiness.

## Architecture

```
quantumguard-cbom-hub/
├── backend/          # Node.js/Express API
│   ├── src/
│   │   ├── routes/       # Express route handlers
│   │   ├── services/     # Scanner, PQC engine, CBOM formatter
│   │   ├── types/        # TypeScript interfaces (CycloneDX 1.6)
│   │   └── index.ts      # Entry point
│   └── Dockerfile
├── frontend/         # React + Tailwind + Recharts
│   ├── src/
│   │   ├── components/   # Dashboard, Charts, List, Banner
│   │   ├── types/        # Shared CBOM types
│   │   └── App.tsx
│   └── Dockerfile
├── .github/
│   └── workflows/
│       └── ci.yml        # CI pipeline
├── action.yml            # GitHub Action definition
├── Dockerfile.action     # Docker image for GitHub Action
├── entrypoint.sh         # Action entrypoint script
├── docker-compose.yml
└── sample-data/      # Example CBOM JSONs
```

## Features

- **CBOM Upload & Parse** – Upload CycloneDX 1.6 CBOM JSON files
- **Network TLS Scanner** – Scan live endpoints for TLS/cipher details
- **Sonar-Cryptography Integration** – Trigger code scans via CLI
- **PQC Risk Engine** – Flag quantum-vulnerable algorithms and suggest replacements
- **Interactive Dashboard** – Donut charts, bubble charts, asset lists, compliance banners

## Quick Start

### With Docker
```bash
docker-compose up --build
```

### Without Docker
```bash
# Install all dependencies
npm run install:all

# Start both backend and frontend
npm run dev
```

- Backend: http://localhost:3001
- Frontend: http://localhost:5173

## 🚀 Use as GitHub Action

Add CBOM Analyser to your repository's CI/CD pipeline to automatically scan for post-quantum cryptography readiness on every push or pull request.

### Basic Usage

Create `.github/workflows/cbom-scan.yml` in your repository:

```yaml
name: CBOM Quantum Readiness Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  cbom-scan:
    name: Scan for Quantum Vulnerabilities
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run CBOM Analyser
        id: cbom
        uses: test-srm-digi/cbom-analyser@v1
        with:
          output-format: summary
          output-file: cbom-report.json

      - name: Display Results
        run: |
          echo "🎯 Quantum Readiness Score: ${{ steps.cbom.outputs.readiness-score }}%"
          echo "📦 Total Assets: ${{ steps.cbom.outputs.total-assets }}"
          echo "✅ Quantum-Safe: ${{ steps.cbom.outputs.quantum-safe-assets }}"
          echo "⚠️ Vulnerable: ${{ steps.cbom.outputs.vulnerable-assets }}"
```

### Advanced Usage

```yaml
name: CBOM Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  cbom-scan:
    name: PQC Compliance Check
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run CBOM Analyser
        id: cbom
        uses: test-srm-digi/cbom-analyser@v1
        with:
          # Fail the workflow if non-quantum-safe algorithms are found
          fail-on-vulnerable: 'true'
          
          # Output format: json, sarif, or summary
          output-format: sarif
          
          # Where to save the CBOM report
          output-file: cbom-results.sarif
          
          # Minimum quantum readiness score (0-100) required to pass
          quantum-safe-threshold: '50'
          
          # Scan a specific path within the repo
          scan-path: 'src'

      - name: Upload CBOM Report
        uses: actions/upload-artifact@v4
        with:
          name: cbom-report
          path: cbom-results.sarif

      - name: Check Results
        run: |
          echo "🎯 Readiness Score: ${{ steps.cbom.outputs.readiness-score }}%"
          echo "📦 Total Assets: ${{ steps.cbom.outputs.total-assets }}"
          echo "⚠️ Vulnerable: ${{ steps.cbom.outputs.vulnerable-assets }}"
```

### Upload to GitHub Security Tab

Integrate with GitHub's Security tab for vulnerability tracking:

```yaml
name: CBOM Security Analysis

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  cbom-security:
    name: CBOM Security Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run CBOM Analyser (SARIF)
        uses: test-srm-digi/cbom-analyser@v1
        with:
          output-format: sarif
          output-file: cbom-results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cbom-results.sarif
          category: cbom-quantum-analysis
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `fail-on-vulnerable` | Fail workflow if non-quantum-safe crypto found | `false` |
| `output-format` | Output format: `json`, `sarif`, or `summary` | `summary` |
| `output-file` | Path to save the CBOM report | `cbom-report.json` |
| `quantum-safe-threshold` | Minimum readiness score (0-100) to pass | `0` |
| `scan-path` | Path within repo to scan | `.` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `readiness-score` | Quantum readiness score (0-100) |
| `total-assets` | Total cryptographic assets found |
| `vulnerable-assets` | Number of non-quantum-safe assets |
| `quantum-safe-assets` | Number of quantum-safe assets |
| `cbom-file` | Path to the generated CBOM file |

## CycloneDX 1.6 CBOM Standard

This tool generates and consumes CBOMs following the [CycloneDX 1.6 specification](https://cyclonedx.org/) with cryptographic extensions, enabling:

- Cryptographic algorithm inventory
- Quantum-safety classification
- Dependency mapping to crypto providers
- NIST PQC compliance checking

## References

- [IBM CBOM](https://github.com/IBM/CBOM)
- [CBOMkit Sonar Plugin](https://github.com/cbomkit/sonar-cryptography)
- [CycloneDX Specification](https://cyclonedx.org/)
- [Open Quantum Safe](https://openquantumsafe.org/)




# QuantumGuard CBOM Hub — Detailed Project Documentation

> **Cryptographic Bill of Materials Scanner & Visualizer**
> A full-stack application that scans, parses, and visualizes the cryptographic inventory of any software project — then assesses its readiness for the post-quantum era.

---

## Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [Why Does This Exist?](#2-why-does-this-exist)
3. [Core Concepts & Terminology](#3-core-concepts--terminology)
4. [Architecture Overview](#4-architecture-overview)
5. [Project Structure](#5-project-structure)
6. [Data Model (CycloneDX 1.6 CBOM)](#6-data-model-cyclonedx-16-cbom)
7. [Backend — Deep Dive](#7-backend--deep-dive)
   - 7.1 [Express Server & Routes](#71-express-server--routes)
   - 7.2 [PQC Risk Engine](#72-pqc-risk-engine)
   - 7.3 [Network TLS Scanner](#73-network-tls-scanner)
   - 7.4 [Scanner Aggregator](#74-scanner-aggregator)
8. [Frontend — Deep Dive](#8-frontend--deep-dive)
   - 8.1 [App Component & State Management](#81-app-component--state-management)
   - 8.2 [Dashboard Components](#82-dashboard-components)
   - 8.3 [Visualization Charts](#83-visualization-charts)
9. [API Reference](#9-api-reference)
10. [Sample Data & Demo Code](#10-sample-data--demo-code)
11. [Approaches to Generate a CBOM from GitHub Repos](#11-approaches-to-generate-a-cbom-from-github-repos)
12. [Docker & Deployment](#12-docker--deployment)
13. [Technology Stack](#13-technology-stack)
14. [How to Run](#14-how-to-run)
15. [Competitive Differentiators](#15-competitive-differentiators)

---

## 1. What Is This Project?

**QuantumGuard CBOM Hub** is a web application that produces and visualizes a **Cryptographic Bill of Materials (CBOM)** — a structured inventory of every cryptographic algorithm, protocol, certificate, and key used by a software project.

Think of it like an SBOM (Software Bill of Materials), but specifically for cryptography. Instead of listing software dependencies, a CBOM lists every use of SHA-256, RSA-2048, AES-128, TLS 1.2, etc., and maps where each one is used in the codebase.

The application then goes a step further: it evaluates every cryptographic asset against **Post-Quantum Cryptography (PQC) standards** — telling you which algorithms will be broken by quantum computers and what NIST-approved replacements you should migrate to.

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

## 2. Why Does This Exist?

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

Most organizations have **no idea** what cryptography their software uses. A typical enterprise Java application might use 30–60 different crypto algorithms scattered across hundreds of files and 50+ dependencies. When quantum computers arrive, these organizations won't know:

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

## 3. Core Concepts & Terminology

| Term | Definition |
|------|-----------|
| **CBOM** | Cryptographic Bill of Materials — a machine-readable inventory of all cryptographic assets in a software project |
| **CycloneDX 1.6** | An OWASP-backed open standard for BOMs. Version 1.6 added crypto-specific properties (`cryptoProperties`) |
| **PQC** | Post-Quantum Cryptography — algorithms designed to resist quantum computer attacks |
| **ML-KEM (Kyber)** | NIST FIPS 203. Replaces RSA/ECDH for key encapsulation |
| **ML-DSA (Dilithium)** | NIST FIPS 204. Replaces RSA/ECDSA/Ed25519 for digital signatures |
| **SLH-DSA (SPHINCS+)** | NIST FIPS 205. Hash-based signature scheme, alternative to ML-DSA |
| **Shor's Algorithm** | Quantum algorithm that breaks RSA, ECC, DH in polynomial time |
| **Grover's Algorithm** | Quantum algorithm that provides quadratic speedup for brute-force search (halves symmetric key security) |
| **Quantum Safe** | An algorithm that is not known to be breakable by quantum computers |
| **Not Quantum Safe** | An algorithm that WILL be broken by a sufficiently powerful quantum computer |
| **Crypto Asset** | A single use of a crypto algorithm/protocol/certificate at a specific location in code |
| **Crypto Primitive** | The category of an algorithm: hash, block-cipher, signature, key-agreement, etc. |
| **Crypto Function** | What the algorithm is doing: Hash, Encrypt, Decrypt, Sign, Verify, Keygen, etc. |

---

## 4. Architecture Overview

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

**Communication:** Frontend calls backend REST API at `/api/*`. In development, Vite proxies these requests. In production, nginx reverse-proxies to the backend container. If the backend is unreachable, the frontend **falls back to client-side parsing** — so the dashboard works even offline.

---

## 5. Project Structure

```
cbom-analyser/
├── package.json                    # Monorepo root (npm workspaces)
├── README.md                       # Quick-start README
├── PROJECT_DOCUMENTATION.md        # This file
├── docker-compose.yml              # Docker orchestration
│
├── backend/                        # Node.js + Express backend
│   ├── package.json
│   ├── tsconfig.json
│   ├── Dockerfile
│   └── src/
│       ├── index.ts                # Express entry point (port 3001)
│       ├── types/
│       │   └── cbom.types.ts       # CycloneDX 1.6 TypeScript interfaces (262 lines)
│       ├── services/
│       │   ├── index.ts            # Barrel export
│       │   ├── pqcRiskEngine.ts    # Quantum safety classification (306 lines)
│       │   ├── networkScanner.ts   # Live TLS endpoint scanning (170 lines)
│       │   └── scannerAggregator.ts# Code scanning + CBOM merging (306 lines, 35 regex patterns)
│       └── routes/
│           ├── index.ts            # Barrel export
│           ├── cbomRoutes.ts       # Upload, list, get CBOMs (131 lines)
│           ├── networkRoutes.ts    # Network TLS scanning (139 lines)
│           └── scanRoutes.ts       # Code scanning endpoints (92 lines)
│
├── frontend/                       # React + Vite frontend
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts              # Vite config with /api proxy
│   ├── tailwind.config.js          # Custom dark theme (QuantumGuard palette)
│   ├── postcss.config.js
│   ├── index.html
│   ├── Dockerfile
│   ├── nginx.conf                  # Production SPA routing + API proxy
│   └── src/
│       ├── main.tsx                # React entry point
│       ├── App.tsx                 # Main app: state management + dashboard layout
│       ├── index.css               # Tailwind imports + custom animations
│       ├── sampleData.ts           # 58 crypto assets mimicking Keycloak CBOM
│       ├── types/
│       │   └── cbom.ts             # Frontend mirror of backend CBOM types
│       └── components/
│           ├── index.ts            # Barrel export
│           ├── CBOMUploader.tsx     # Drag-and-drop JSON file upload
│           ├── CBOMHeader.tsx       # Project name, version, asset count
│           ├── ComplianceBanner.tsx # Red/green NIST PQC compliance banner
│           ├── QuantumSafetyDonut.tsx   # Donut: quantum-safe vs not-safe
│           ├── PrimitivesDonut.tsx      # Donut: hash, pke, signature, etc.
│           ├── FunctionsDonut.tsx       # Donut: Encrypt, Sign, Hash, etc.
│           ├── CryptoBubbleChart.tsx    # Scatter/bubble: algorithm distribution
│           ├── ReadinessScoreCard.tsx   # Circular progress: 0–100 PQC score
│           ├── NetworkScanner.tsx       # URL input for live TLS scanning
│           └── AssetListView.tsx        # Sortable, filterable, paginated table
│
├── demo-code/                      # Demo source files with real crypto API calls
│   ├── java/
│   │   ├── CryptoService.java      # SHA-256, SHA-1, MD5, AES, RSA, ECDSA
│   │   └── AuthenticationModule.java # Password hashing, token signing, channel encryption
│   ├── python/
│   │   └── crypto_utils.py         # hashlib, PyCryptodome AES, RSA, EC keys, HMAC
│   └── typescript/
│       └── cryptoUtils.ts          # Node.js crypto: hash, HMAC, AES, RSA, ECDH, PBKDF2, scrypt
│
└── sample-data/                    # Example CBOM JSON files
    ├── keycloak-cbom.json          # 8 assets from Keycloak
    └── spring-petclinic-cbom.json  # 34 assets from Spring PetClinic
```

---

## 6. Data Model (CycloneDX 1.6 CBOM)

The entire application revolves around the **CycloneDX 1.6 CBOM document** format. Here's the complete type hierarchy:

### 6.1 Top-Level CBOM Document

```typescript
interface CBOMDocument {
  bomFormat: 'CycloneDX';        // Always "CycloneDX"
  specVersion: '1.6';            // CycloneDX version
  serialNumber?: string;          // UUID identifier, e.g. "urn:uuid:..."
  version: number;                // BOM version (starts at 1)
  metadata: CBOMMetadata;         // When, who, what was scanned
  components: CBOMComponent[];    // Software components (libs, frameworks)
  cryptoAssets: CryptoAsset[];    // THE KEY PART — crypto inventory
  dependencies?: CryptoDependency[]; // Which libs provide which crypto
}
```

### 6.2 Crypto Asset (The Core Object)

Every row in the dashboard represents one `CryptoAsset`:

```typescript
interface CryptoAsset {
  id: string;                     // Unique identifier
  name: string;                   // e.g. "AES-256-GCM", "RSA-2048", "TLS 1.3"
  type: string;                   // "crypto-asset", "network", etc.
  version?: string;
  description?: string;
  cryptoProperties: {
    assetType: 'algorithm' | 'protocol' | 'certificate' | 'related-crypto-material';
    algorithmProperties?: {
      primitive: 'hash' | 'block-cipher' | 'signature' | 'pke' | 'ae' | 'mac' | ...;
      mode?: string;              // "GCM", "CBC", etc.
      padding?: string;           // "PKCS5Padding", etc.
      curve?: string;             // "P-256", "Curve25519", etc.
      cryptoFunctions?: string[]; // ["Encrypt", "Decrypt"], ["Sign", "Verify"], etc.
    };
    protocolProperties?: {
      type: string;               // "tls"
      version: string;            // "1.3", "1.2"
      cipherSuites?: { name: string; algorithms?: string[] }[];
    };
  };
  location?: {
    fileName: string;             // "SecurityConfig.java"
    lineNumber?: number;          // 47
    className?: string;           // "SecurityConfig"
    methodName?: string;          // "passwordEncoder"
  };
  quantumSafety: 'quantum-safe' | 'not-quantum-safe' | 'unknown';
  keyLength?: number;             // 128, 256, 2048, 4096
  recommendedPQC?: string;        // "ML-KEM (Kyber-768)"
  complianceStatus?: 'compliant' | 'not-compliant' | 'unknown';
}
```

### 6.3 Classification Enums

| Enum | Values | Purpose |
|------|--------|---------|
| `QuantumSafetyStatus` | `quantum-safe`, `not-quantum-safe`, `unknown` | Is this algorithm safe from quantum attacks? |
| `CryptoPrimitive` | `hash`, `block-cipher`, `stream-cipher`, `mac`, `signature`, `key-encapsulation`, `key-agreement`, `key-derivation`, `pke`, `ae`, `other` | What category of cryptography |
| `CryptoFunction` | `Hash Function`, `Keygen`, `Encrypt`, `Decrypt`, `Sign`, `Verify`, `Key Exchange`, `Digest`, `Tag`, `Other` | What operation the algorithm performs |
| `AssetType` | `algorithm`, `protocol`, `certificate`, `related-crypto-material` | What kind of crypto asset |
| `ComplianceStatus` | `compliant`, `not-compliant`, `unknown` | Does it pass NIST PQC policy? |

---

## 7. Backend — Deep Dive

### 7.1 Express Server & Routes

**File:** `backend/src/index.ts`

The backend is a standard Express.js server on port 3001 with:
- **CORS** configured for `http://localhost:5173` (Vite dev server)
- **JSON body limit** of 50MB (CBOMs can be large)
- Three route groups mounted under `/api`

#### Route Groups

| Route File | Endpoints | Purpose |
|-----------|-----------|---------|
| `cbomRoutes.ts` | `POST /api/upload`, `POST /api/upload/raw`, `GET /api/cbom/list`, `GET /api/cbom/:id` | CBOM file upload (multipart & raw JSON), storage, retrieval |
| `networkRoutes.ts` | `POST /api/scan-network`, `POST /api/scan-network/batch`, `POST /api/scan-network/merge/:cbomId` | Live TLS endpoint scanning |
| `scanRoutes.ts` | `POST /api/scan-code`, `POST /api/scan-code/regex` | Source code scanning with sonar-cryptography or regex fallback |

**How Upload Works:**

1. User uploads a `.json` file via `POST /api/upload` (multipart form)
2. `multer` middleware reads the file into memory
3. `parseCBOMFile()` parses the JSON (supports both our format and standard CycloneDX)
4. Each crypto asset is enriched via `enrichAssetWithPQCData()` — filling in quantum safety, compliance, and PQC recommendations
5. `calculateReadinessScore()` computes a 0–100 quantum readiness score
6. `checkNISTPQCCompliance()` checks against NIST PQC policy
7. The full response (CBOM + score + compliance) is returned

**Storage:** CBOMs are stored in an in-memory `Map<string, CBOMDocument>`. In production you'd replace this with a database.

---

### 7.2 PQC Risk Engine

**File:** `backend/src/services/pqcRiskEngine.ts` (306 lines)

This is the brain of the project. It contains:

#### Algorithm Classification Database

A lookup table mapping **50+ algorithms** to their quantum safety status:

```
RSA, RSA-2048, RSA-4096    → NOT_QUANTUM_SAFE  → Replace with ML-KEM (Kyber)
ECC, ECDSA, ECDH, Ed25519  → NOT_QUANTUM_SAFE  → Replace with ML-DSA (Dilithium)
DSA, DH, SSL               → NOT_QUANTUM_SAFE  → Replace with PQC equivalents
AES-128                     → NOT_QUANTUM_SAFE  → Replace with AES-256
AES-256, AES                → QUANTUM_SAFE      → 128-bit effective security with Grover
SHA-256, SHA-384, SHA-512   → QUANTUM_SAFE      → Sufficient collision resistance
SHA-1, MD5                  → NOT_QUANTUM_SAFE  → Classically broken (not just quantum)
HMACSHA256/384/512          → QUANTUM_SAFE
CHACHA20                    → QUANTUM_SAFE
ML-KEM, ML-DSA, SLH-DSA    → QUANTUM_SAFE      → NIST post-quantum standards
TLSv1.0–1.3                → NOT_QUANTUM_SAFE  → Key exchange is not PQC yet
```

#### Key Functions

| Function | Input | Output | Purpose |
|----------|-------|--------|---------|
| `classifyAlgorithm(name)` | Algorithm name string | `AlgorithmProfile` with quantum safety + recommendation | Looks up algorithm in database with exact → case-insensitive → partial matching |
| `enrichAssetWithPQCData(asset)` | `CryptoAsset` | Enriched `CryptoAsset` with quantum safety, compliance, PQC recommendation filled in | The main enrichment function called for every asset |
| `calculateReadinessScore(assets)` | Array of `CryptoAsset` | `QuantumReadinessScore` (0–100) | Score formula: `(safe + unknown*0.5) / total * 100` |
| `checkNISTPQCCompliance(assets)` | Array of `CryptoAsset` | `ComplianceSummary` | Returns compliant only if `nonCompliantAssets === 0` |

#### Why This Matters

Without this engine, a CBOM is just a list of algorithm names. The PQC Risk Engine transforms it into actionable intelligence:
- "Your RSA-2048 at JwtKeyProvider.java:63 → **replace with ML-KEM (Kyber-768)**"
- "Your overall score is **56/100** — you have significant quantum risk"

---

### 7.3 Network TLS Scanner

**File:** `backend/src/services/networkScanner.ts` (170 lines)

This is what makes QuantumGuard unique — it can scan **live network endpoints** to discover their TLS configuration.

#### How It Works

```
                User enters "github.com"
                         │
                         ▼
            ┌──────────────────────┐
            │  https.request()     │  ← Node.js TLS/HTTPS module
            │  rejectUnauthorized: │     connects to port 443
            │  false (for scanning)│     with SNI (Server Name Indication)
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  socket.getCipher()  │  ← Extracts cipher suite name
            │  socket.getProtocol()│  ← Extracts TLS version
            │  socket.getPeerCert()│  ← Gets server certificate
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  NetworkScanResult   │  ← Structured result:
            │  {                   │     protocol: "TLSv1.3"
            │    cipherSuite,      │     cipher: "TLS_AES_256_GCM_SHA384"
            │    protocol,         │     isQuantumSafe: false
            │    isQuantumSafe,    │
            │    host, port        │
            │  }                   │
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  networkResultTo     │  ← Converts to CycloneDX CryptoAsset
            │  CBOMAsset()         │     assetType: "protocol"
            │                      │     Parses cipher suite into
            │                      │     individual algorithm names
            └──────────────────────┘
```

#### Cipher Suite Parsing

The function `extractAlgorithmsFromCipher()` breaks down cipher suite strings:
- `TLS_AES_256_GCM_SHA384` → `["AES-256", "GCM", "SHA-384"]`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` → `["ECDHE", "RSA", "AES-128", "GCM", "SHA-256"]`

#### Batch Scanning

`scanMultipleHosts()` runs `Promise.allSettled()` across an array of hosts — so one failure doesn't block the others.

---

### 7.4 Scanner Aggregator

**File:** `backend/src/services/scannerAggregator.ts` (260 lines)

The aggregator orchestrates all scanning and merging:

#### Scanning Pipeline

1. **Sonar-Cryptography Integration** (primary)
   - Checks if `sonar-scanner` CLI is installed
   - If yes: runs `sonar-scanner` against the repo, reads the CBOM report from `.scannerwork/cbom-report.json`
   - If no: falls back to regex scanning

2. **Regex-Based Fallback Scanner** (always available)
   - Scans `.java`, `.py`, `.js`, `.ts`, `.jsx`, `.tsx` files
   - Excludes `node_modules/`, `dist/`, `build/`, `.git/` directories
   - Applies **35 regex patterns** that detect crypto API calls across Java, Python, and Node.js/TypeScript:

   **Java Patterns (9):**

   | Pattern | Detects |
   |---------|---------|
   | `MessageDigest.getInstance("SHA-256")` | Java SHA-256 hashing |
   | `MessageDigest.getInstance("SHA-1")` | Java SHA-1 hashing |
   | `MessageDigest.getInstance("MD5")` | Java MD5 hashing |
   | `KeyPairGenerator.getInstance("RSA")` | Java RSA key generation |
   | `Cipher.getInstance("AES...")` | Java AES encryption |
   | `Cipher.getInstance("RSA...")` | Java RSA encryption |
   | `KeyGenerator.getInstance("AES")` | Java AES key generation |
   | `Signature.getInstance("SHA256withRSA")` | Java RSA signing |
   | `Signature.getInstance("SHA256withECDSA")` | Java ECDSA signing |

   **Python Patterns (8):**

   | Pattern | Detects |
   |---------|---------|
   | `hashlib.sha256` | Python SHA-256 hashing |
   | `hashlib.sha1` | Python SHA-1 hashing |
   | `hashlib.md5` | Python MD5 hashing |
   | `from Crypto.Cipher import AES` | Python AES encryption (PyCryptodome) |
   | `RSA.generate` | Python RSA key generation (PyCryptodome) |
   | `from cryptography.hazmat...import...rsa` | Python RSA usage (cryptography lib) |
   | `from cryptography.hazmat...import...ec` | Python ECC usage (cryptography lib) |
   | `hmac.new(...hashlib.sha256)` | Python HMAC-SHA256 |

   **Node.js / TypeScript Patterns (18):**

   | Pattern | Detects |
   |---------|---------|
   | `crypto.createHash('sha256')` | Node.js SHA-256 hashing |
   | `crypto.createHash('sha512')` | Node.js SHA-512 hashing |
   | `crypto.createHash('sha1')` | Node.js SHA-1 hashing |
   | `crypto.createHash('md5')` | Node.js MD5 hashing |
   | `crypto.createCipheriv('aes-256-...')` | Node.js AES-256 encryption |
   | `crypto.createCipheriv('aes-128-...')` | Node.js AES-128 encryption |
   | `crypto.createDecipheriv('aes-...')` | Node.js AES decryption |
   | `crypto.generateKeyPairSync('rsa', ...)` | Node.js RSA key generation |
   | `crypto.generateKeyPairSync('ec', ...)` | Node.js EC key generation |
   | `crypto.createSign('SHA256')` | Node.js RSA-SHA256 signing |
   | `crypto.createHmac('sha256', ...)` | Node.js HMAC-SHA256 |
   | `crypto.createHmac('sha512', ...)` | Node.js HMAC-SHA512 |
   | `crypto.randomBytes(...)` | Node.js CSPRNG |
   | `crypto.pbkdf2Sync(...)` | Node.js PBKDF2 key derivation |
   | `crypto.scryptSync(...)` | Node.js scrypt key derivation |
   | `crypto.createDiffieHellman(...)` | Node.js Diffie-Hellman key exchange |
   | `crypto.createECDH(...)` | Node.js ECDH key exchange |
   | `crypto.subtle. / new SubtleCrypto` | WebCrypto API usage |

   For each match, it records:
   - Algorithm name
   - Primitive (hash, pke, block-cipher, signature)
   - Crypto function (Hash, Keygen, Encrypt, Sign)
   - File path and line number

3. **CBOM Parsing** (for uploads)
   - Supports our enriched format (with `cryptoAssets` array)
   - Supports standard CycloneDX 1.6 (where crypto info is in `components[].cryptoProperties`)
   - Auto-enriches every asset with PQC data

4. **Merge Logic**
   - `mergeCBOMs()` combines a base CBOM with additional assets (e.g., from network scans)
   - `runFullScan()` orchestrates: code scan → network scan → merge → return unified CBOM

---

## 8. Frontend — Deep Dive

### 8.1 App Component & State Management

**File:** `frontend/src/App.tsx` (274 lines)

The `App` component is the top-level orchestrator. It manages three pieces of state:

```typescript
const [cbom, setCbom] = useState<CBOMDocument | null>(null);
const [readinessScore, setReadinessScore] = useState<QuantumReadinessScore | null>(null);
const [compliance, setCompliance] = useState<ComplianceSummary | null>(null);
```

#### User Flows

| Action | What Happens |
|--------|-------------|
| **Upload CBOM file** | `handleUpload()` → sends to `POST /api/upload` → backend enriches & scores → updates all 3 state variables → dashboard renders |
| **Upload (backend down)** | `handleUpload()` catches error → calls `handleLocalParse()` → client-side enrichment (basic) → dashboard still renders |
| **Load Sample Data** | `loadSampleData()` → uses built-in `SAMPLE_CBOM` (58 assets) → calls `handleLocalParse()` → instant dashboard |
| **Network Scan** | `handleNetworkScan()` → appends scanned TLS asset to existing CBOM → recalculates score & compliance → dashboard updates live |
| **Upload Another** | A second `CBOMUploader` appears at the bottom of the dashboard |

#### Client-Side Fallback

The `handleLocalParse()` function is key for offline operation. If the backend is unreachable:
- It parses the JSON directly
- Maps standard CycloneDX `components[].cryptoProperties` to our `cryptoAssets[]` format
- Computes readiness score client-side: `(safe + unknown * 0.5) / total * 100`
- Computes compliance client-side: `nonCompliantAssets === 0 → compliant`

---

### 8.2 Dashboard Components

#### CBOMHeader (`CBOMHeader.tsx`)
- Shows the project name (e.g., `spring-projects/spring-petclinic`)
- Shows version, total asset count, scan timestamp
- Pulls from `cbom.metadata.component`

#### ComplianceBanner (`ComplianceBanner.tsx`)
- Full-width banner at the top of the dashboard
- **Green** with checkmark icon → "This CBOM complies with NIST PQC policy"
- **Red** with alert icon (pulsing) → "This CBOM does NOT comply with NIST PQC policy"
- Shows the compliance source

#### ReadinessScoreCard (`ReadinessScoreCard.tsx`)
- **Circular SVG progress ring** showing 0–100 score
- Color: Green (≥80), Yellow (≥50), Red (<50)
- Labels: "Good", "Moderate", "At Risk"
- Breakdown: `X quantum-safe`, `Y not quantum-safe`, `Z unknown`
- SVG is animated with `strokeDashoffset` transition

#### CBOMUploader (`CBOMUploader.tsx`)
- **Drag-and-drop** zone using `react-dropzone`
- Accepts `.json` files only
- Shows file icon and instructional text
- Loading state with spinner

#### NetworkScanner (`NetworkScanner.tsx`)
- URL input field + "Scan" button
- Calls `POST /api/scan-network` and returns the result to the parent
- Shows scanned cipher suite and protocol on success
- Error handling for unreachable hosts

#### AssetListView (`AssetListView.tsx`)
- **Table** showing all crypto assets
- Columns: Name, Type, Primitive, Functions, Location (file:line), Quantum Safety, Recommended PQC
- **Sortable** by clicking column headers
- **Filterable** by quantum safety status (dropdown)
- **Paginated** (10 per page)
- Quantum safety shown as colored badges (green/red/gray)

---

### 8.3 Visualization Charts

All charts use **Recharts** library with a dark theme matching the QuantumGuard palette.

#### QuantumSafetyDonut (`QuantumSafetyDonut.tsx`)
- **Donut chart** showing 3 segments:
  - 🟢 Quantum Safe (green `#3fb950`)
  - 🔴 Not Quantum Safe (red `#f85149`)
  - ⚪ Unknown (gray `#8b949e`)
- Center label shows total asset count
- Percentage labels on slices

#### PrimitivesDonut (`PrimitivesDonut.tsx`)
- **Donut chart** breaking down assets by cryptographic primitive:
  - Hash, Block Cipher, Signature, PKE (Public Key Encryption), AE (Authenticated Encryption), MAC, Key Agreement, Key Derivation, Key Encapsulation, Other
- Each primitive has a distinct color

#### FunctionsDonut (`FunctionsDonut.tsx`)
- **Donut chart** breaking down by crypto function:
  - Hash Function, Encrypt, Decrypt, Sign, Verify, Keygen, Key Exchange, Digest, Tag, Other
- Shows the operational profile of the codebase

#### CryptoBubbleChart (`CryptoBubbleChart.tsx`)
- **Scatter/bubble chart** where:
  - Each bubble = one unique algorithm
  - Bubble size = number of occurrences
  - Colors distinguish algorithms
- Custom tooltip shows algorithm name and count
- Useful for seeing which algorithms dominate

---

## 9. API Reference

### CBOM Management

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/upload` | Multipart form, field `cbom` (JSON file) | `{ success, cbom, readinessScore, compliance }` |
| `POST` | `/api/upload/raw` | Raw JSON body (CBOM document) | Same as above |
| `GET` | `/api/cbom/list` | — | `{ success, cboms: [{ id, component, assetCount, timestamp }] }` |
| `GET` | `/api/cbom/:id` | — | `{ success, cbom, readinessScore, compliance }` |

### Network Scanning

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/scan-network` | `{ url, port? }` | `{ success, result, cbomAsset }` |
| `POST` | `/api/scan-network/batch` | `{ hosts: [{ host, port? }] }` | `{ success, results, cbomAssets, errors }` |
| `POST` | `/api/scan-network/merge/:cbomId` | `{ url, port? }` | Updated CBOM with network asset merged |

### Code Scanning

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| `POST` | `/api/scan-code` | `{ repoPath }` | `{ success, cbomId, cbom, readinessScore, compliance }` |
| `POST` | `/api/scan-code/regex` | `{ repoPath }` | Same (regex scanner only, no sonar) |

### Health

| Method | Endpoint | Response |
|--------|----------|----------|
| `GET` | `/api/health` | `{ status: 'ok', service, version, timestamp }` |

---

## 10. Sample Data & Demo Code

### Pre-Built CBOM Files

#### keycloak-cbom.json (8 assets)
A minimal CBOM simulating a Keycloak scan:
- SHA-256 (×2), RSA-2048, Ed25519, AES-256-GCM, AES-128-GCM, HMACSHA256, SHA-1

#### spring-petclinic-cbom.json (34 assets)
A comprehensive CBOM simulating a Spring PetClinic scan with:
- **Hashes:** SHA-256 (×2), SHA-384, SHA-512, SHA-1, MD5, BCrypt, SHA3-256
- **Symmetric:** AES-256-GCM (×2), AES-128-CBC, ChaCha20-Poly1305
- **Asymmetric:** RSA-2048, RSA-4096, EC-P256, EC-P384, Ed25519, DSA-1024
- **MACs:** HMAC-SHA256 (×2), HMAC-SHA512
- **Key Derivation:** PBKDF2-HMAC-SHA256, HKDF-SHA256
- **Key Agreement:** ECDH-P256, DH-2048
- **Protocols:** TLS 1.3, TLS 1.2 (with cipher suites)
- **Certificates:** X.509-RSA-2048, X.509-EC-P256
- **PRNG:** SecureRandom (SHA1PRNG), SecureRandom (NativePRNG)
- **PQC:** ML-KEM-768 (Kyber), ML-DSA-65 (Dilithium)
- **Legacy:** 3DES, DSA-1024, SHA-1, MD5

#### sampleData.ts (58 assets, embedded in frontend)
The built-in sample data loaded when clicking "sample CBOM file" on the landing page. Mimics a Keycloak scan with the most variety — used for the demo.

### Demo Source Code (`demo-code/`)

The `demo-code/` directory contains real source files with actual crypto API calls that the built-in regex scanner detects. These files are provided so that scanning the project itself produces a meaningful CBOM with 40+ assets.

#### `demo-code/java/CryptoService.java`
A Java service class demonstrating:
- `MessageDigest.getInstance("SHA-256")` — SHA-256 hashing
- `MessageDigest.getInstance("SHA-1")` — SHA-1 hashing (deprecated)
- `MessageDigest.getInstance("MD5")` — MD5 hashing (broken)
- `KeyGenerator.getInstance("AES")` — AES key generation
- `Cipher.getInstance("AES/GCM/NoPadding")` — AES-GCM encryption
- `KeyPairGenerator.getInstance("RSA")` — RSA key pair generation
- `Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")` — RSA encryption
- `Signature.getInstance("SHA256withRSA")` — RSA digital signatures
- `Signature.getInstance("SHA256withECDSA")` — ECDSA digital signatures
- Full encrypt-then-sign workflow example

#### `demo-code/java/AuthenticationModule.java`
A Java authentication module with:
- Password hashing (SHA-256, MD5)
- Token signing (ECDSA)
- Session cipher (AES/CBC/PKCS5Padding)
- RSA-4096 session key pair generation
- Certificate signature verification (SHA256withRSA)

#### `demo-code/python/crypto_utils.py`
Python crypto utilities featuring:
- `hashlib.sha256`, `hashlib.sha1`, `hashlib.md5` — hash functions
- `from Crypto.Cipher import AES` — PyCryptodome AES-GCM encryption
- `RSA.generate()` — PyCryptodome RSA key generation
- `from cryptography.hazmat...import rsa` — RSA key pair (cryptography lib)
- `from cryptography.hazmat...import ec` — ECDSA key pair and signing
- HMAC-SHA256 computation
- Full secure message exchange workflow

#### `demo-code/typescript/cryptoUtils.ts`
Node.js crypto module patterns:
- `crypto.createHash('sha256'/'sha512'/'sha1'/'md5')` — hashing
- `crypto.createHmac('sha256'/'sha512', ...)` — HMAC
- `crypto.createCipheriv('aes-256-gcm', ...)` — AES-256 encryption
- `crypto.createCipheriv('aes-128-cbc', ...)` — AES-128 encryption
- `crypto.createDecipheriv('aes-256-gcm', ...)` — AES decryption
- `crypto.generateKeyPairSync('rsa', ...)` — RSA key generation
- `crypto.generateKeyPairSync('ec', ...)` — EC key generation
- `crypto.createSign('SHA256')` — RSA-SHA256 signing
- `crypto.pbkdf2Sync(...)` — PBKDF2 key derivation
- `crypto.scryptSync(...)` — scrypt key derivation
- `crypto.createDiffieHellman(...)` — Diffie-Hellman key exchange
- `crypto.createECDH(...)` — ECDH key exchange
- `crypto.randomBytes(...)` — Cryptographic random number generation
- Full secure message workflow (encrypt + sign + HMAC)

### Scanning the Demo Code

```bash
# Scan the entire project (including demo-code/)
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/path/to/cbom-analyser"}' \
  -o cbom-analyser-cbom.json

# Expected result: 40+ cryptographic assets detected
# Then upload cbom-analyser-cbom.json to the dashboard at http://localhost:5173
```

---

## 11. Approaches to Generate a CBOM from GitHub Repos

There are several approaches to generate a real CBOM from an existing GitHub repository. Each has different trade-offs in terms of accuracy, setup complexity, and language coverage.

### Approach 1: Built-In Regex Scanner (Easiest — No Setup)

The **simplest approach** — uses the QuantumGuard regex scanner that's already built into this project. No external tools needed.

```bash
# Clone any GitHub repo
git clone https://github.com/spring-projects/spring-petclinic.git /tmp/petclinic

# Scan it (backend must be running on port 3001)
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/petclinic"}' \
  -o petclinic-cbom.json

# Or use regex-only (skips sonar attempt, slightly faster)
curl -X POST http://localhost:3001/api/scan-code/regex \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/petclinic"}' \
  -o petclinic-cbom.json
```

**How it works:** Runs `find` to locate `.java`, `.py`, `.js`, `.ts`, `.jsx`, `.tsx` files (excluding `node_modules/`, `dist/`, `build/`, `.git/`), then applies **35 regex patterns** to detect cryptographic API calls. Automatically enriches every detected asset with PQC risk classification.

| Pros | Cons |
|------|------|
| Zero setup — works out of the box | Pattern-based, may miss uncommon crypto APIs |
| Fast — scans 500 files in seconds | Doesn't analyze dependencies/transitive crypto |
| Covers Java, Python, Node.js/TypeScript | No bytecode analysis |
| Precise file + line number locations | May produce false positives on commented code |

---

### Approach 2: IBM sonar-cryptography (Most Accurate for Java)

The **gold standard** for Java projects. Uses SonarQube with IBM's cryptography plugin for deep static analysis.

```bash
# 1. Install SonarQube + sonar-cryptography plugin
# See: https://github.com/IBM/sonar-cryptography

# 2. Run the scanner — QuantumGuard auto-detects it
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/petclinic"}'
# If sonar-scanner is on $PATH, QuantumGuard uses it automatically
# and reads the CBOM report from .scannerwork/cbom-report.json
```

**How it works:** The QuantumGuard backend checks if `sonar-scanner` CLI is available. If yes, it runs `sonar-scanner` with the cryptography plugin against the repo. The plugin performs deep analysis — including dataflow, library resolution, and JCA/JCE API tracking. The resulting CBOM report is automatically parsed and enriched.

| Pros | Cons |
|------|------|
| Deep static analysis (dataflow-aware) | Requires SonarQube server + Java SDK |
| Analyzes transitive dependencies | Primarily Java/Python focused |
| High accuracy, low false positives | Slower (minutes for large repos) |
| Industry-standard tooling | Complex setup |

**Setup:**
```bash
# Install SonarQube (via Docker)
docker run -d --name sonarqube -p 9000:9000 sonarqube:lts

# Download sonar-cryptography plugin
# https://github.com/IBM/sonar-cryptography/releases
# Place JAR in sonarqube/extensions/plugins/

# Install sonar-scanner CLI
brew install sonar-scanner   # macOS
# or download from https://docs.sonarqube.org/latest/analyzing-source-code/scanners/sonarscanner/
```

---

### Approach 3: CycloneDX cdxgen (Broadest Language Support)

**cdxgen** is an OWASP tool that generates CycloneDX BOMs (including CBOM data) from source code. It supports 30+ languages.

```bash
# Install cdxgen
npm install -g @cyclonedx/cdxgen

# Generate CBOM from a repo
cd /tmp/petclinic
cdxgen -o cbom.json --type java

# Upload the generated CBOM to QuantumGuard
curl -X POST http://localhost:3001/api/upload/raw \
  -H "Content-Type: application/json" \
  -d @cbom.json
```

**How it works:** cdxgen analyzes `pom.xml`, `build.gradle`, `package.json`, `requirements.txt`, etc. to build a full dependency tree. For some languages it also detects crypto API usage. The CycloneDX 1.6 output includes `cryptoProperties` when available.

| Pros | Cons |
|------|------|
| 30+ language support | Crypto detection not as deep as sonar |
| Dependency-aware (full SBOM + CBOM) | May not find inline crypto API calls |
| Active open-source project | Requires build tools for the target language |
| Standard CycloneDX output | CBOM features are still evolving |

---

### Approach 4: Network TLS Scanner (Runtime Crypto Discovery)

Instead of (or in addition to) scanning source code, scan **live endpoints** to discover what cryptography is actually used at runtime.

```bash
# Scan a single endpoint
curl -X POST http://localhost:3001/api/scan-network \
  -H "Content-Type: application/json" \
  -d '{"url": "github.com", "port": 443}'

# Batch scan multiple endpoints
curl -X POST http://localhost:3001/api/scan-network/batch \
  -H "Content-Type: application/json" \
  -d '{
    "hosts": [
      {"host": "github.com"},
      {"host": "google.com"},
      {"host": "api.stripe.com"},
      {"host": "your-app.herokuapp.com"}
    ]
  }'

# Merge network results into an existing CBOM
curl -X POST http://localhost:3001/api/scan-network/merge/urn:uuid:YOUR-CBOM-ID \
  -H "Content-Type: application/json" \
  -d '{"url": "your-app.com"}'
```

**How it works:** Connects to the target host on the specified port (default 443), completes a TLS handshake, and extracts the cipher suite, TLS protocol version, and server certificate. Parses the cipher suite name (`TLS_AES_256_GCM_SHA384`) into individual algorithm assets (`AES-256`, `GCM`, `SHA-384`).

| Pros | Cons |
|------|------|
| Discovers actual runtime crypto | Only sees what's negotiated, not all supported |
| No source code access needed | Requires network access to target |
| Catches crypto that static analysis misses | Limited to TLS/HTTPS endpoints |
| Can merge with code scan results | Doesn't see internal (non-TLS) crypto |

---

### Approach 5: Combined Approach (Recommended)

For the most complete CBOM, **combine multiple approaches**:

```bash
# Step 1: Clone the repo
git clone https://github.com/your-org/your-app.git /tmp/your-app

# Step 2: Scan the source code
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/your-app"}' \
  -o your-app-cbom.json

# Step 3: Upload the code-scan CBOM
curl -X POST http://localhost:3001/api/upload/raw \
  -H "Content-Type: application/json" \
  -d @your-app-cbom.json
# Note the cbomId from the response

# Step 4: Merge in network scan results
curl -X POST http://localhost:3001/api/scan-network/merge/urn:uuid:YOUR-CBOM-ID \
  -H "Content-Type: application/json" \
  -d '{"url": "your-app.com"}'

# Step 5: Upload the final CBOM to the dashboard
# Open http://localhost:5173 and upload your-app-cbom.json
```

This gives you:
- ✅ All crypto APIs used in source code (regex/sonar)
- ✅ All crypto used on the wire (TLS scanner)
- ✅ PQC risk scores and NIST compliance
- ✅ Actionable migration recommendations

### Comparison Matrix

| Approach | Setup | Speed | Accuracy | Languages | Finds Runtime Crypto |
|----------|-------|-------|----------|-----------|---------------------|
| **Regex Scanner** | None | Fast (seconds) | Medium | Java, Python, JS/TS | No |
| **sonar-cryptography** | High | Slow (minutes) | Very High | Java, Python | No |
| **cdxgen** | Medium | Medium | Medium-High | 30+ languages | No |
| **Network TLS Scanner** | None | Fast (seconds) | High (for TLS) | N/A | Yes |
| **Combined** | Varies | Medium | Highest | All | Yes |

---

## 12. Docker & Deployment

### docker-compose.yml

```yaml
services:
  backend:
    build: ./backend
    ports: ["3001:3001"]
    volumes: [./sample-data:/app/sample-data]

  frontend:
    build: ./frontend
    ports: ["8080:80"]           # nginx serves on port 80 inside container
    depends_on: [backend]
```

### Backend Dockerfile
- Multi-stage: `node:20-alpine` → build TypeScript → run with Node
- Exposes port 3001

### Frontend Dockerfile
- Stage 1: `node:20-alpine` → `npm run build` (Vite produces static files)
- Stage 2: `nginx:alpine` → serves built files with SPA routing
- `nginx.conf` routes `/api/*` to `backend:3001` (Docker network)

### Production URLs
- Frontend: `http://localhost:8080`
- Backend API: `http://localhost:3001` (or proxied through nginx at `:8080/api/`)

---

## 13. Technology Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| **Runtime** | Node.js | 20+ | JavaScript/TypeScript runtime |
| **Language** | TypeScript | 5.x | Type-safe development on both ends |
| **Backend Framework** | Express.js | 4.18 | REST API server |
| **File Upload** | Multer | 1.4 | Multipart form data handling |
| **Frontend Framework** | React | 18.3 | UI component library |
| **Build Tool** | Vite | 6.x | Fast dev server + production bundler |
| **CSS** | Tailwind CSS | 3.4 | Utility-first dark theme |
| **Charts** | Recharts | 2.10 | Donut, scatter, and pie charts |
| **Icons** | Lucide React | latest | Shield, AlertTriangle, CheckCircle, etc. |
| **Drag & Drop** | react-dropzone | 14.x | File upload UX |
| **HTTP Client** | Axios | 1.x | (Available, frontend uses fetch for core) |
| **UUID** | uuid | 9.x | Unique IDs for assets, BOMs |
| **Containerization** | Docker + nginx | latest | Production deployment |
| **Monorepo** | npm workspaces | native | Shared node_modules |
| **Concurrent Dev** | concurrently | 8.x | Run backend + frontend dev servers |

### Custom Tailwind Theme

```javascript
// tailwind.config.js - QuantumGuard dark palette
colors: {
  'qg-dark':   '#0d1117',   // Page background (GitHub dark)
  'qg-card':   '#161b22',   // Card backgrounds
  'qg-border': '#30363d',   // Borders
  'qg-accent': '#58a6ff',   // Links, highlights (blue)
  'qg-green':  '#3fb950',   // Quantum-safe, compliant
  'qg-red':    '#f85149',   // Not quantum-safe, non-compliant
  'qg-yellow': '#d29922',   // Warnings, moderate risk
  'qg-purple': '#bc8cff',   // PQC algorithms
}
```

---

## 14. How to Run

### Development (Recommended)

```bash
# 1. Clone the repo
git clone https://github.com/your-org/cbom-analyser.git
cd cbom-analyser

# 2. Install all dependencies
npm install
cd backend && npm install && cd ..
cd frontend && npm install && cd ..

# 3. Start both servers
npm run dev
# Backend → http://localhost:3001
# Frontend → http://localhost:5173

# 4. Open http://localhost:5173 in your browser
```

### Production (Docker)

```bash
docker-compose up --build
# Frontend → http://localhost:8080
# Backend  → http://localhost:3001
```

### Manual Start

```bash
# Terminal 1 - Backend
cd backend && npx ts-node src/index.ts

# Terminal 2 - Frontend
cd frontend && npx vite
```

### Scanning a Local Repo

```bash
# Clone any repo
git clone https://github.com/spring-projects/spring-petclinic.git /tmp/petclinic

# Scan it (backend must be running)
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/petclinic"}' | jq .

# Or use the regex-only scanner (faster)
curl -X POST http://localhost:3001/api/scan-code/regex \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/tmp/petclinic"}' | jq .
```

### Scanning a Live TLS Endpoint

```bash
curl -X POST http://localhost:3001/api/scan-network \
  -H "Content-Type: application/json" \
  -d '{"url": "github.com", "port": 443}' | jq .
```

---

## 15. Competitive Differentiators

| Feature | IBM CBOMkit | CycloneDX cdxgen | **QuantumGuard CBOM Hub** |
|---------|-------------|-------------------|--------------------------|
| CBOM Upload & Visualize | ✅ | ❌ | ✅ |
| Code Scanning (sonar) | ✅ (SonarQube only) | ✅ | ✅ (with regex fallback) |
| **Network TLS Scanning** | ❌ | ❌ | ✅ |
| **PQC Risk Scoring (0-100)** | ❌ | ❌ | ✅ |
| **PQC Replacement Recommendations** | ❌ | ❌ | ✅ (NIST FIPS 203/204/205) |
| Compliance Banner | ✅ | ❌ | ✅ |
| Dark Theme Dashboard | ✅ | ❌ | ✅ |
| **Offline/Client-side Mode** | ❌ | ❌ | ✅ |
| **Code + Network + Upload in 1 tool** | ❌ | ❌ | ✅ |
| CycloneDX 1.6 Standard | ✅ | ✅ | ✅ |
| Docker Deployment | ✅ | ❌ | ✅ |
| **50+ Algorithm PQC Database** | ❌ | ❌ | ✅ |

### Key Innovation: Complete Cryptographic Inventory

Most tools do either code scanning OR network scanning. QuantumGuard does both and merges the results into a single CBOM — giving you a complete picture of your cryptographic posture: what's in the code AND what's on the wire.

---

*Generated for QuantumGuard CBOM Hub v1.0.0 — Built for the post-quantum era.*
