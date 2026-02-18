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
