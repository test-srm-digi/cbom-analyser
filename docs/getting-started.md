# Getting Started

> Quick setup, Docker deployment, configuration, and sample data.

---

## Quick Start

```bash
# Clone
git clone https://github.com/test-srm-digi/cbom-analyser.git
cd cbom-analyser

# Install dependencies
npm install

# Run (backend: 3001, frontend: 5173)
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) — upload a CBOM JSON or click **"sample CBOM file"** to explore the dashboard.

---

## Docker Deployment

### Using Docker Compose (Recommended)

The `docker-compose.yml` spins up all three services — **MariaDB**, **backend**, and **frontend** — in a single command:

```bash
docker compose up --build
# DB       → MariaDB 11 on port 3306
# Backend  → http://localhost:3001
# Frontend → http://localhost:8080
```

#### Services

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `db` | `mariadb:11` | `3306` | MariaDB database with a health check. Auto-creates the `dcone-quantum-gaurd` database. Data persisted in a `db_data` named volume. |
| `backend` | Custom (Node 20 Alpine) | `3001` | Express + Sequelize API server. Waits for `db` to report healthy before starting. |
| `frontend` | Custom (nginx Alpine) | `8080` | Vite-built SPA served by nginx. API requests at `/api/*` are proxied to `backend:3001`. |

#### Environment Variables Set in Docker Compose

The `backend` service is pre-configured with all database connection variables:

| Variable | Value | Description |
|----------|-------|-------------|
| `DB_HOST` | `db` | Docker service name for MariaDB |
| `DB_PORT` | `3306` | MariaDB port |
| `DB_DATABASE` | `dcone-quantum-gaurd` | Database name |
| `DB_USERNAME` | `root` | MariaDB user |
| `DB_PASSWORD` | `asdasd` | MariaDB password |

Additional secrets (API keys, tokens) are loaded from a `.env` file via `env_file: .env`. Create a `.env` in the project root with any keys you need (e.g. `AWS_BEARER_TOKEN_BEDROCK`, `SONAR_TOKEN`).

#### Health Check & Startup Order

The `db` service uses MariaDB's built-in health check (`healthcheck.sh --connect --innodb_initialized`). The `backend` has `depends_on: db: condition: service_healthy`, so it only starts once the database is ready to accept connections. The `frontend` starts after the backend.

#### Persistent Volume

The `db_data` Docker volume persists database contents across restarts:

```bash
# Remove everything including the database volume
docker compose down -v

# Keep the database between rebuilds
docker compose down
docker compose up --build
```

### Manual Docker Build

```bash
# Build backend
cd backend && docker build -t cbom-backend .

# Build frontend
cd frontend && docker build -t cbom-frontend .

# Run (you must provide your own MariaDB instance)
docker run -d -p 3001:3001 \
  -e DB_HOST=host.docker.internal \
  -e DB_DATABASE=dcone-quantum-gaurd \
  cbom-backend
docker run -d -p 8080:80 cbom-frontend
```

### Production URLs
- Frontend: `http://localhost:8080`
- Backend API: `http://localhost:3001` (or proxied through nginx at `:8080/api/`)

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Backend server port |
| `NODE_ENV` | `development` | Environment mode |
| `SONAR_HOST_URL` | `http://localhost:9090` | SonarQube server URL (for sonar-cryptography) |
| `SONAR_TOKEN` | — | SonarQube authentication token |
| `AWS_BEARER_TOKEN_BEDROCK` | — | AWS Bedrock bearer token (for AI suggestions) |
| `VITE_BEDROCK_API_ENDPOINT` | — | AWS Bedrock API endpoint URL |
| `VITE_ACCESS_KEY_ID` | — | AWS access key ID (alternative auth) |
| `VITE_SECRET_ACCESS_KEY` | — | AWS secret access key (alternative auth) |
| `VITE_SESSION_TOKEN` | — | AWS session token (alternative auth) |
| `DB_DATABASE` | `dcone-quantum-gaurd` | MariaDB database name |
| `DB_USERNAME` | `root` | MariaDB username |
| `DB_PASSWORD` | `asdasd` | MariaDB password |
| `DB_HOST` | `localhost` | MariaDB host |
| `DB_PORT` | `3306` | MariaDB port |
| `DB_DIALECT` | `mariadb` | Sequelize dialect (`mariadb` or `mysql`) |

### Vite Proxy Configuration

The frontend proxies `/api/*` requests to the backend in development. See `frontend/vite.config.ts`:

```typescript
server: {
  proxy: {
    '/api': {
      target: 'http://localhost:3001',
      changeOrigin: true
    }
  }
}
```

### nginx Configuration (Production)

The production frontend uses nginx to proxy API requests. See `frontend/nginx.conf`.

---

## Sample Data & Demo Code

### Pre-Built CBOM Files

| File | Assets | Description |
|------|--------|-------------|
| `sample-data/keycloak-cbom.json` | 8 | Minimal Keycloak simulation |
| `sample-data/spring-petclinic-cbom.json` | 34 | Comprehensive Spring app |
| `frontend/src/sampleData.ts` | 58 | Built-in demo (click "sample CBOM file") |

### Demo Source Code

The `demo-code/` directory contains real source files with crypto API calls:

- **`demo-code/java/CryptoService.java`** — SHA-256, AES-GCM, RSA, ECDSA
- **`demo-code/java/AuthenticationModule.java`** — Password hashing, token signing
- **`demo-code/python/crypto_utils.py`** — hashlib, PyCryptodome, cryptography lib
- **`demo-code/typescript/cryptoUtils.ts`** — Node.js crypto module patterns

### Scanning the Demo Code

```bash
curl -X POST http://localhost:3001/api/scan-code \
  -H "Content-Type: application/json" \
  -d '{"repoPath": "/path/to/cbom-analyser"}' \
  -o cbom-analyser-cbom.json

# Expected: 40+ cryptographic assets detected
```

---

*Back to [README](../README.md) · See also [API Reference](api-reference.md) · [GitHub Actions](github-actions.md)*
