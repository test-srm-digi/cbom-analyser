# AWS EC2 Deployment Guide — QuantumGuard CBOM Analyser

## Prerequisites

- AWS EC2 instance (Amazon Linux 2023 recommended)
- SSH key (.pem file) for the instance
- GitHub PAT with `read:packages` scope (for `@digicert` private packages)
- Font Awesome Pro token
- AWS credentials (for Bedrock AI features)

---

## 1. SSH into EC2

```bash
ssh -i "quantumgaurd (1).pem" ec2-user@52.86.226.172
```

---

## 2. Install Docker

```bash
sudo yum update -y
sudo yum install -y docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ec2-user
```

Log out and back in for the group change to take effect:

```bash
exit
ssh -i "quantumgaurd (1).pem" ec2-user@52.86.226.172
```

Verify:

```bash
docker --version
```

---

## 3. Install Docker Buildx Plugin

```bash
mkdir -p ~/.docker/cli-plugins
curl -L https://github.com/docker/buildx/releases/download/v0.19.3/buildx-v0.19.3.linux-amd64 \
  -o ~/.docker/cli-plugins/docker-buildx
chmod +x ~/.docker/cli-plugins/docker-buildx
```

Verify:

```bash
docker buildx version
```

---

## 4. Install Docker Compose Plugin

```bash
curl -L https://github.com/docker/compose/releases/download/v2.32.4/docker-compose-linux-x86_64 \
  -o ~/.docker/cli-plugins/docker-compose
chmod +x ~/.docker/cli-plugins/docker-compose
```

Verify:

```bash
docker compose version
```

---

## 5. Clone the Repository

```bash
cd ~
git clone https://github.com/<org>/cbom-analyser.git
cd cbom-analyser
```

If already cloned, pull latest:

```bash
cd ~/cbom-analyser
git pull
```

---

## 6. Create the `.env` File

```bash
cat > .env << 'EOF'
# -- Private npm registry tokens (for Docker build) --
FONTAWESOME_TOKEN=<your-fontawesome-token>
GH_NPM_TOKEN=<your-github-pat-with-read-packages>

# -- AWS Bedrock (AI features) --
VITE_BEDROCK_API_ENDPOINT=https://bedrock-runtime.us-east-1.amazonaws.com
VITE_BEARER_TOKEN=<your-bedrock-bearer-token>
VITE_ACCESS_KEY_ID=<your-aws-access-key>
VITE_SECRET_ACCESS_KEY=<your-aws-secret-key>
VITE_SESSION_TOKEN=<your-aws-session-token>
AWS_ACCESS_KEY_ID=<your-aws-access-key>
AWS_SECRET_ACCESS_KEY=<your-aws-secret-key>
AWS_REGION=us-east-1
AWS_SESSION_TOKEN=<your-aws-session-token>

# -- GitHub (CBOM scanning) --
GITHUB_TOKEN=<your-github-pat>

# -- SonarQube (optional) --
SONAR_HOST_URL=http://localhost:9090
SONAR_TOKEN=<your-sonar-token>

# -- Database (must match docker-compose.yml) --
DB_DATABASE=dcone-quantum-gaurd
DB_USERNAME=root
DB_PASSWORD=asdasd
DB_HOST=db
DB_PORT=3306
DB_DIALECT=mariadb
EOF
```

> **Important:** `DB_HOST` must be `db` — this matches the service name in `docker-compose.yml`.

> **Note:** AWS STS session tokens expire. If Bedrock AI features stop working, regenerate your STS credentials and update `VITE_SESSION_TOKEN`, `AWS_SESSION_TOKEN`, `VITE_ACCESS_KEY_ID`, `AWS_ACCESS_KEY_ID`, `VITE_SECRET_ACCESS_KEY`, and `AWS_SECRET_ACCESS_KEY`.

---

## 7. Build & Start

```bash
docker compose up -d --build
```

This starts 3 containers:

| Service    | Port | Description               |
| ---------- | ---- | ------------------------- |
| `db`       | 3306 | MariaDB 11                |
| `backend`  | 3001 | Node.js API               |
| `frontend` | 8080 | Nginx serving React build |

Check status:

```bash
docker compose ps
docker compose logs -f          # live logs (Ctrl+C to exit)
docker compose logs backend     # backend only
docker compose logs frontend    # frontend only
```

---

## 8. Open Ports in AWS Security Group

1. Go to **EC2 Console** → select your instance
2. Click **Security** tab → click the **Security Group** link
3. **Edit inbound rules** → add:

| Type       | Port  | Source    | Description |
| ---------- | ----- | --------- | ----------- |
| Custom TCP | 8080  | 0.0.0.0/0 | Frontend    |
| Custom TCP | 3001  | 0.0.0.0/0 | Backend API |

4. Save rules

---

## 9. Access the Application

```
http://52.86.226.172:8080
```

Backend API:

```
http://52.86.226.172:3001/api
```

---

## Common Operations

### Redeploy after code changes

```bash
cd ~/cbom-analyser
git pull
docker compose up -d --build
```

### Stop everything

```bash
docker compose down
```

### Stop and remove all data (including database)

```bash
docker compose down -v
```

### Restart a single service

```bash
docker compose restart backend
docker compose restart frontend
```

### View logs

```bash
docker compose logs -f --tail=100 backend
```

### Check disk space

```bash
df -h
docker system df
```

### Clean up old Docker images

```bash
docker image prune -a -f
```

---

## Troubleshooting

| Problem                         | Fix                                                                              |
| ------------------------------- | -------------------------------------------------------------------------------- |
| `E401 Unauthorized` during build | Check `GH_NPM_TOKEN` in `.env` — needs `read:packages` scope                   |
| Frontend can't reach backend    | Check Security Group has port 3001 open                                          |
| Bedrock AI not working          | AWS STS tokens expired — regenerate and update `.env`, then `docker compose up -d` |
| Database connection refused     | Ensure `DB_HOST=db` (not `localhost` or `mariadb`)                               |
| Out of disk space               | Run `docker image prune -a -f` and `docker system prune`                         |
| Container keeps restarting      | Check logs: `docker compose logs <service>`                                      |
