# Deploying to an Ubuntu Server (Docker)

This repo contains two independent FastAPI services:

| Service          | Path            | Port   | Depends on |
|-------------------|-----------------|--------|------------|
| `middleware-api`  | `/` (root)      | `8000` | Redis      |
| `kyc-gateway`     | `/kyc-gateway`  | `8001` | SQLite (local file, no external DB) |

Both are Dockerized. `docker-compose.yml` at the repo root builds and runs
both services (plus Redis for `middleware-api`) together.

---

## 1. Prerequisites on the Ubuntu server

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin git
sudo systemctl enable --now docker

# (optional) run docker without sudo
sudo usermod -aG docker $USER
newgrp docker
```

## 2. Clone the repo

```bash
git clone https://github.com/ssonkokevin/middlewareapi.git
cd middlewareapi
```

## 3. Configure environment variables

Each service has its own `.env`, based on the committed `.env.example`.
**Never commit the real `.env` files** — they hold live credentials.

```bash
# middleware-api (NIRA/Refugee — root of repo)
cp .env.example .env
nano .env    # fill in NIRA_*, REFUGEE_*, CLIENT_*, ADMIN_SECRET_KEY, etc.

# kyc-gateway
cp kyc-gateway/.env.example kyc-gateway/.env
nano kyc-gateway/.env    # set KYC_API_KEYS at minimum
```

Notes:
- `middleware-api` needs `REDIS_URL=redis://redis:6379/0` when run via
  docker-compose (service name `redis`, not `localhost`) — update `.env`
  accordingly since the example defaults to `localhost`.
- `kyc-gateway`'s `SQLITE_PATH` is overridden by `docker-compose.yml` to
  `/app/data/kyc_gateway.db` so its database persists in the
  `kyc_gateway_data` volume across container restarts — no change needed
  in `kyc-gateway/.env` for that.
- Set real, non-empty IP/subnet whitelists (`NIRA_*_ALLOWED_IP`,
  `REFUGEE_*_ALLOWED_SUBNETS`) before exposing this to production traffic —
  leaving them blank allows all IPs.

## 4. Build and start everything

```bash
docker compose up -d --build
```

This builds both images and starts:
- `redis` (internal, not exposed to the host)
- `middleware-api` on `http://<server-ip>:8000`
- `kyc-gateway` on `http://<server-ip>:8001`

## 5. Verify

```bash
curl http://localhost:8000/health
curl http://localhost:8001/health

docker compose ps
docker compose logs -f middleware-api
docker compose logs -f kyc-gateway
```

Swagger docs:
- `http://<server-ip>:8000/docs` (middleware-api)
- `http://<server-ip>:8001/docs` (kyc-gateway)

## 6. Updating after a new push

```bash
cd middlewareapi
git pull
docker compose up -d --build
```

## 7. Common operations

```bash
# Stop everything
docker compose down

# Stop and wipe volumes (Redis data + kyc-gateway SQLite DB — destructive)
docker compose down -v

# Tail logs
docker compose logs -f

# Rebuild a single service
docker compose up -d --build kyc-gateway
```

## Networking reminder

`middleware-api` talks to internal government endpoints
(`10.20.20.x` for NIRA, `192.168.168.x` for Refugee/UCC). The Ubuntu
server running this container must have network-level access
(same LAN, VPN, or routed subnet) to those internal hosts, or the
`/api/nira/verify` and `/api/refugee/verify` calls will time out.
