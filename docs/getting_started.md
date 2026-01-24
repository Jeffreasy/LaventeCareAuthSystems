# Getting Started

## 🚀 Zero to Hero

Welcome to the **LaventeCare Auth Systems**. This project assumes you are operating in a hostile environment. Follow these steps to secure your local development station.

### Prerequisites
- **Go**: 1.22+
- **Docker & Docker Compose**: For local PostgreSQL containment.
- **Make**: For command automation.

### Quick Start
1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Jeffreasy/LaventeCareAuthSystems.git
    cd LaventeCareAuthSystems
    ```

2.  **Environment Setup**
    Copy the example environment (if missing, create one):
    ```bash
    # Create a .env file
    cp .env.example .env
    ```
    *See [Configuration](#configuration) for details.*

3.  **Ignition**
    Start the database container:
    ```bash
    docker compose up -d
    ```
    
    Run the application:
    ```bash
    make build
    make run
    ```
    server should listen on port `8080`.

---

## 🔧 Configuration

The application is configured via Environment Variables. In production, these **MUST** be injected securely.

| Variable | Description | Default (Dev) | Criticality |
| :--- | :--- | :--- | :--- |
| `APP_ENV` | Environment mode (`development`/`production`) | `development` | ⚠️ HIGH |
| `PORT` | HTTP Server Port | `8080` | LOW |
| `DATABASE_URL` | PostgreSQL Connection String | `postgres://user:password@localhost:5432/...` | 🚨 CRITICAL |
| `JWT_SECRET` | 32+ char random string for signing tokens | `super-secret...` | 🚨 CRITICAL |
| `SENTRY_DSN` | Sentry Project DSN for telemetry | (empty) | HIGH |
| `ALLOW_PUBLIC_REGISTRATION` | Enable/Disable public sign-ups | `true` | HIGH |
| `APP_URL` | Base URL for email links | `http://localhost:3000` | HIGH |

> **Anti-Gravity Law 1:** Never commit real secrets to Git. The `.env` file is gitignored for a reason.

---

## 🐳 Docker Architecture

We use `docker-compose.yml` to orchestrate dependencies.

- **Service: `db`**
    - **Image**: `postgres:16-alpine`
    - **Port**: `5432` exposed locally.
    - **Persistence**: Named volume `postgres_data`.
    - **Init**: Auto-seed via `migrations/001_init_schema.up.sql`.

To nuke the database and start fresh:
```bash
docker compose down -v
docker compose up -d
```
