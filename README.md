# Enterprise Identity Provider (IDP) & Dispatch Network

A zero-trust, decoupled microservice architecture built in Go. This repository contains a fully containerized Identity Provider (IDP) and a secure Dispatch API, demonstrating enterprise-grade authentication, asymmetric cryptography, and multi-stage Docker orchestration.

## 🏗 Architecture Overview

This monorepo utilizes a decoupled architecture where authentication is strictly isolated from business logic. The IDP acts as the central cryptographic authority, while downstream microservices (like the Dispatch API) operate on a zero-trust model, verifying asymmetric signatures mathematically without requiring database round-trips.

```text
THE ENTERPRISE ZERO-TRUST ARCHITECTURE
                                       
+-------------------+                                +-------------------------------------------------+
|                   |       (1) POST /login          |  DOCKER BRIDGE NETWORK (enterprise_net)         |
|                   |       Email & Password         |                                                 |
|                   | -----------------------------> |  +--------------------+                         |
|                   |                                |  |                    |                         |
|   CLIENT          | <----------------------------- |  |   IDP Core         |                         |
|  (Postman / Web)  |       (3) 200 OK               |  |   (Go API - :8085) |                         |
|                   |       Returns RSA JWT &        |  |                    |                         |
|                   |       Sets Refresh Cookie      |  +--------------------+                         |
|                   |                                |    |                ^                           |
|                   |                                |    | (2) Hash Pass  | (Verify)                  |
|                   |                                |    v     & Store    |                           |
|                   |                                |  +--------------------+                         |
|                   |                                |  |                    |                         |
|                   |                                |  |   The Vault        |                         |
|                   |                                |  |   (PostgreSQL 15)  |                         |
|                   |                                |  |   (Port :5432)     |                         |
|                   |                                |  +--------------------+                         |
|                   |                                |                                                 |
|                   |==================================================================================|
|                   |                                |                                                 |
|                   |       (4) GET /classified      |  +--------------------+                         |
|                   |       Header: Bearer <JWT>     |  |                    |                         |
|                   | -----------------------------> |  |   Dispatch API     |--+ (5) Verify RSA       |
|                   |                                |  |   (Go API - :8081) |  | Signature Locally    |
|                   | <----------------------------- |  |                    |<-+ (No DB Call!)        |
|                   |       (6) 200 OK               |  +--------------------+                         |
|                   |       Top Secret Payload       |                                                 |
+-------------------+                                +-------------------------------------------------+
```

### Core Components
* **IDP Core (`/idp`):** Handles user registration, cryptographic password hashing, and the minting of RSA-256 signed JSON Web Tokens (JWTs). Manages session state via PostgreSQL.
* **Dispatch Service (`/dispatch`):** A downstream microservice simulating a classified vault. It intercepts requests, extracts the JWT, and verifies the RSA signature using only the IDP's Public Key.
* **The Vault (PostgreSQL):** A persistent database strictly isolated within a virtual Docker network, utilizing automated initialization scripts for schema enforcement.

## 🛠 Tech Stack

* **Language:** Go (1.26+)
* **Database:** PostgreSQL 15 (Alpine)
* **Orchestration:** Docker & Docker Compose
* **Security:** Asymmetric RSA-256 (JWT), bcrypt hashing, HttpOnly Secure Cookies

## 📂 Repository Structure

    .
    ├── docker-compose.yml      # Master orchestration blueprint
    ├── init.sql                # Automated PostgreSQL schema generation
    ├── idp/                    # Identity Provider Service
    │   ├── Dockerfile          # Multi-stage security build
    │   ├── main.go             
    │   └── internal/           # Handlers, Repositories, Cryptography
    └── dispatch/               # Downstream Microservice
        ├── Dockerfile          
        └── main.go             

## 🚀 Getting Started

### Prerequisites
* Docker engine and Docker Compose installed.
* Ports `8085`, `8081`, and `5432` available on your host machine.

### Quickstart

1. **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd enterprise-idp
    ```

2. **Boot the fleet:**
    The entire network, including the database and Go binaries, will compile and boot automatically.
    ```bash
    docker compose up --build -d
    ```

3. **Verify the network:**
    Check the logs to ensure the database schema was built and the Go servers connected successfully.
    ```bash
    docker logs idp_core
    ```

## 🔌 API Endpoints

### Identity Provider (Port 8085)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/register` | Registers a new user. Expects `email` and `password`. |
| `POST` | `/api/login` | Authenticates a user. Returns an RSA-signed JWT Access Token and sets an HttpOnly Refresh Cookie. |

### Dispatch Service (Port 8081)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/classified` | Requires a valid Bearer Token in the Authorization header. Returns classified payload if signature is verified. |

## 🛡️ Security Posture

* **Asymmetric Key Verification:** Microservices do not share a database or symmetrical secret keys. Downstream services verify tokens using only a distributed Public Key.
* **Multi-Stage Docker Builds:** The Go binaries are compiled in a heavy builder image, but deployed in a pristine, stripped-down `alpine:latest` vault, neutralizing builder-stage CVEs and reducing the attack surface.
* **Stateless Validation:** The Dispatch service achieves single-digit millisecond latency by mathematically verifying tokens locally.