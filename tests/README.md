# Tests

## Unit tests (JUnit 5 + AssertJ + Mockito)

Run from the module root:

```bash
mvn test
```

They live in `src/test/java` and cover the CSP report parser, the policy/header builders, the nonce
injection, the rate limiter, and the orchestration of both OSGi entry points (mocked Jahia/servlet
collaborators) — no running Jahia needed.

## E2E tests (Cypress against a live Jahia)

### Prerequisites

- Docker (with access to `ghcr.io/jahia` images) and Docker Compose
- Node 22+ and Yarn 4 (`corepack enable`)
- A Jahia Enterprise license

### Setup

1. Build the module first so its jar lands in `../target/`:

   ```bash
   mvn clean install
   ```

2. Copy `.env.example` to `.env` in this folder and fill in:
   - `NEXUS_USERNAME` / `NEXUS_PASSWORD` — credentials for Jahia EE artifacts
   - `JAHIA_LICENSE` — the license, base64-encoded
   - Optionally `JAHIA_IMAGE` (defaults to `ghcr.io/jahia/jahia-ee-dev:8-SNAPSHOT`)

   `.env` is gitignored — never commit it.

3. `MANIFEST` selects the provisioning manifest (`provisioning-manifest-build.yml` by default;
   `provisioning-manifest-snapshot.yml` for snapshot runs). The module jar and the test template
   module are installed automatically from `artifacts/`.

### Run

```bash
./ci.build.sh     # Builds the Cypress runner image and copies the module jars into artifacts/
./ci.startup.sh   # Starts Jahia + the runner (docker compose), provisions, runs the whole suite
```

The startup script tears the stack down when the run finishes; reports land in `results/`.

### Interactive debugging

With a Jahia already running on `http://localhost:8080`:

```bash
yarn install
yarn e2e:debug    # Opens the Cypress UI
```
