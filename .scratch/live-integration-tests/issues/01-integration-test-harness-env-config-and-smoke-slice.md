# 01: Integration Test Harness, `.env` Configuration & Live Infrastructure Smoke Slice

**What to build:** A dedicated integration test project wired into the solution alongside `.env.example`, `docker-compose.yml` environment alignment, `integration.runsettings`, and custom opt-in test attributes (`[IntegrationFact]` and `[IntegrationTheory]`). Running standard unit tests (`dotnet test`) automatically skips all live integration tests so existing self-contained unit tests remain fast and dependency-free. Running `dotnet test --settings integration.runsettings` activates integration tests, loads connection settings from `.env` (falling back to `.env.example` when `.env` is absent, with process/runsettings environment variables taking highest precedence), and verifies live connectivity against the deployed TimescaleDB instance, MinIO server, and local `tshark` binary, failing loudly if any dependency is unreachable.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] Plain `dotnet test` auto-skips all live integration tests while continuing to run all self-contained unit tests without requiring `.env`, `tshark`, TimescaleDB, or MinIO.
- [x] Running `dotnet test --settings integration.runsettings` enables the integration test suite and executes live infrastructure tests.
- [x] Tracked `.env.example` provides default test environment settings (`POSTGRES_*`, `MINIO_*`, `TSHARK_PATH`) aligned with `docker-compose.yml`, while untracked `.env` overrides them when present.
- [x] Live smoke tests verify connectivity to TimescaleDB, MinIO, and the `tshark` executable, failing with clear diagnostic messages if any service or binary is unavailable.

