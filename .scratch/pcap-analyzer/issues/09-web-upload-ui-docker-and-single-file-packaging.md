# 09: Web Upload UI, Docker Containerization & Single-File Packaging (`Analyzer.Web`)

**What to build:** An ASP.NET Core Minimal API and Blazor Web UI enabling engineers to upload PCAP files, session manifests, and tag mapping CSVs via drag-and-drop, monitor ingestion session status and summary metrics, and delete sessions via the `delete_test_session` database function. Includes a multi-stage `Dockerfile` (with `tshark` installed), full `docker-compose.yml` integration alongside TimescaleDB, MinIO, and Grafana, and standalone single-file publish profiles for `win-x64` and `linux-x64`.

**Blocked by:** 08: CLI Analyzer Entry Point (`Analyzer.Cli`)

**Status:** ready-for-agent

- [ ] Exposes REST API endpoints in `Analyzer.Web` to list sessions, upload a new session bundle (PCAP + manifest + CSVs), query session status/metrics, and delete a session using `SELECT delete_test_session(@sessionId)`.
- [ ] Provides a Blazor UI page for drag-and-drop PCAP + CSV + manifest upload and a session dashboard displaying ingestion progress and RED summary counts.
- [ ] Authors a multi-stage `Dockerfile` installing `.NET 8.0` runtime and `tshark`, and wires `analyzer-web` into `docker-compose.yml` with TimescaleDB, MinIO, and Grafana.
- [ ] Configures single-file standalone publish support (`PublishSingleFile=true`, `SelfContained=true`) targeting `win-x64` and `linux-x64`.

