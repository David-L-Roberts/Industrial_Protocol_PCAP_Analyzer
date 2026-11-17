# 01: Pipeline lifecycle phase milestones in CLI analysis output

**What to build:** When a user runs a `TestSession` analysis from the CLI, the terminal prints clear lifecycle milestone messages as the ingestion pipeline transitions between database initialization, `DissectedFrame` streaming, and post-stream $T_0$ Initial State finalization. This gives immediate feedback on which high-level phase is active before packet dissection starts and after the packet stream ends.

Domain progress reporting uses strong domain types (`PipelinePhase` enum for `InitializingSession`, `DissectingPackets`, and `FinalizingSession`, plus a `PipelineProgress` record) emitted synchronously by the ingestion pipeline orchestrator without introducing console or wall-clock dependencies into the core domain.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The ingestion pipeline emits strongly-typed `PipelineProgress` notifications as a `TestSession` transitions through `InitializingSession`, `DissectingPackets` (once session, `DeviceEndpointPair`, and `TagDefinition` records are initialized), and `FinalizingSession` (once all `DissectedFrame` records and EOF timeouts are flushed, prior to updating $T_0$ Initial States).
- [ ] When `DissectingPackets` begins, the CLI writes `Initialized session with <N> device pair(s) and <M> tag(s). Dissecting packets...` to the progress output stream.
- [ ] When `FinalizingSession` begins, the CLI writes `Packet stream complete. Finalizing initial tag states in database...` to the progress output stream before the final session completion banner.
- [ ] Core domain logic remains free of `TextWriter` and wall-clock time dependencies.
- [ ] Unit tests verify phase transition ordering and CLI milestone output without invoking external binaries or a live database.
