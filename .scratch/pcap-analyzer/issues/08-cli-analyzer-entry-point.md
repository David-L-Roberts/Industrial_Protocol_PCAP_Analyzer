# 08: CLI Analyzer Entry Point (`Analyzer.Cli`)

**What to build:** A command-line interface (`analyze --manifest <path> --db <conn_string>`) that wires together the manifest/CSV loaders, `TSharkStreamingFrameSource`, `ModbusTcpDecoder`, `Dnp3Decoder`, `TimescaleDbBatchSink`, optional MinIO archiver, and `IngestionPipelineOrchestrator` to execute a full FAT/SAT PCAP analysis session from the terminal with structured progress and summary reporting.

**Blocked by:**
- 02: Session Manifest & Tag Mapping CSV Loader + TShark NDJSON Source
- 04: Modbus TCP Write Commands & Client Replay Capture
- 06: DNP3 Event Object Handlers (Dual Timestamps) & CROB Control Command Capture
- 07: TimescaleDB High-Speed Batch Sink & MinIO PCAP Archiver

**Status:** ready-for-agent

- [x] Implements the `analyze` CLI command accepting `--manifest <path>`, `--db <conn_string>`, and optional `--s3-endpoint` / `--ndjson-input` arguments.
- [x] Registers all core engines, protocol decoders, DNP3 Phase 1 object group handlers, and infrastructure adapters via Dependency Injection.
- [x] Executes end-to-end session initialization, frame streaming, protocol decoding, timeout flushing, $T_0$ baseline population, and session completion, marking the session `FAILED` on unhandled errors.
- [x] Outputs a clear execution summary (total frames processed, RED transaction counts, timeouts/exceptions detected, data points and command events persisted) and returns non-zero exit code on failure.

