# ADR 0001: Solution Architecture and Technology Stack

- **Status:** Accepted
- **Date:** 2026-10-23

## Context

The Industrial Protocol Traffic Analyzer must ingest Wireshark PCAP/PCAPNG files up to ~500 MB containing Modbus TCP and DNP3 traffic from Factory Acceptance Testing (FAT) and Site Acceptance Testing (SAT), decode telemetry and control commands, resolve engineering tags with linear scaling, compute RED (Rate, Errors, Duration) metrics using packet timestamps, and persist results for Grafana analytics and deterministic protocol replay.

## Decision

1. **Clean / Hexagonal Architecture:**
   - `Analyzer.Core` contains pure domain records, service interfaces (`IFrameSource`, `IProtocolDecoder`, `IDnp3ObjectGroupHandler`, `IDataSink`), and pipeline orchestration. It has **zero external NuGet dependencies** on database drivers, process runners, or UI frameworks.
   - `Analyzer.Decoders.Modbus` and `Analyzer.Decoders.Dnp3` implement pure protocol decoding over `DissectedFrame` and `ReadOnlySpan<byte>` payloads.
   - `Analyzer.Infrastructure` implements external adapters (`TSharkStreamingFrameSource`, `TimescaleDbBatchSink`, `CsvTagMappingLoader`, `MinioPcapStorageService`).
   - `Analyzer.Cli` and `Analyzer.Web` act as thin entry points composing dependencies.

2. **Target Runtime & Language:**
   - Target **.NET 8.0 (`net8.0`)** with C# 12, `<Nullable>enable</Nullable>`, and `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`.
   - Must build and execute identically on `win-x64` and `linux-x64`.

3. **Virtual Clock Enforcement:**
   - All request timeouts and duration calculations are driven strictly by `DissectedFrame.TimestampUtc`. `DateTime.Now` and `DateTime.UtcNow` are forbidden in domain and decoder timing paths.

4. **Unit Test Isolation:**
   - Unit tests (`tests/*.Tests`) use xUnit and never invoke `tshark` binaries or live PostgreSQL/TimescaleDB instances. They test against synthetic `DissectedFrame` streams, byte arrays, and static NDJSON/CSV fixtures.

5. **Persistence & Dissection Stack:**
   - **Dissection:** `tshark -r <file> -T ek` streaming NDJSON with TCP stream desegmentation enabled (`tcp.desegment_tcp_streams:TRUE`).
   - **Time-Series Database:** PostgreSQL 16 + TimescaleDB hypertables populated via `NpgsqlBinaryImporter` bulk `COPY`.
   - **Object Storage:** S3-compatible MinIO for archiving raw PCAP files.

## Consequences

- Decoders and RED metrics engines can be unit-tested in milliseconds without external infrastructure.
- Adding new DNP3 Object Group variations (e.g., Phase 2 SEL RTAC extensions) only requires adding a new `IDnp3ObjectGroupHandler` implementation and registering it in DI.
- High-volume PCAP files can be ingested in bounded memory via `IAsyncEnumerable<DissectedFrame>` and batched binary `COPY` into TimescaleDB.

