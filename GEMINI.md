# Industrial Protocol PCAP Analyzer — Agent Guidelines

Master engineering specification is stored in [`SPECIFICATION.md`](./SPECIFICATION.md). Always consult `SPECIFICATION.md` for database schema, domain record definitions, interface contracts, and protocol decoding requirements.

## Non-Negotiable Architectural & Coding Rules

1. **Priority Order:** Maintainability, Observability, Testability, and Extensibility take strict precedence over micro-optimizations.
2. **Clean / Hexagonal Architecture:**
   - `Analyzer.Core` must have **zero dependencies** on database drivers (`Npgsql`), external processes (`tshark`), or UI frameworks.
   - Protocol decoders (`Analyzer.Decoders.Modbus`, `Analyzer.Decoders.Dnp3`) must be pure domain services accepting `DissectedFrame` / `ReadOnlySpan<byte>` payloads and emitting strongly typed domain records.
3. **Unit Testability Without External Binaries:**
   - Unit tests must **never** invoke `tshark` or require a live database.
   - Ingestion is abstracted behind `IFrameSource`. Tests inject synthetic `DissectedFrame` streams or static NDJSON fixtures.
4. **Virtual Clock Enforcement:**
   - Never use `DateTime.Now` or `DateTime.UtcNow` when evaluating packet timeouts or transaction durations. All timing calculations must be driven exclusively by `DissectedFrame.TimestampUtc`.
5. **Cross-Platform Target:**
   - Target **.NET 8.0 (`net8.0`)** in C#. Code must compile with zero warnings (`TreatWarningsAsErrors=true`) and run identically on Windows (`win-x64`) and Linux (`linux-x64`).
6. **Strong Domain Typing (Enums & Value Objects over Free-Form Primitives):**
   - Model finite sets of values (e.g., protocol identifiers, tag data types, error classifications, transaction status codes) using C# `enum` types or strongly typed value objects rather than free-form `string` or unconstrained primitive fields. Parse external strings into strong domain types at the ingestion/configuration seam and serialize to wire/database strings only at the persistence seam.

## Build & Verification Commands

- **Build Solution:** `dotnet build ProtocolAnalyzer.sln`
- **Run Unit Tests:** `dotnet test ProtocolAnalyzer.sln`

## Agent skills

### Issue tracker

Issues and specs live as local markdown files under `.scratch/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical triage roles (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout (`GLOSSARY.md` and `docs/adr/` at the repo root). See `docs/agents/domain.md`.

