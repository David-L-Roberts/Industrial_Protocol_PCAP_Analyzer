# Industrial Protocol PCAP Analyzer (FAT/SAT)

The **Industrial Protocol PCAP Analyzer** is a high-performance .NET 8 ingestion and analysis engine designed to evaluate network packet captures (PCAP/PCAPNG) of industrial control system (ICS) traffic during Factory Acceptance Testing (FAT) and Site Acceptance Testing (SAT).

The system stream-processes captures containing **Modbus TCP** and **DNP3** traffic, resolves raw register and object addresses into scaled engineering tags, calculates Virtual-Clock **RED** metrics (Request **R**ate, **E**rrors, response **D**uration), captures control commands for client/server replay, and writes time-series telemetry into **TimescaleDB (PostgreSQL)** with optional PCAP archiving to **MinIO / S3**.

---

## Architecture Overview

- **`Analyzer.Core`**: Pure domain model (zero dependencies on database drivers, external processes, or UI). Implements `VirtualClockRedEngine`, `TagResolutionEngine`, domain records, and `IngestionPipelineOrchestrator`.
- **`Analyzer.Decoders.Modbus`**: Decodes Modbus TCP MBAP headers, FC 01–06, 15, 16, exceptions (FC ≥ 0x80), linear register unpacking, command capture, and unmapped register tracking.
- **`Analyzer.Decoders.Dnp3`**: Decodes DNP3 Data Link, Transport, and Application headers, sequence numbers, Internal Indications (IIN), dual timestamps (`packet_timestamp` vs. 48-bit RTU `event_timestamp`), CROB control commands (Group 12 Var 1), and Phase 1 object groups (G1, G2, G10, G12, G20, G22, G30, G32).
- **`Analyzer.Infrastructure`**: External adapters including `TSharkStreamingFrameSource` (streaming NDJSON dissection via `tshark -T ek`), `TimescaleDbBatchSink` (high-speed PostgreSQL binary `COPY`), `CsvTagMappingLoader`, `ManifestParser`, and `MinioPcapStorageService`.
- **`Analyzer.Cli`**: Command-line application entry point powered by `System.CommandLine` and Dependency Injection.
- **`Analyzer.Web`**: Minimal API and Blazor web interface.

---

## Prerequisites & External Dependencies

Before running the CLI analyzer, ensure the following dependencies are installed and available:

### 1. .NET 8.0 SDK or Runtime
- **Required**: [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) to build and run the solution.
- Verify installation:
  ```bash
  dotnet --version
  ```

### 2. TimescaleDB (PostgreSQL 14+)
- **Required**: A running TimescaleDB or PostgreSQL instance with the `timescaledb` extension enabled.
- **Database Schema**: The database tables and hypertables must be initialized using [`sql/001_init_timescaledb.sql`](./sql/001_init_timescaledb.sql).
- *Easiest setup via Docker Compose* (see [Quickstart with Docker](#quickstart-with-docker-compose) below).

### 3. Wireshark / `tshark`
- **Required** (unless using `--ndjson-input`): `tshark` is used to stream-dissect PCAP files with TCP stream desegmentation enabled (`tcp.desegment_tcp_streams:TRUE`).
- **Installation**:
  - **Linux / Ubuntu**: `sudo apt install tshark`
  - **macOS**: `brew install wireshark`
  - **Windows**: Install [Wireshark](https://www.wireshark.org/download.html). Ensure `tshark` is added to your system `PATH` (typically `C:\Program Files\Wireshark\tshark.exe`) or pass the path via `--tshark`.
- Verify installation:
  ```bash
  tshark -v
  ```
- *Offline / Pre-parsed alternative*: If you already have pre-extracted `tshark -T ek` NDJSON output, you can supply `--ndjson-input <path>` to skip running `tshark`.

### 4. MinIO / S3 Object Storage (Optional)
- **Optional**: Used for archiving original PCAP capture files alongside session metadata.
- If `--s3-endpoint` is omitted, PCAP capture archiving is safely skipped.
- Provided out-of-the-box in the included `docker-compose.yml`.

---

## Quickstart with Docker Compose

A pre-configured `docker-compose.yml` is provided at the repository root to start **TimescaleDB**, **pgAdmin**, **MinIO**, and **Grafana**:

```bash
# Start TimescaleDB, pgAdmin, MinIO, and Grafana in the background
docker compose up -d

# Check service health
docker compose ps
```

### Default Service Endpoints and Credentials

| Service | Port | Default Credentials | Notes |
| :--- | :--- | :--- | :--- |
| **TimescaleDB** | `localhost:5432` | User: `analyzer`<br/>Password: `analyzer_dev_password`<br/>DB: `protocol_analyzer` | Automatically runs `docker/sql/001_init_timescaledb.sql` upon container creation |
| **pgAdmin** | `localhost:5050` | User: `admin@analyzer.com`<br/>Password: `analyzer` | Web UI for PostgreSQL/TimescaleDB; auto-loads preconfigured server connection |
| **MinIO API** | `localhost:9000` | User: `minioadmin`<br/>Password: `minioadmin_dev_password` | S3 API endpoint for capture archiving |
| **MinIO Console** | `localhost:9001` | User: `minioadmin`<br/>Password: `minioadmin_dev_password` | Web UI to inspect uploaded PCAP buckets |
| **Grafana** | `localhost:3000` | User: `admin`<br/>Password: `admin_dev_password` | Pre-configured visualization dashboards |

To stop the services:
```bash
docker compose down
```

---

## Building the Solution & Running Tests

### Build Solution
```bash
dotnet build ProtocolAnalyzer.sln
```

---

### Running Tests

The test suite is partitioned into **fast unit tests** (dependency-free) and **live integration tests** (which test real Docker services, `tshark`, and PCAP fixtures).

#### 1. Fast Unit Tests (Default / Offline / CI)
By default, running `dotnet test` executes all self-contained unit tests across `Analyzer.Core.Tests`, `Analyzer.Decoders.Modbus.Tests`, `Analyzer.Decoders.Dnp3.Tests`, `Analyzer.Infrastructure.Tests`, and `Analyzer.Cli.Tests`:

```bash
dotnet test ProtocolAnalyzer.sln
```

- **Zero External Dependencies**: Runs entirely in-memory using synthetic packets, test frames, and mock/fake sinks.
- **Auto-Skipped Integration Tests**: Any tests decorated with `[IntegrationFact]` or `[IntegrationTheory]` in `Analyzer.IntegrationTests` are automatically skipped with an informative notice when run without the integration runsettings file.
- **Fast Feedback**: Executes the full test suite (~125+ tests) in under 2 seconds.

#### 2. Live Integration Tests (End-to-End Pipeline & Infrastructure)
The `Analyzer.IntegrationTests` suite validates live interactions against real infrastructure, including:
- **Infrastructure Smoke Tests**: Live connectivity and schema validation for TimescaleDB, MinIO bucket operations, and `tshark` version checks.
- **TimescaleDB Persistence & Session Lifecycle**: Full batch ingestion, relational metadata insertion, hypertables writing, $T_0$ initial state updates, and cascading session deletion.
- **MinIO PCAP Archiving & Lifecycle**: File stream archiving, SHA-256 / metadata validation, and object cleanup.
- **Real Modbus TCP Capture Ingestion**: Live `tshark` process dissection of `ModbusSampleCapture.pcapng` and full runner ingestion into TimescaleDB and MinIO.
- **Real DNP3 Capture Ingestion**: Live `tshark` process dissection of `Dnp3SampleCapture.pcap` and full runner ingestion, asserting RED transactions, CROB `Select`/`Operate` command events, and $T_0$ states.

##### Prerequisites for Integration Tests
1. Start the local containers via Docker Compose:
   ```bash
   docker compose up -d
   ```
2. Ensure `tshark` is installed and reachable (set `TSHARK_PATH` in `.env` if not in system `PATH`).

##### Running the Integration Suite
To activate live integration tests, pass `--settings integration.runsettings` (which sets `RUN_INTEGRATION_TESTS=true`):

```bash
# Run all unit tests AND live integration tests across the entire solution
dotnet test ProtocolAnalyzer.sln --settings integration.runsettings

# Run only the live integration test project
dotnet test tests/Analyzer.IntegrationTests/Analyzer.IntegrationTests.csproj --settings integration.runsettings
```

##### Filtering Tests
You can filter by trait, fixture, or protocol:

```bash
# Run only integration tests (skipping unit tests)
dotnet test ProtocolAnalyzer.sln --settings integration.runsettings --filter "Category=Integration"

# Run only the Modbus integration tests
dotnet test tests/Analyzer.IntegrationTests/Analyzer.IntegrationTests.csproj --settings integration.runsettings --filter "FullyQualifiedName~Modbus"

# Run only the DNP3 integration tests
dotnet test tests/Analyzer.IntegrationTests/Analyzer.IntegrationTests.csproj --settings integration.runsettings --filter "FullyQualifiedName~Dnp3"
```

##### Integration Test Configuration (`.env`)
Configuration is resolved hierarchically:
1. Process environment variables / `integration.runsettings` (highest precedence).
2. `.env` file at repository root (untracked local overrides).
3. `.env.example` file at repository root (tracked defaults aligned with `docker-compose.yml`).

Key configuration settings:

| Setting | Default (`.env.example`) | Description |
| :--- | :--- | :--- |
| `POSTGRES_HOST` | `localhost` | TimescaleDB host |
| `POSTGRES_PORT` | `5432` | TimescaleDB port |
| `POSTGRES_DB` | `protocol_analyzer` | Database name |
| `POSTGRES_USER` | `analyzer` | Database user |
| `POSTGRES_PASSWORD` | `analyzer_dev_password` | Database password |
| `TIMESCALE_CONNECTION_STRING` | *Derived from POSTGRES_** | Optional explicit Npgsql connection string |
| `MINIO_ENDPOINT` | `localhost:9000` | MinIO S3 API endpoint |
| `MINIO_ROOT_USER` | `minioadmin` | MinIO access key |
| `MINIO_ROOT_PASSWORD` | `minioadmin_dev_password` | MinIO secret key |
| `MINIO_BUCKET` | `pcap-captures` | Target bucket for captures |
| `MINIO_USE_SSL` | `false` | Enable SSL for MinIO |
| `TSHARK_PATH` | `C:\Program Files\Wireshark\tshark.exe` (or `tshark`) | Path to `tshark` executable |
| `KEEP_TEST_DATA` | `false` | When `false` (default), all test session rows in TimescaleDB and objects in MinIO are automatically cleaned up after tests run. Set to `true` to keep test data for inspection in pgAdmin (`http://localhost:5050`), MinIO Console (`http://localhost:9001`), or Grafana (`http://localhost:3000`). |

---

## CLI Usage Guide

The CLI analyzer is located in `src/Analyzer.Cli`. You can execute it directly via `dotnet run` or by compiling a standalone executable.

### Command Syntax

```bash
dotnet run --project src/Analyzer.Cli/Analyzer.Cli.csproj -- analyze --manifest <path> --db <connection_string> [options]
```

Or from the compiled output directory:

```bash
Analyzer.Cli analyze --manifest <path> --db <connection_string> [options]
```

### Options Reference

| Argument / Option | Short | Required? | Default | Description |
| :--- | :--- | :---: | :--- | :--- |
| `--manifest <path>` | `-m` | **Yes** | — | Path to the session manifest JSON file. Relative paths resolve against the working directory. |
| `--db <conn_string>` | `-d` | **Yes** | — | TimescaleDB / PostgreSQL connection string. |
| `--s3-endpoint <url>` | — | No | `null` | MinIO or S3 endpoint URL (e.g., `http://localhost:9000`). If omitted, capture archiving is skipped. |
| `--s3-bucket <name>` | — | No | `pcap-captures` | MinIO / S3 bucket name for capture storage. |
| `--s3-access-key <key>` | — | No | `minioadmin` | MinIO / S3 access key. |
| `--s3-secret-key <key>` | — | No | `minioadmin` | MinIO / S3 secret key. |
| `--s3-ssl` | — | No | `false` | Enable SSL/HTTPS when connecting to S3 / MinIO. |
| `--ndjson-input <path>` | — | No | `null` | Optional pre-dissected tshark NDJSON file path (skips running `tshark`). |
| `--tshark <path>` | — | No | `tshark` | Custom path to the `tshark` executable if not in system `PATH`. |
| `--batch-size <int>` | — | No | `5000` | Batch size for bulk PostgreSQL binary `COPY` operations. |
| `--help` | `-?`, `-h` | No | — | Display CLI help and option descriptions. |

---

## Required Inputs

To run an analysis session, you need three primary inputs:

### 1. Session Manifest JSON (`session_manifest.json`)
The manifest configures the test session name, the capture file location, timeout thresholds, whether to store unmapped Modbus registers, and one or more **Device Endpoint Pairs**.

Paths in the manifest (such as `pcap_file` and `tag_mapping_csv`) can be absolute or relative to the manifest file's directory.

```json
{
  "session_name": "FAT_Substation_Feeder1",
  "pcap_file": "feeder1_capture.pcap",
  "timeout_threshold_ms": 1500,
  "store_unmapped_registers": false,
  "device_pairs": [
    {
      "name": "RTAC_Client_to_Relay_Server",
      "protocol": "ModbusTCP",
      "client_ip": "10.0.1.10",
      "server_ip": "10.0.1.20",
      "client_protocol_address_id": null,
      "server_protocol_address_id": 1,
      "tag_mapping_csv": "relay_modbus_tags.csv"
    },
    {
      "name": "SCADA_Master_to_RTAC_Outstation",
      "protocol": "DNP3",
      "client_ip": "10.0.1.5",
      "server_ip": "10.0.1.10",
      "client_protocol_address_id": 1,
      "server_protocol_address_id": 100,
      "tag_mapping_csv": "rtac_dnp3_tags.csv"
    }
  ]
}
```

#### Manifest Fields

- **`session_name`**: Name identifying this test run in database queries and reports.
- **`pcap_file`**: Path to the PCAP/PCAPNG capture file.
- **`timeout_threshold_ms`**: Virtual-clock timeout duration in milliseconds (default: `2000`). If a request does not receive a response within this elapsed virtual time, a `TIMEOUT` transaction is emitted.
- **`store_unmapped_registers`**: When `true`, any Modbus holding/input registers or coils requested in the PCAP that do not exist in the tag CSV are saved to `modbus_raw_unmapped`.
- **`device_pairs`**: List of communication pairs:
  - **`name`**: Descriptive channel name.
  - **`protocol`**: `"ModbusTCP"` or `"DNP3"`.
  - **`client_ip`**: Client/Master IP address.
  - **`server_ip`**: Server/Outstation IP address.
  - **`client_protocol_address_id`**: Client address ID (e.g., DNP3 Master Address; optional/null for Modbus).
  - **`server_protocol_address_id`**: Server address ID (e.g., Modbus Unit ID `1`, or DNP3 Outstation Address `100`).
  - **`tag_mapping_csv`**: Path to the tag definition CSV for this pair.

---

### 2. Tag Mapping CSV Files
Each device pair references a CSV file defining tag mappings and linear engineering scaling ($y = mx + c$).

```csv
Protocol,Address,TagName,DataType,ScaleMultiplier,ScaleOffset,Units,Description
ModbusTCP,HR:40001,Bus_Volts_PhaseA,FLOAT32_BE,0.1,0.0,kV,Phase A Bus Voltage
ModbusTCP,COIL:00005,Breaker_52A_Status,BOOL,1.0,0.0,,52A Breaker Auxiliary Contact
DNP3,G30V02:Idx0,Feeder_Active_Power,INT16,0.01,0.0,MW,Feeder MW Telemetry
DNP3,G01V02:Idx4,Overcurrent_Trip,BOOL,1.0,0.0,,Relay 51 Trip Signal
DNP3,G12V01:Idx0,Breaker_Trip_Cmd,BOOL,1.0,0.0,,CROB Trip Command Point
```

#### CSV Column Definitions

1. **`Protocol`**: `ModbusTCP` or `DNP3` (must match the device pair's protocol).
2. **`Address`**: Protocol address in `<Prefix>:<Target>` format:
   - Modbus Holding Register: `HR:40001` (1-based register)
   - Modbus Input Register: `IR:30001`
   - Modbus Coil: `COIL:00005`
   - Modbus Discrete Input: `DI:10001`
   - DNP3 Object: `G<Group>V<Variation>:Idx<Index>` (e.g., `G30V02:Idx0`, `G01V02:Idx4`, `G12V01:Idx0`)
3. **`TagName`**: Unique, human-readable tag identifier (e.g. `Bus_Volts_PhaseA`).
4. **`DataType`**: Wire decoding format:
   - `BOOL`: Single bit boolean
   - `INT16`: 16-bit signed integer (Big-Endian)
   - `UINT16`: 16-bit unsigned integer (Big-Endian)
   - `INT32`: 32-bit signed integer (Big-Endian)
   - `FLOAT32_BE`: IEEE 754 32-bit float (Big-Endian: `[Byte0, Byte1, Byte2, Byte3]`)
   - `FLOAT32_SWAPPED`: IEEE 754 32-bit float with 16-bit word swap (`[Byte2, Byte3, Byte0, Byte1]`)
5. **`ScaleMultiplier`**: Multiplier $m$ in $y = mx + c$ (use `1.0` for unscaled).
6. **`ScaleOffset`**: Offset $c$ in $y = mx + c$ (use `0.0` for no offset).
7. **`Units`**: Engineering units string (e.g., `kV`, `MW`, `Hz`, `degC`). Optional.
8. **`Description`**: Engineering point description. Optional.

---

### 3. Database Connection String (`--db`)
Must point to the target TimescaleDB/PostgreSQL database where `sql/001_init_timescaledb.sql` has been executed.

```text
Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password
```

---

## Expected Outputs

### 1. Terminal Progress & Summary Report

During execution, progress is logged to standard output. Upon completion, a structured summary block is printed:

```text
Parsing session manifest 'C:\Captures\session_manifest.json'...
Loading tag mappings for pair 'RTAC_Client_to_Relay_Server' from 'C:\Captures\relay_modbus_tags.csv'...
Loading tag mappings for pair 'SCADA_Master_to_RTAC_Outstation' from 'C:\Captures\rtac_dnp3_tags.csv'...
Archiving capture 'C:\Captures\feeder1_capture.pcap' to MinIO/S3 endpoint 'http://localhost:9000'...
Capture archived with key: captures/49a75225-bfa2-43bb-a5a5-924bcfe7f4b8/feeder1_capture.pcap
Starting analysis session 'FAT_Substation_Feeder1' (ID: 49a75225-bfa2-43bb-a5a5-924bcfe7f4b8)...
=================================================
Session Completed: FAT_Substation_Feeder1 (ID: 49a75225-bfa2-43bb-a5a5-924bcfe7f4b8) in 4.12s
Total frames processed: 48512
Matched frames processed: 45210
Transactions: 22605 (Success: 22590, Errors: 15, Timeouts: 12, Exceptions: 3)
Data points persisted: 135630
Command events persisted: 42
=================================================
```

#### Exit Codes
- **`0`**: Session completed successfully.
- **`1`**: Execution failed (e.g. invalid arguments, missing PCAP, database error). On failure, the session status in `test_sessions` is updated to `FAILED`, and the error message is written to `stderr`.

---

### 2. Database Output Tables (TimescaleDB)

All analytical outputs are persisted into TimescaleDB tables and hypertables:

| Table Name | Type | Description |
| :--- | :--- | :--- |
| **`test_sessions`** | Relational | Session metadata (`id`, `name`, `pcap_file_name`, `s3_object_key`, `status` = `'COMPLETED'` / `'FAILED'`). |
| **`device_pairs`** | Relational | Configured Client/Server endpoint pairs for the session. |
| **`tag_definitions`** | Relational | Tag definitions populated with $T_0$ initial baseline states (`initial_unscaled_numeric_value`, `initial_scaled_numeric_value`, `initial_boolean_value`, `initial_raw_hex`) captured from the first frame. |
| **`red_transactions`** | **Hypertable** | RED metrics per request/response pair: `timestamp`, `duration_ms`, `is_error`, `error_type` (`NONE`, `TIMEOUT`, `TIMEOUT_AT_EOF`, `EXCEPTION`, `MALFORMED`), and `status_code` (`SUCCESS`, `MODBUS_EX_02`, `DNP3_IIN_PARAM_ERR`, etc.). |
| **`tag_values`** | **Hypertable** | Time-series data points with dual timestamps (`packet_timestamp` vs. DNP3 `event_timestamp`), `unscaled_numeric_value`, `scaled_numeric_value`, `quality_flags`, and `is_value_change` flag. |
| **`captured_command_events`** | **Hypertable** | Client control actions (Modbus FC 05, 06, 15, 16 writes; DNP3 CROB Select, Operate, DirectOperate) storing structured parameters and raw byte payload (`raw_pdu_bytes`) for wire-accurate Client Replay. |
| **`modbus_raw_unmapped`** | **Hypertable** | Raw register offsets and hex values for unmapped Modbus points (active when `store_unmapped_registers: true`). |

---

### 3. MinIO / S3 Capture Archive (When Enabled)

If `--s3-endpoint` is passed:
- The raw PCAP/PCAPNG capture is uploaded into the specified bucket (default: `pcap-captures`).
- The object key follows the schema: `captures/<session_id>/<pcap_file_name>`.
- The generated key is linked to `test_sessions.s3_object_key` in the database.

---

## Example Ingestion Session

Given a capture in `tests/fixtures/sample.pcap` with `manifest.json` and `tags.csv`:

```bash
dotnet run --project src/Analyzer.Cli/Analyzer.Cli.csproj -- analyze \
  --manifest ./tests/fixtures/manifest.json \
  --db "Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password" \
  --s3-endpoint "http://localhost:9000" \
  --s3-access-key "minioadmin" \
  --s3-secret-key "minioadmin_dev_password"
```

---

## Troubleshooting

1. **`tshark exited with code 1 / executable not found`**:
   - Ensure Wireshark/tshark is installed.
   - On Windows, pass `--tshark "C:\Program Files\Wireshark\tshark.exe"` if it is not in your `PATH`.
2. **`Failed to connect to PostgreSQL`**:
   - Verify TimescaleDB is running: `docker compose ps`
   - Ensure database schema has been initialized via `sql/001_init_timescaledb.sql`.
3. **`Manifest file not found / Tag mapping CSV not found`**:
   - Relative paths inside the manifest resolve against the manifest's parent directory. Ensure the CSV and PCAP paths are placed next to the manifest or specify absolute paths.
