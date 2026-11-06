# Industrial Protocol PCAP Analyzer (FAT/SAT)

The **Industrial Protocol PCAP Analyzer** is a high-performance .NET 8 ingestion and analysis engine designed to evaluate network packet captures (PCAP/PCAPNG) of industrial control system (ICS) traffic during Factory Acceptance Testing (FAT) and Site Acceptance Testing (SAT).

The system stream-processes captures containing **Modbus TCP** and **DNP3** traffic, resolves raw register and object addresses into scaled engineering tags, calculates Virtual-Clock **RED** metrics (Request **R**ate, **E**rrors, response **D**uration), captures control commands for client/server replay, and writes time-series telemetry into **TimescaleDB (PostgreSQL)** with optional PCAP archiving to **MinIO / S3**.

---

## Quickstart

### 1. Start Infrastructure with Docker Compose

A pre-configured `docker-compose.yml` is provided at the repository root to start **TimescaleDB**, **pgAdmin**, **MinIO**, and **Grafana**:

```bash
# Start TimescaleDB, pgAdmin, MinIO, and Grafana in the background
docker compose up -d

# Check service health
docker compose ps
```

#### Default Service Endpoints and Credentials

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

### 2. Run a Sample Analysis

Run the analyzer against the included Modbus sample capture:

```bash
dotnet run --project src/Analyzer.Cli/Analyzer.Cli.csproj -- analyze \
  --manifest tests/Analyzer.IntegrationTests/Fixtures/Modbus/manifest.json \
  --db "Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password" \
  --s3-endpoint "http://localhost:9000" \
  --s3-access-key "minioadmin" \
  --s3-secret-key "minioadmin_dev_password"
```

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

---

### Example Commands

Below are concrete, ready-to-run examples matching the default endpoints from `docker-compose.yml` and the committed fixture files in the repository:

#### 1. Full Ingestion with MinIO PCAP Archiving (Modbus TCP)
Runs live `tshark` dissection against `ModbusSampleCapture.pcapng`, persists RED metrics, tag telemetry, command events, and unmapped registers to TimescaleDB, and archives the capture file to MinIO:

```bash
dotnet run --project src/Analyzer.Cli/Analyzer.Cli.csproj -- analyze \
  --manifest tests/Analyzer.IntegrationTests/Fixtures/Modbus/manifest.json \
  --db "Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password" \
  --s3-endpoint "http://localhost:9000" \
  --s3-bucket "pcap-captures" \
  --s3-access-key "minioadmin" \
  --s3-secret-key "minioadmin_dev_password"
```

#### 2. Local Database Only (DNP3, Skipping PCAP Archiving)
When `--s3-endpoint` is omitted, capture archiving is safely skipped and all frames are processed directly into TimescaleDB:

```bash
dotnet run --project src/Analyzer.Cli/Analyzer.Cli.csproj -- analyze \
  --manifest tests/Analyzer.IntegrationTests/Fixtures/Dnp3/manifest.json \
  --db "Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password"
```

#### 3. Specifying Custom `tshark` Path (Windows Wireshark Installation)
If `tshark` is not in your system `PATH`, specify its location with `--tshark`:

```bash
dotnet run --project src/Analyzer.Cli/Analyzer.Cli.csproj -- analyze \
  --manifest tests/Analyzer.IntegrationTests/Fixtures/Modbus/manifest.json \
  --db "Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password" \
  --tshark "C:\Program Files\Wireshark\tshark.exe"
```

#### 4. Offline Analysis via Pre-Extracted NDJSON (No `tshark` Required)
If you have already extracted the EK NDJSON packet dump via `tshark -T ek`, you can provide `--ndjson-input` to bypass spawning `tshark` entirely, along with a custom batch size:

```bash
dotnet run --project src/Analyzer.Cli/Analyzer.Cli.csproj -- analyze \
  --manifest tests/Analyzer.IntegrationTests/Fixtures/Modbus/manifest.json \
  --db "Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password" \
  --ndjson-input "captures/pre_extracted_modbus.ndjson" \
  --batch-size 2500
```

#### 5. Shorthand Flags with Compiled Binary
Using the shorthand flags `-m` and `-d`:

```bash
Analyzer.Cli analyze \
  -m tests/Analyzer.IntegrationTests/Fixtures/Modbus/manifest.json \
  -d "Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password"
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

### Compiling into an Executable (.exe)

You can compile the CLI tool (`Analyzer.Cli.csproj`) into a native binary using the `dotnet publish` command. Two publishing modes are supported:

#### Option A: Self-Contained Single-File Executable (Recommended for Field / FAT / SAT Machines)
This mode bundles the .NET 8 runtime and all framework dependencies directly into a single executable file. The target testing or field computer **does not need the .NET 8 SDK or Runtime installed**:

```bash
dotnet publish src/Analyzer.Cli/Analyzer.Cli.csproj \
  -c Release \
  -r win-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -o publish/win-x64/
```

* **Generated File:** `publish/win-x64/Analyzer.Cli.exe` (self-contained binary) and `Analyzer.Cli.pdb` (debug symbols).
* **Cross-Platform (Linux):** Replace `-r win-x64` with `-r linux-x64` to generate an executable Linux binary (`publish/linux-x64/Analyzer.Cli`).

```bash
dotnet publish src/Analyzer.Cli/Analyzer.Cli.csproj \
  -c Release \
  -r linux-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -o publish/linux-x64/
```

Other options:
* `-p:DebugType=embedded`: Embed symbols (`.pdb`) directly inside the .exe (so you don't have a separate .pdb file, but retain detailed debug info in error logs)
* `-p:DebugType=None`: Disable `.pdb` generation entirely

#### Option B: Framework-Dependent Executable (Lightweight)
This mode produces a small executable stub along with supporting DLLs. The target machine **must have the [.NET 8.0 Runtime](https://dotnet.microsoft.com/download/dotnet/8.0)** installed:

```powershell
dotnet publish src/Analyzer.Cli/Analyzer.Cli.csproj `
  -c Release `
  -o publish/cli/
```

* **Generated File:** `publish/cli/Analyzer.Cli.exe` along with its dependency DLLs.
  * `.exe` is specific to host that ran `dotnet publish`. The DLLs are platform agnostic. 
    * You can run the portable DLLs directly with the dotnet command:
    ```bash
    dotnet Analyzer.Cli.dll analyze --manifest manifest.json --db "<connection_string>"
    ```

Alternatively, you may run the following (example is for linux):
```bash
dotnet publish src/Analyzer.Cli/Analyzer.Cli.csproj \
  -c Release \
  -r linux-x64 \
  --no-self-contained \
  -o publish/linux-cli/
```

---

### Accessing and Using the .exe

Once compiled, `Analyzer.Cli.exe` can be invoked directly from PowerShell, Windows Command Prompt (CMD), or terminal scripts without requiring `dotnet run`.

#### 1. Direct Invocation
You can execute the binary from your current working directory or navigate to the publish folder:

```powershell
# PowerShell / Terminal (from the repository root):
.\publish\win-x64\Analyzer.Cli.exe analyze `
  --manifest tests/Analyzer.IntegrationTests/Fixtures/Modbus/manifest.json `
  --db "Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password"
```

In Windows Command Prompt (`cmd.exe`):
```cmd
publish\win-x64\Analyzer.Cli.exe analyze ^
  --manifest tests\Analyzer.IntegrationTests\Fixtures\Modbus\manifest.json ^
  --db "Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password"
```

To display help and available options:
```powershell
.\publish\win-x64\Analyzer.Cli.exe --help
.\publish\win-x64\Analyzer.Cli.exe analyze --help
```

#### 2. Adding to System PATH (Optional)
To run `Analyzer.Cli` from any directory or test folder on your machine:
1. Copy `Analyzer.Cli.exe` to a dedicated utility folder (e.g., `C:\Tools\ProtocolAnalyzer\`), or add the `publish\win-x64\` folder directly to your user or system `PATH` environment variable.
2. In PowerShell, you can temporarily add the output directory to your current session:
   ```powershell
   $env:PATH += ";$PWD\publish\win-x64"
   ```
3. You can then run the analyzer anywhere simply as:
   ```powershell
   Analyzer.Cli.exe analyze -m path/to/manifest.json -d "<connection_string>"
   ```

#### 3. Runtime Prerequisites & Environment Requirements
Even with a self-contained single-file `.exe`, the application interacts with external services and packet dissection tools. Ensure the following are set up on the target machine:

1. **Wireshark / `tshark` Installation**:
   - `Analyzer.Cli.exe` launches `tshark` as a subprocess to stream-dissect PCAP / PCAPNG captures.
   - If installed in the default location (`C:\Program Files\Wireshark\tshark.exe`) and present in `PATH`, it is detected automatically.
   - If `tshark` is located elsewhere, supply the `--tshark` argument:
     ```powershell
     --tshark "C:\CustomTools\Wireshark\tshark.exe"
     ```
   - *Note:* If you supply pre-dissected EK NDJSON captures using `--ndjson-input`, `tshark` is not required.
2. **TimescaleDB / PostgreSQL Reachability**:
   - The machine running the `.exe` must have network line-of-sight to PostgreSQL / TimescaleDB (default port 5432) specified in `--db`.
   - The database schema must be initialized (see `docker/sql/001_init_timescaledb.sql`).
3. **MinIO / S3 Object Storage (Optional)**:
   - If archiving raw PCAPs via `--s3-endpoint`, the S3 endpoint (default port 9000) must be reachable. If `--s3-endpoint` is omitted, PCAP archiving is skipped and only database persistence is performed.
4. **File Path Resolution**:
   - Manifest paths (`--manifest`) can be relative to your current working directory or absolute.
   - Paths referenced *inside* the manifest JSON (such as `pcap_file` and `tag_mapping_csv`) resolve relative to the manifest file's parent folder.


---

## Configuration & Inputs

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
Must point to the target TimescaleDB/PostgreSQL database where `docker/sql/001_init_timescaledb.sql` has been executed.

```text
Host=localhost;Port=5432;Database=protocol_analyzer;Username=analyzer;Password=analyzer_dev_password
```

---

## Outputs & Telemetry

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

## Troubleshooting

1. **`tshark exited with code 1 / executable not found`**:
   - Ensure Wireshark/tshark is installed.
   - On Windows, pass `--tshark "C:\Program Files\Wireshark\tshark.exe"` if it is not in your `PATH`.
2. **`Failed to connect to PostgreSQL`**:
   - Verify TimescaleDB is running: `docker compose ps`
   - Ensure database schema has been initialized via `docker/sql/001_init_timescaledb.sql`.
3. **`Manifest file not found / Tag mapping CSV not found`**:
   - Relative paths inside the manifest resolve against the manifest's parent directory. Ensure the CSV and PCAP paths are placed next to the manifest or specify absolute paths.

---

## Developer Guide & Architecture

This section is intended for developers, maintainers, and engineers extending the protocol analyzer.

### Architecture Overview

The solution follows a strict **Hexagonal / Clean Architecture** pattern:

- **`Analyzer.Core`**: Pure domain model (zero dependencies on database drivers, external processes, or UI). Implements `VirtualClockRedEngine`, `TagResolutionEngine`, domain records, and `IngestionPipelineOrchestrator`.
- **`Analyzer.Decoders.Modbus`**: Decodes Modbus TCP MBAP headers, FC 01–06, 15, 16, exceptions (FC ≥ 0x80), linear register unpacking, command capture, and unmapped register tracking.
- **`Analyzer.Decoders.Dnp3`**: Decodes DNP3 Data Link, Transport, and Application headers, sequence numbers, Internal Indications (IIN), dual timestamps (`packet_timestamp` vs. 48-bit RTU `event_timestamp`), CROB control commands (Group 12 Var 1), and Phase 1 object groups (G1, G2, G10, G12, G20, G22, G30, G32).
- **`Analyzer.Infrastructure`**: External adapters including `TSharkStreamingFrameSource` (streaming NDJSON dissection via `tshark -T ek`), `TimescaleDbBatchSink` (high-speed PostgreSQL binary `COPY`), `CsvTagMappingLoader`, `ManifestParser`, and `MinioPcapStorageService`.
- **`Analyzer.Cli`**: Command-line application entry point powered by `System.CommandLine` and Dependency Injection.
- **`Analyzer.Web`**: Minimal API and Blazor web interface.

---

### Development Prerequisites & External Dependencies

Before building or developing on the solution, ensure the following are installed:

#### 1. .NET 8.0 SDK
- **Required**: [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) to build and run the solution.
- Verify:
  ```bash
  dotnet --version
  ```

#### 2. TimescaleDB (PostgreSQL 14+)
- **Required**: A running TimescaleDB or PostgreSQL instance with the `timescaledb` extension enabled.
- Tables and hypertables are initialized via `docker/sql/001_init_timescaledb.sql`.
- Running `docker compose up -d` provides this out-of-the-box.

#### 3. Wireshark / `tshark`
- **Required** (unless using `--ndjson-input`): Used to stream-dissect PCAP files with TCP stream desegmentation enabled (`tcp.desegment_tcp_streams:TRUE`).
- **Installation**:
  - **Linux / Ubuntu**: `sudo apt install tshark`
  - **macOS**: `brew install wireshark`
  - **Windows**: Install [Wireshark](https://www.wireshark.org/download.html). Ensure `tshark` is added to your system `PATH` (typically `C:\Program Files\Wireshark\tshark.exe`) or set `TSHARK_PATH`.

#### 4. MinIO / S3 Object Storage (Optional)
- Used for archiving original PCAP capture files alongside session metadata.
- Provided out-of-the-box in `docker-compose.yml`.

---

### Building & Publishing the Solution

#### Build the Entire Solution
```bash
dotnet build ProtocolAnalyzer.sln
```

#### Compile / Publish Standalone CLI Executables
To produce standalone or framework-dependent executables for field deployment, see [Compiling into an Executable (.exe)](#compiling-into-an-executable-exe).

* **Self-Contained Single-File (Windows):**
  ```powershell
  dotnet publish src/Analyzer.Cli/Analyzer.Cli.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/win-x64/
  ```
* **Self-Contained Single-File (Linux):**
  ```bash
  dotnet publish src/Analyzer.Cli/Analyzer.Cli.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -o publish/linux-x64/
  ```
* **Framework-Dependent:**
  ```powershell
  dotnet publish src/Analyzer.Cli/Analyzer.Cli.csproj -c Release -o publish/cli/
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
