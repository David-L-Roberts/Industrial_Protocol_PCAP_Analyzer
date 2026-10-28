# 03: Modbus TCP Read Telemetry, RED Transactions & Unmapped Register Capture

**What to build:** A Modbus TCP protocol decoder that parses MBAP headers and Read Function Codes (`01` Read Coils, `02` Read Discrete Inputs, `03` Read Holding Registers, `04` Read Input Registers) along with Modbus exception responses (`FC >= 0x80`). Correlates requests and responses by MBAP Transaction ID and Unit ID to emit RED Metrics, unpacks register/coil payloads into mapped Extracted Data Points (`BOOL`, `INT16`, `UINT16`, `INT32`, `FLOAT32_BE`, `FLOAT32_SWAPPED`), and optionally emits Unmapped Register records when `StoreUnmappedRegisters` is enabled on the session.

**Blocked by:** 01: Core Pipeline, Virtual Clock RED Engine & Tag Resolution Engine

**Status:** resolved

- [x] Parses the 7-byte MBAP Header (Transaction ID, Protocol ID, Length, Unit ID) and validates framing, emitting a `MALFORMED` RED Transaction record on truncated or invalid payloads.
- [x] Tracks `ClientToServer` read requests (FC `01`, `02`, `03`, `04`) by Transaction ID + Unit ID so the corresponding `ServerToClient` response resolves target register/coil offsets and calculates Virtual Clock response duration.
- [x] Detects Modbus exception responses (`FC >= 0x80`) and emits RED Transaction records with `IsError = true`, `ErrorType = "EXCEPTION"`, and status code (e.g., `MODBUS_EX_02`).
- [x] Unpacks multi-format telemetry values (`BOOL`, `INT16`, `UINT16`, `INT32`, `FLOAT32_BE`, `FLOAT32_SWAPPED`) for mapped tags (`HR:<addr>`, `IR:<addr>`, `COIL:<addr>`, `DI:<addr>`) and emits scaled `ExtractedDataPointRecord` items.
- [x] Emits `ModbusUnmappedRecord` items for unmapped register/coil addresses when `StoreUnmappedRegisters` is `true`, and suppresses them when `false`.
- [x] Verified by unit tests covering every read function code, data type unpacking format, exception response, and unmapped register toggle using raw byte payloads.

