# 04: Modbus TCP Write Commands & Client Replay Capture

**What to build:** Support in the Modbus TCP decoder for Write Function Codes (`05` Write Single Coil, `06` Write Single Register, `15` Write Multiple Coils, `16` Write Multiple Registers). When a client issues a write command, the decoder emits a `CapturedCommandEventRecord` containing the command classification, target address, register/coil count, unscaled numeric value, and exact `RawPduBytes` for wire-accurate Client Replay, while also recording RED Transactions and updating mapped Tag Definitions.

**Blocked by:** 03: Modbus TCP Read Telemetry, RED Transactions & Unmapped Register Capture

**Status:** resolved

- [x] Decodes `ClientToServer` write requests for FC `05` (`MODBUS_WRITE_SINGLE_COIL`), FC `06` (`MODBUS_WRITE_SINGLE_REG`), FC `15` (`MODBUS_WRITE_MULTI_COILS`), and FC `16` (`MODBUS_WRITE_MULTI_REGS`).
- [x] Emits a `CapturedCommandEventRecord` for each write command with target address, command count, unscaled command value (where applicable), and exact application PDU bytes (`RawPduBytes`).
- [x] Emits `ExtractedDataPointRecord` updates for any written addresses that match a configured `TagDefinition`.
- [x] Correlates write requests with `ServerToClient` write echoes/responses (and exception responses) to emit complete `ProtocolTransactionRecord` RED Metrics.
- [x] Verified by unit tests using raw byte arrays for single and multi-point write function codes.

