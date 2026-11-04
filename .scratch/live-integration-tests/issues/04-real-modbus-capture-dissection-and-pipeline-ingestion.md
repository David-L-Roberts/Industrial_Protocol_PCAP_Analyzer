# 04: Real Modbus TCP Capture Fixture, Live `tshark` Dissection & Full Pipeline Ingestion

**What to build:** Commits the real Modbus TCP capture fixture alongside its `manifest.json` and `tags.csv` files in the integration test fixtures directory, and verifies both live `tshark` frame dissection and a full end-to-end CLI/Runner ingestion pipeline run against TimescaleDB and MinIO. Confirms that real Modbus TCP packets are dissected by `tshark` into `DissectedFrame` records, decoded into RED Metrics, Extracted Data Points, $T_0$ Initial States, Captured Command Events, and Unmapped Registers (as applicable to the capture), persisted to TimescaleDB, and archived to MinIO.

**Blocked by:** 02: Live TimescaleDB Batch Persistence & Session Cleanup Slice, 03: Live MinIO PCAP Archiving & Object Lifecycle Slice

**Status:** resolved

- [x] Stores the committed Modbus TCP capture file alongside a valid `manifest.json` and `tags.csv` in the integration test fixtures folder, tracked in git.
- [x] Exercises live `tshark` process dissection against the real Modbus TCP capture file and verifies that `DissectedFrame` records are emitted with `ProtocolType.ModbusTcp`, valid UTC timestamps, IP/TCP endpoints, and raw application payloads.
- [x] Executes a full end-to-end ingestion run from the Modbus TCP fixture set through `tshark`, the Modbus TCP decoder, TimescaleDB persistence, and MinIO archiving.
- [x] Queries TimescaleDB and MinIO to assert that the `TestSession` reaches `COMPLETED`, the S3 object key is recorded and present in MinIO, and expected RED transactions, tag values / $T_0$ Initial States, command events, or unmapped registers are persisted, followed by automatic session and object cleanup unless `KEEP_TEST_DATA=true` is set.

