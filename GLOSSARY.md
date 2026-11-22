# Domain Glossary

Canonical domain terminology for the Industrial Protocol Traffic Analyzer (FAT/SAT). Use these terms consistently across code, tests, tickets, and documentation.

| Term | Definition | Avoid / Synonyms |
| :--- | :--- | :--- |
| **Test Session** (`TestSession`) | A top-level ingestion and analysis run tied to a single PCAP capture, session manifest, and configuration. | Job, Run, Capture Batch |
| **Device Endpoint Pair** (`DeviceEndpointPair`) | A strictly directional communication link between a specific Client IP (+ optional protocol address) and Server IP (+ optional protocol address) for a single industrial protocol (`ModbusTCP` or `DNP3`). | Channel, Connection, Link |
| **Tag Definition** (`TagDefinition`) | Metadata mapping a protocol-specific register or object address (e.g., `HR:40001`, `G30V02:Idx0`) on a `DeviceEndpointPair` to a human-readable engineering name, data type, linear scaling ($y = mx + c$), and initial $T_0$ state. | Point, Variable, Signal |
| **Dissected Frame** (`DissectedFrame`) | A transport-level packet extracted from a PCAP source containing frame number, packet UTC timestamp, IP/Port endpoints, protocol name, raw application payload bytes, and optional dissected key-value fields. | Packet, Raw Frame |
| **Virtual Clock** | The simulation clock driven exclusively by `DissectedFrame.TimestampUtc` rather than wall-clock time (`DateTime.UtcNow`). All timeout evaluations and transaction latency metrics depend on the Virtual Clock. | System Clock, Wall Clock |
| **RED Metrics** (`ProtocolTransactionRecord`) | Request **R**ate, **E**rrors (timeouts, protocol exceptions, malformed frames), and **D**uration (response latency in milliseconds) calculated per transaction. | Telemetry Stats, KPIs |
| **Extracted Data Point** (`ExtractedDataPointRecord`) | A decoded telemetry reading associated with a mapped `TagDefinition`, holding both unscaled wire numeric values and scaled engineering values, dual timestamps, quality flags, and `IsValueChange`. | Sample, Tag Reading |
| **Packet Timestamp vs. Event Timestamp** | `PacketTimestamp` is when the frame was captured in the PCAP (`TimestampUtc`). `EventTimestamp` is the optional hardware/RTU timestamp embedded inside the protocol payload (e.g., DNP3 48-bit event time). | Arrival Time, Payload Time |
| **$T_0$ Initial State** | The first seen value of a tag during a `TestSession`, recorded on `tag_definitions` to seed an external Server Replay state machine. | Default Value, Seed State |
| **Captured Command Event** (`CapturedCommandEventRecord`) | A client-to-server control or write operation (e.g., Modbus FC 5/6/15/16 or DNP3 CROB Select/Operate/DirectOperate) persisted with both structured parameters and exact `RawPduBytes` for wire-accurate Client Replay. | Write Log, Control Command |
| **Unmapped Register** (`ModbusUnmappedRecord`) | A decoded Modbus register/coil value that has no matching `TagDefinition` in the session's CSV mapping, optionally stored for diagnostics and contiguous block replay. | Unknown Register, Orphan Point |
| **MBAP Header** | Modbus Application Protocol 7-byte header preceding the Modbus PDU in Modbus TCP frames (Transaction ID, Protocol ID, Length, Unit ID). | Modbus Header |
| **IIN (Internal Indications)** | 2-byte status bitfield included in every DNP3 Outstation response header indicating device state and errors. | DNP3 Status Word |
| **CROB (Control Relay Output Block)** | DNP3 Group 12 Variation 1 object used to issue binary control operations (Pulse On/Off, Latch On/Off, Trip, Close). | Binary Output Command |
| **Trace Span** (`TraceSpanRecord`) | An OpenTelemetry-compatible timed unit of protocol activity persisted in `trace_spans` (covering a request/response exchange, timeout, malformed frame, unsolicited message, confirm, or orphan response) with attributes and timeline events for Grafana Trace View and Node Graph visualizations. | Transaction Log, Span Row |
| **Trace ID** (`TraceId`) | A deterministic W3C 32-character lowercase hexadecimal (128-bit) identifier grouping related spans (such as a single transaction or a multi-step DNP3 SBO/Confirm exchange) across `trace_spans`, `red_transactions`, `captured_command_events`, and `tag_values`. | Correlation GUID, Flow ID |
| **Span ID** (`SpanId`) | A deterministic W3C 16-character lowercase hexadecimal (64-bit) identifier uniquely identifying a single `TraceSpanRecord` and linking child spans via `ParentSpanId`. | Event ID, Node ID |
| **Span Origin Kind** (`SpanOriginKind`) | Strongly typed classification of what protocol circumstance produced a `TraceSpanRecord` (`RequestResponse`, `Timeout`, `TimeoutAtEof`, `Malformed`, `Unsolicited`, `DirectNoAck`, `Confirm`, `ConfirmTimeout`, `OrphanResponse`). | Span Type, Message Category |
| **SBO Window** (`SboWindowMs`) | Configurable Virtual-Clock duration (default `10,000` ms) within which a DNP3 `Operate` (`FC 0x04`) targeting the same `(DevicePairId, TargetAddress)` links as a child span of its preceding `Select` (`FC 0x03`) root span. | Control Timeout, Select Timeout |
| **Device Endpoint Name** (`ClientName` / `ServerName`) | Optional human-readable device identity on a `DeviceEndpointPair` (falling back to IP and optional protocol address ID) used as `service_name` in Grafana Trace View and node labels in Node Graph. | Host Alias, Service Label |

