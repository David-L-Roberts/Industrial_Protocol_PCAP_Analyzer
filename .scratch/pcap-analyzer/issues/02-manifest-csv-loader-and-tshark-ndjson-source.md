# 02: Session Manifest & Tag Mapping CSV Loader + TShark NDJSON Source

**What to build:** Ingestion configuration loaders and the streaming packet dissection adapter. Given a session manifest JSON and per-device-pair tag mapping CSV files, the loader produces validated `TestSession`, `DeviceEndpointPair`, and `TagDefinition` domain records. Given a PCAP/PCAPNG capture or NDJSON stream (`tshark -T ek` format with TCP stream desegmentation enabled), the frame source streams `DissectedFrame` records with frame numbers, UTC timestamps, IP/port endpoints, protocol names, raw application payload bytes, and dissected fields.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] Parses session manifest JSON into a `TestSession` and its associated `DeviceEndpointPair` collection, including timeout threshold, unmapped register flag, client/server IPs, protocol address IDs, and tag CSV references.
- [x] Parses tag mapping CSV files (`Protocol,Address,TagName,DataType,ScaleMultiplier,ScaleOffset,Units,Description`) into `TagDefinition` records scoped to their `DeviceEndpointPair`.
- [x] Deserializes `tshark -T ek` NDJSON lines into `DissectedFrame` records asynchronously (`IAsyncEnumerable<DissectedFrame>`), extracting packet UTC timestamps, IP/TCP endpoints, and hex-decoded raw application payloads.
- [x] Configures `tshark` process invocation with `-r <file> -T ek -j "modbus dnp3 tcp ip" -o tcp.desegment_tcp_streams:TRUE` while allowing direct stream injection for unit tests.
- [x] Verified by unit tests against static JSON, CSV, and NDJSON fixtures without invoking the `tshark` binary.

