# 05: DNP3 Framing, RED Transactions, IIN Decoding & Static/Counter Object Handlers

**What to build:** The DNP3 protocol decoder and extensible `IDnp3ObjectGroupHandler` registry supporting DNP3 Data Link, Transport, and Application layer headers, Master/Outstation address verification, application sequence RED transaction correlation, Internal Indications (`IIN`) bit decoding, and Phase 1 static and counter object groups: **Group 1** (Binary Input Static), **Group 10** (Binary Output Status), **Group 20** (Running Counters), and **Group 30** (Analog Input Static).

**Blocked by:** 01: Core Pipeline, Virtual Clock RED Engine & Tag Resolution Engine

**Status:** ready-for-agent

- [ ] Parses DNP3 Data Link (start bytes `0x0564`, length, control, source/destination addresses, CRC stripping), Transport header, and Application request/response headers.
- [ ] Correlates `ClientToServer` requests and `ServerToClient` responses by DNP3 Application Sequence number to emit `ProtocolTransactionRecord` RED Metrics, flagging error `IIN` bits (e.g., `DNP3_IIN_PARAM_ERR`, `DNP3_IIN_FUNC_NOT_SUPPORTED`) as `EXCEPTION` errors.
- [ ] Dispatches object headers (Group, Variation, Qualifier/Range) through `Dnp3HandlerRegistry` to registered `IDnp3ObjectGroupHandler` services.
- [ ] Decodes **Group 1** (Var 1 packed binary, Var 2 binary with flags), **Group 10** (Var 1 packed binary output, Var 2 binary output status with flags), **Group 20** (Var 1, 2, 5, 6 16/32-bit running counters with/without flags), and **Group 30** (Var 1–5 16/32-bit integer and 32-bit float analog inputs) into `ExtractedDataPointRecord` items with decoded quality flags (e.g., `ONLINE`, `RESTART`, `COMM_LOST`).
- [ ] Verified by unit tests covering DNP3 framing, IIN error detection, and each static/counter Group and Variation handler.

