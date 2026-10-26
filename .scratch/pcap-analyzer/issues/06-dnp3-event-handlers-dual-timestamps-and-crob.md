# 06: DNP3 Event Object Handlers (Dual Timestamps) & CROB Control Command Capture

**What to build:** Phase 1 DNP3 event and control `IDnp3ObjectGroupHandler` implementations: **Group 2** (Binary Input Event), **Group 22** (Counter Change Event), **Group 32** (Analog Input Event) with dual timestamp capture (`PacketTimestamp` + DNP3 48-bit RTU `EventTimestamp`), and **Group 12** (Var 1 `CROB` Control Relay Output Block) capturing `Select`, `Operate`, and `DirectOperate` control commands into `CapturedCommandEventRecord` for wire-accurate Client Replay.

**Blocked by:** 05: DNP3 Framing, RED Transactions, IIN Decoding & Static/Counter Object Handlers

**Status:** ready-for-agent

- [ ] Decodes **Group 2** (Var 1 without time, Var 2 with absolute 48-bit DNP3 time, Var 3 with relative time), populating both `PacketTimestamp` and `EventTimestamp` (when present) on `ExtractedDataPointRecord`.
- [ ] Decodes **Group 22** (Var 1, 2, 5, 6 16/32-bit counter change events with/without time) into `ExtractedDataPointRecord`.
- [ ] Decodes **Group 32** (Var 1–5, 7 16/32-bit integer and 32-bit float analog input events with and without 48-bit DNP3 event timestamps) into `ExtractedDataPointRecord`.
- [ ] Decodes **Group 12** (Var 1 `CROB`) on `ClientToServer` control requests (`Select` FC 3, `Operate` FC 4, `DirectOperate` FC 5), emitting `CapturedCommandEventRecord` items with `CommandType` (`DNP3_CROB_SELECT`, `DNP3_CROB_OPERATE`, `DNP3_DIRECT_OPERATE`), `ControlAction` (`PULSE_ON`, `PULSE_OFF`, `LATCH_ON`, `LATCH_OFF`, `TRIP`, `CLOSE`), `CommandCount`, `PulseOnMs`, `PulseOffMs`, and `RawPduBytes`.
- [ ] Verified by unit tests covering 48-bit DNP3 timestamp conversion and each event/CROB variation.

