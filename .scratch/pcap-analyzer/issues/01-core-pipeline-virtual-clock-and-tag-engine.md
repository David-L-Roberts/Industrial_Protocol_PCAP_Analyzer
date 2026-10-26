# 01: Core Pipeline, Virtual Clock RED Engine & Tag Resolution Engine

**What to build:** An in-memory ingestion pipeline orchestrator coupled with the Virtual Clock RED Engine and Tag Resolution Engine. When a stream of Dissected Frames is fed through the pipeline for a Test Session, each frame is matched to its configured Device Endpoint Pair by IP and protocol address, assigned a Traffic Direction, and evaluated for request timeouts and response latency strictly using the Virtual Clock (`TimestampUtc`, never wall-clock time). Decoded tag values are linearly scaled ($y = mx + c$), evaluated against the last known state cache to flag state transitions (`IsValueChange`), and recorded as $T_0$ Initial States on their first appearance. At end-of-file, any remaining pending requests are flushed as `TIMEOUT_AT_EOF`.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Matches incoming Dissected Frames to configured Device Endpoint Pairs and determines `ClientToServer` vs. `ServerToClient` Traffic Direction (ignoring unmatched frames).
- [ ] Evaluates pending request expiration strictly using `DissectedFrame.TimestampUtc` against the session's `TimeoutThresholdMs`, emitting `TIMEOUT` RED Transaction records when exceeded.
- [ ] Correlates `ServerToClient` responses with pending `ClientToServer` requests to calculate `DurationMs` and emit `SUCCESS` or `EXCEPTION` RED Transaction records.
- [ ] Flushes all remaining unanswered requests at the end of the frame stream as `TIMEOUT_AT_EOF` RED Transaction records.
- [ ] Resolves protocol addresses to mapped Tag Definitions, applies linear scaling (`(unscaled * ScaleMultiplier) + ScaleOffset`), sets `IsValueChange = true` when scaled value, boolean value, or quality flags change, and captures $T_0$ Initial State on first observation per tag.
- [ ] Verified by unit tests using synthetic Dissected Frame streams with zero external binary or database dependencies.

