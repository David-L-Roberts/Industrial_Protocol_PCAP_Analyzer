# 02: Throttled 5-second packet dissection progress status lines

**What to build:** While the CLI is streaming and decoding `DissectedFrame` traffic during a `TestSession`, the user sees a periodic append-only status line every 5 seconds of elapsed wall-clock time showing live counters and the current Virtual Clock capture timestamp. This confirms that packet processing is actively progressing without flooding the terminal or using carriage-return overwrites.

Each periodic status line follows the compact single-line format:
`  [mm:ss] Frames: <total> (<matched> matched) | Tx: <transactions> | Records: <total_records> | Capture time: <yyyy-MM-dd HH:mm:ss> UTC`

where `<total_records>` is the combined count of persisted Extracted Data Points, Captured Command Events, and Unmapped Registers (only counting Unmapped Registers when the session is configured to store them).

**Blocked by:** 01: Pipeline lifecycle phase milestones in CLI analysis output

**Status:** resolved

- [x] During the `DissectingPackets` phase, `PipelineProgress` snapshots include running counts for total frames processed, matched frames processed, RED transactions, combined persisted records, and the latest `DissectedFrame` Virtual Clock UTC timestamp.
- [x] The CLI throttles `DissectingPackets` progress output using an injectable `TimeProvider` (defaulting to system wall-clock time) so that a status line is written at most once every 5 seconds of elapsed wall-clock time as frames are processed.
- [x] Status lines format elapsed time as `[mm:ss]` (or `[hh:mm:ss]` if a run exceeds one hour), format integer counters with thousands separators (`N0` invariant formatting), and format the packet Virtual Clock timestamp as `yyyy-MM-dd HH:mm:ss UTC`.
- [x] No new CLI flags are introduced; the 5-second progress interval is active by default whenever progress output is provided.
- [x] Deterministic unit tests using a controllable `TimeProvider` verify that status lines are emitted at 5-second intervals, suppressed between intervals, and accurately reflect frame, transaction, record, and Virtual Clock metrics.
