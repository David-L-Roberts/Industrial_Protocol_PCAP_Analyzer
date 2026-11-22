# 05: Grafana SQL Views, Trace & Topology Explorer Dashboard, Data Links & Spec Sync

**What to build:** Expose TimescaleDB's persisted **Trace Spans** through Grafana-native PostgreSQL views and provisioned dashboards so engineers can explore interactive Tempo-style trace waterfalls, multi-device time-window waterfalls, and live device-to-device topology graphs directly in Grafana—with 1-click drilldown from existing RED, command, and tag telemetry panels. Once end-to-end verification passes, synchronize the master engineering specification (`SPECIFICATION.md`) and promote `ADR 0002` to `Accepted`.

**Blocked by:** 02: Modbus TCP Trace Spans, Timeline Events & Cross-Table Correlation; 04: DNP3 Multi-Step Trace Correlation (Select-Before-Operate & Application Confirm)

**Status:** ready-for-agent

- [ ] `002_add_trace_spans.sql` defines idempotent (`CREATE OR REPLACE VIEW`) PostgreSQL views:
  - `v_grafana_traces` projecting Grafana's Traces DataFrame columns (`"traceID"`, `"spanID"`, `"parentSpanID"`, `"operationName"`, `"serviceName"`, `"startTime"` in epoch ms, `"duration"` in ms, `"statusCode"` `0/1/2`, `"statusMessage"`, `"serviceTags"` JSONB array, `"tags"` JSONB array, `"logs"` JSONB array) alongside filter columns (`session_id`, `device_pair_id`, `start_time_utc`, `origin_kind`, `protocol`).
  - `v_grafana_node_graph_nodes` projecting per-session device nodes (`id`, `title`, `"subTitle"`, `"mainStat"`, `"secondaryStat"`, `arc__success`, `arc__error`).
  - `v_grafana_node_graph_edges` projecting directed per-session links (`id`, `source`, `target`, `"mainStat"`, `"secondaryStat"`, `detail__protocol`, `detail__span_count`, `detail__error_count`, `detail__avg_duration_ms`, `detail__p95_duration_ms`), routing `SERVER_TO_CLIENT` unsolicited traffic from `server_endpoint` to `client_endpoint`.
- [ ] A new provisioned Grafana dashboard (**Industrial Protocol Trace & Topology Explorer**, UID `industrial-protocol-traces`) is added with `$session`, `$device_pair`, `$protocol`, `$status`, `$trace_id`, and `$window_bucket` template variables and panels for:
  - Device Communication Topology (Node Graph panel backed by `v_grafana_node_graph_nodes` and `v_grafana_node_graph_edges`),
  - Trace & Span Explorer table (with row click Data Link updating `$trace_id`),
  - Trace Waterfall (Traces panel backed by `v_grafana_traces` for `$trace_id`),
  - Time-Window Capture Waterfall (collapsible Traces panel aliasing `"traceID"` by time bucket across concurrent spans), and
  - Correlated Telemetry (`tag_values`) and Commands (`captured_command_events`) detail tables filtered by `$session` and `$trace_id`.
- [ ] The existing provisioned analyzer dashboard (`industrial_protocol_analyzer.json`) projects `trace_id` on RED error/transaction, captured command, and tag telemetry tables and wires 1-click Grafana Data Links to `/d/industrial-protocol-traces` passing `$session`, `trace_id`, and the active time range.
- [ ] Live integration tests ingest both the real Modbus and DNP3 PCAP fixtures into TimescaleDB and assert that `v_grafana_traces`, `v_grafana_node_graph_nodes`, and `v_grafana_node_graph_edges` execute cleanly and return non-empty, well-typed rows conforming to Grafana's Traces and Node Graph column contracts.
- [ ] The full solution builds with zero warnings (`dotnet build ProtocolAnalyzer.sln`) and all unit tests pass (`dotnet test ProtocolAnalyzer.sln`).
- [ ] Once the feature is complete and verified, `SPECIFICATION.md` is updated to reflect the trace/span schema, domain contracts, manifest/CLI options, and Grafana dashboards, and `ADR 0002` status is updated from `Proposed` to `Accepted`.
