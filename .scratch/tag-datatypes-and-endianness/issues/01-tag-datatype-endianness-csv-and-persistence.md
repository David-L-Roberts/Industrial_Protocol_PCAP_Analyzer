# 01: Tag DataType Expansion, RegisterEndianness Domain Model, 9-Column CSV Loader & Persistence Seam

**What to build:** Expand `TagDefinition` domain modeling, CSV ingestion, and TimescaleDB persistence to support the full set of tag data types (`BOOL`, `INT16`, `UINT16`, `INT32`, `UINT32`, `INT64`, `UINT64`, `FLOAT32`, `FLOAT64`) and explicit register endianness (`ABCD`, `DCBA`, `BADC`, `CDAB`). Replace the legacy `FLOAT32_BE` and `FLOAT32_SWAPPED` data types cleanly with `FLOAT32` plus `RegisterEndianness`, update the tag mapping CSV parser to require the 9-column format (`Protocol,Address,TagName,DataType,Endianness,ScaleMultiplier,ScaleOffset,Units,Description`) where blank `Endianness` defaults to `ABCD`, and persist both `data_type` and `endianness` to `tag_definitions`.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] `TagDataType` defines `Bool`, `Int16`, `UInt16`, `Int32`, `UInt32`, `Int64`, `UInt64`, `Float32`, and `Float64` (`Float32Be` and `Float32Swapped` are removed).
- [x] `RegisterEndianness` defines `Abcd`, `Dcba`, `Badc`, and `Cdab`, and `TagDefinition` includes `RegisterEndianness Endianness = RegisterEndianness.Abcd`.
- [x] Tag mapping CSV loader parses the 9-column schema (`Protocol,Address,TagName,DataType,Endianness,ScaleMultiplier,ScaleOffset,Units,Description`), parsing `DataType` and `Endianness` case-insensitively, defaulting an empty/blank `Endianness` cell to `Abcd`, and throwing `FormatException` on invalid column counts, legacy `FLOAT32_BE`/`FLOAT32_SWAPPED` names, or unsupported `DataType`/`Endianness` values.
- [x] Database schema (`tag_definitions`) and persistence wire format serialize `data_type` (`BOOL`, `INT16`, `UINT16`, `INT32`, `UINT32`, `INT64`, `UINT64`, `FLOAT32`, `FLOAT64`) and `endianness` (`VARCHAR(10) NOT NULL DEFAULT 'ABCD'` with values `ABCD`, `DCBA`, `BADC`, `CDAB`).
- [x] Existing unit and integration test CSV fixtures and `TagDefinition` call sites are updated to the new 9-column schema and `Float32` + `RegisterEndianness`, with all unit tests passing.
