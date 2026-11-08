# 02: Generalized Endianness & 16/32/64-Bit Unpacking in Modbus TCP Decoder + Documentation

**What to build:** Decode 16-bit (`INT16`, `UINT16`), 32-bit (`INT32`, `UINT32`, `FLOAT32`), and 64-bit (`INT64`, `UINT64`, `FLOAT64`) Modbus TCP registers across all four word/byte endianness permutations (`ABCD`, `CDAB`, `BADC`, `DCBA`) for both register read responses (FC 03, FC 04) and register write requests (FC 06, FC 16), and document the updated CSV schema and byte-mapping rules.

**Blocked by:** 01: Tag DataType Expansion, RegisterEndianness Domain Model, 9-Column CSV Loader & Persistence Seam

**Status:** resolved

- [x] Reorders wire bytes `[B0, B1, ...]` into Big-Endian evaluation order prior to unpacking according to `TagDefinition.Endianness`:
  - `ABCD` (Big-Endian words, Big-Endian bytes): 16-bit `[B0,B1]`, 32-bit `[B0,B1,B2,B3]`, 64-bit `[B0,B1,B2,B3,B4,B5,B6,B7]`
  - `CDAB` (Little-Endian words, Big-Endian bytes): 16-bit `[B0,B1]`, 32-bit `[B2,B3,B0,B1]`, 64-bit `[B6,B7,B4,B5,B2,B3,B0,B1]`
  - `BADC` (Big-Endian words, Little-Endian bytes): 16-bit `[B1,B0]`, 32-bit `[B1,B0,B3,B2]`, 64-bit `[B1,B0,B3,B2,B5,B4,B7,B6]`
  - `DCBA` (Little-Endian words, Little-Endian bytes): 16-bit `[B1,B0]`, 32-bit `[B3,B2,B1,B0]`, 64-bit `[B7,B6,B5,B4,B3,B2,B1,B0]`
- [x] Unpacks `INT16`, `UINT16`, `INT32`, `UINT32`, `INT64`, `UINT64`, `FLOAT32`, and `FLOAT64` in Modbus TCP FC 03, FC 04, FC 06, and FC 16, advancing by 1 register for 16-bit, 2 registers for 32-bit, and 4 registers for 64-bit tags.
- [x] Preserves exact pre-swap wire byte order in `ExtractedDataPointRecord.RawHex` and skips emitting a data point if fewer than 2 remaining registers (32-bit) or 4 remaining registers (64-bit) are present in the frame.
- [x] Populates `CapturedCommandEventRecord.UnscaledCommandValue` on FC 06 and FC 16 using the tag's `DataType` and `Endianness` when a write targets a single complete tag (1, 2, or 4 registers), defaults unmapped 1-register writes to `UINT16` (`ABCD`), and sets `UnscaledCommandValue = null` when a write spans multiple tags.
- [x] Updates `README.md` (including the 9-column CSV specification and the endianness byte-mapping reference table) and `SPECIFICATION.md` to reflect the new data types, endianness column, and database schema.
- [x] Verified by unit tests covering 16-bit, 32-bit, and 64-bit data types across `ABCD`, `CDAB`, `BADC`, and `DCBA` endianness modes for both read responses and write requests, including truncated multi-register boundary handling.
