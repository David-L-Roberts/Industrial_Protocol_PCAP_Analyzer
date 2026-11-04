# 03: Live MinIO PCAP Archiving & Object Lifecycle Slice

**What to build:** End-to-end live object storage integration tests exercising PCAP capture archiving against the deployed MinIO server using a real capture file. Tests verify bucket existence checks and creation, deterministic `captures/<sessionId>/<fileName>` object key generation, streaming upload with appropriate PCAP/PCAPNG MIME content types, remote object stat verification, and automatic test object removal on teardown.

**Blocked by:** 01: Integration Test Harness, `.env` Configuration & Live Infrastructure Smoke Slice

**Status:** resolved

- [x] Archives a real capture file to the live MinIO server for a unique `TestSession` ID, ensuring the target bucket is created if it does not already exist.
- [x] Verifies via the MinIO client that the uploaded object exists under `captures/<sessionId>/<fileName>` with a byte length matching the source file on disk and the expected content type.
- [x] Automatically deletes the uploaded test object from MinIO during test teardown (`DisposeAsync`) unless `KEEP_TEST_DATA=true` is set.

