using Analyzer.Core.Domain;
using Analyzer.Core.Services;

namespace Analyzer.Core.Tests;

public class VirtualClockRedEngineTests
{
    [Fact]
    public void TryCompleteResponse_MatchingPendingRequest_CalculatesVirtualClockDurationAndEmitsSuccessOrException()
    {
        var sessionId = Guid.NewGuid();
        var pairId = Guid.NewGuid();
        var engine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var t0 = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

        // 1. Register normal request with context and complete it 45.5 ms later
        engine.RegisterRequest(
            sessionId: sessionId,
            devicePairId: pairId,
            frameNumber: 10,
            timestampUtc: t0,
            transactionId: "TX-001",
            functionCode: 3,
            requestContext: "HR:40001:Count2");

        var matchedOk = engine.TryCompleteResponse<string>(
            devicePairId: pairId,
            transactionId: "TX-001",
            responseFrameNumber: 11,
            responseTimestampUtc: t0.AddMilliseconds(45.5),
            responseFunctionCode: 3,
            isException: false,
            statusCode: "SUCCESS",
            out var okTx,
            out var context);

        Assert.True(matchedOk);
        Assert.Equal("HR:40001:Count2", context);
        Assert.NotNull(okTx);
        Assert.Equal(t0.AddMilliseconds(45.5), okTx.Timestamp);
        Assert.Equal(sessionId, okTx.SessionId);
        Assert.Equal(pairId, okTx.DevicePairId);
        Assert.Equal(11, okTx.FrameNumber);
        Assert.Equal(TrafficDirection.ServerToClient, okTx.Direction);
        Assert.Equal("TX-001", okTx.TransactionId);
        Assert.Equal(3, okTx.FunctionCode);
        Assert.Equal(45.5, okTx.DurationMs!.Value, precision: 5);
        Assert.False(okTx.IsError);
        Assert.Equal("NONE", okTx.ErrorType);
        Assert.Equal("SUCCESS", okTx.StatusCode);

        // Duplicate response for already-completed request returns false
        Assert.False(engine.TryCompleteResponse<string>(
            pairId, "TX-001", 12, t0.AddMilliseconds(50), 3, false, "SUCCESS", out _, out _));

        // 2. Register request that receives a protocol exception response
        engine.RegisterRequest(
            sessionId: sessionId,
            devicePairId: pairId,
            frameNumber: 13,
            timestampUtc: t0.AddMilliseconds(100),
            transactionId: "TX-002",
            functionCode: 3);

        var matchedEx = engine.TryCompleteResponse<object>(
            devicePairId: pairId,
            transactionId: "TX-002",
            responseFrameNumber: 14,
            responseTimestampUtc: t0.AddMilliseconds(112.25),
            responseFunctionCode: 0x83,
            isException: true,
            statusCode: "MODBUS_EX_02",
            out var exTx,
            out _);

        Assert.True(matchedEx);
        Assert.NotNull(exTx);
        Assert.Equal(12.25, exTx.DurationMs!.Value, precision: 5);
        Assert.True(exTx.IsError);
        Assert.Equal("EXCEPTION", exTx.ErrorType);
        Assert.Equal("MODBUS_EX_02", exTx.StatusCode);
    }

    [Fact]
    public void FlushExpiredTimeouts_MidStreamAndEndOfFile_EmitsTimeoutAndTimeoutAtEofStrictlyUsingVirtualClock()
    {
        var sessionId = Guid.NewGuid();
        var pairId = Guid.NewGuid();
        var engine = new VirtualClockRedEngine(timeoutThresholdMs: 1500);
        var t0 = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

        // Request 1 at T + 0ms (will expire when T > 1500ms)
        engine.RegisterRequest(sessionId, pairId, frameNumber: 1, timestampUtc: t0, transactionId: "TX-1", functionCode: 3);
        // Request 2 at T + 500ms (will be answered at T + 600ms, so must NOT timeout later)
        engine.RegisterRequest(sessionId, pairId, frameNumber: 2, timestampUtc: t0.AddMilliseconds(500), transactionId: "TX-2", functionCode: 3);
        // Request 3 at T + 1000ms (will still be pending at T + 1600ms, then flushed at EOF at T + 2000ms)
        engine.RegisterRequest(sessionId, pairId, frameNumber: 3, timestampUtc: t0.AddMilliseconds(1000), transactionId: "TX-3", functionCode: 4);

        // Complete TX-2 at T + 600ms
        Assert.True(engine.TryCompleteResponse(pairId, "TX-2", 4, t0.AddMilliseconds(600), 3, false, "SUCCESS", out _));

        // At exact threshold T + 1500ms, TX-1 is NOT yet > 1500ms
        Assert.Empty(engine.FlushExpiredTimeouts(t0.AddMilliseconds(1500), isEndOfFile: false));

        // At T + 1600ms, TX-1 (elapsed 1600ms > 1500ms) expires as TIMEOUT; TX-2 was already answered; TX-3 (elapsed 600ms) remains pending
        var midStreamTimeouts = engine.FlushExpiredTimeouts(t0.AddMilliseconds(1600), isEndOfFile: false);
        var timeoutRec = Assert.Single(midStreamTimeouts);
        Assert.Equal(t0, timeoutRec.Timestamp);
        Assert.Equal(sessionId, timeoutRec.SessionId);
        Assert.Equal(pairId, timeoutRec.DevicePairId);
        Assert.Equal(1, timeoutRec.FrameNumber);
        Assert.Equal(TrafficDirection.ClientToServer, timeoutRec.Direction);
        Assert.Equal("TX-1", timeoutRec.TransactionId);
        Assert.Equal(3, timeoutRec.FunctionCode);
        Assert.Equal(1500.0, timeoutRec.DurationMs!.Value, precision: 5);
        Assert.True(timeoutRec.IsError);
        Assert.Equal("TIMEOUT", timeoutRec.ErrorType);
        Assert.Equal("TIMEOUT", timeoutRec.StatusCode);

        // Late response for already timed-out TX-1 is ignored
        Assert.False(engine.TryCompleteResponse(pairId, "TX-1", 5, t0.AddMilliseconds(1700), 3, false, "SUCCESS", out _));

        // At EOF (T + 2000ms), remaining unanswered TX-3 is flushed as TIMEOUT_AT_EOF
        var eofTimeouts = engine.FlushExpiredTimeouts(t0.AddMilliseconds(2000), isEndOfFile: true);
        var eofRec = Assert.Single(eofTimeouts);
        Assert.Equal(t0.AddMilliseconds(1000), eofRec.Timestamp);
        Assert.Equal(3, eofRec.FrameNumber);
        Assert.Equal(TrafficDirection.ClientToServer, eofRec.Direction);
        Assert.Equal("TX-3", eofRec.TransactionId);
        Assert.Equal(4, eofRec.FunctionCode);
        Assert.Equal(1000.0, eofRec.DurationMs!.Value, precision: 5);
        Assert.True(eofRec.IsError);
        Assert.Equal("TIMEOUT_AT_EOF", eofRec.ErrorType);
        Assert.Equal("TIMEOUT_AT_EOF", eofRec.StatusCode);

        // Subsequent flush is empty
        Assert.Empty(engine.FlushExpiredTimeouts(t0.AddMilliseconds(3000), isEndOfFile: true));
    }
}

