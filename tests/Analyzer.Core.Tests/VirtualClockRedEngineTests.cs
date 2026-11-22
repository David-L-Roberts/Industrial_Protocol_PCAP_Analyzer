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
            statusCode: TransactionStatusCode.Success,
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
        Assert.Equal(TransactionErrorType.None, okTx.ErrorType);
        Assert.Equal(TransactionStatusCode.Success, okTx.StatusCode);

        // Duplicate response for already-completed request returns false
        Assert.False(engine.TryCompleteResponse<string>(
            pairId, "TX-001", 12, t0.AddMilliseconds(50), 3, false, TransactionStatusCode.Success, out _, out _));

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
            statusCode: TransactionStatusCode.ModbusEx02,
            out var exTx,
            out _);

        Assert.True(matchedEx);
        Assert.NotNull(exTx);
        Assert.Equal(12.25, exTx.DurationMs!.Value, precision: 5);
        Assert.True(exTx.IsError);
        Assert.Equal(TransactionErrorType.Exception, exTx.ErrorType);
        Assert.Equal(TransactionStatusCode.ModbusEx02, exTx.StatusCode);
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
        Assert.True(engine.TryCompleteResponse(pairId, "TX-2", 4, t0.AddMilliseconds(600), 3, false, TransactionStatusCode.Success, out _));

        // At exact threshold T + 1500ms, TX-1 is NOT yet > 1500ms
        var beforeThreshold = engine.FlushExpiredTimeouts(t0.AddMilliseconds(1500), isEndOfFile: false);
        Assert.Empty(beforeThreshold.Transactions);
        Assert.Empty(beforeThreshold.TraceSpans);

        // At T + 1600ms, TX-1 (elapsed 1600ms > 1500ms) expires as TIMEOUT; TX-2 was already answered; TX-3 (elapsed 600ms) remains pending
        var midStreamTimeouts = engine.FlushExpiredTimeouts(t0.AddMilliseconds(1600), isEndOfFile: false);
        var timeoutRec = Assert.Single(midStreamTimeouts.Transactions);
        Assert.Empty(midStreamTimeouts.TraceSpans);
        Assert.Equal(t0, timeoutRec.Timestamp);
        Assert.Equal(sessionId, timeoutRec.SessionId);
        Assert.Equal(pairId, timeoutRec.DevicePairId);
        Assert.Equal(1, timeoutRec.FrameNumber);
        Assert.Equal(TrafficDirection.ClientToServer, timeoutRec.Direction);
        Assert.Equal("TX-1", timeoutRec.TransactionId);
        Assert.Equal(3, timeoutRec.FunctionCode);
        Assert.Equal(1500.0, timeoutRec.DurationMs!.Value, precision: 5);
        Assert.True(timeoutRec.IsError);
        Assert.Equal(TransactionErrorType.Timeout, timeoutRec.ErrorType);
        Assert.Equal(TransactionStatusCode.Timeout, timeoutRec.StatusCode);

        // Late response for already timed-out TX-1 is ignored
        Assert.False(engine.TryCompleteResponse(pairId, "TX-1", 5, t0.AddMilliseconds(1700), 3, false, TransactionStatusCode.Success, out _));

        // At EOF (T + 2000ms), remaining unanswered TX-3 is flushed as TIMEOUT_AT_EOF
        var eofTimeouts = engine.FlushExpiredTimeouts(t0.AddMilliseconds(2000), isEndOfFile: true);
        var eofRec = Assert.Single(eofTimeouts.Transactions);
        Assert.Empty(eofTimeouts.TraceSpans);
        Assert.Equal(t0.AddMilliseconds(1000), eofRec.Timestamp);
        Assert.Equal(3, eofRec.FrameNumber);
        Assert.Equal(TrafficDirection.ClientToServer, eofRec.Direction);
        Assert.Equal("TX-3", eofRec.TransactionId);
        Assert.Equal(4, eofRec.FunctionCode);
        Assert.Equal(1000.0, eofRec.DurationMs!.Value, precision: 5);
        Assert.True(eofRec.IsError);
        Assert.Equal(TransactionErrorType.TimeoutAtEof, eofRec.ErrorType);
        Assert.Equal(TransactionStatusCode.TimeoutAtEof, eofRec.StatusCode);

        // Subsequent flush is empty
        var afterEof = engine.FlushExpiredTimeouts(t0.AddMilliseconds(3000), isEndOfFile: true);
        Assert.Empty(afterEof.Transactions);
        Assert.Empty(afterEof.TraceSpans);
    }

    [Fact]
    public void TryCompleteResponse_WithPendingSpanContext_PropagatesContextAndStampsTraceIdsInBothOverloads()
    {
        var sessionId = Guid.NewGuid();
        var pairId = Guid.NewGuid();
        var engine = new VirtualClockRedEngine(timeoutThresholdMs: 2000);
        var t0 = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

        var traceId1 = DeterministicTraceIdGenerator.CreateTraceId(sessionId, pairId, 10, SpanCorrelationRole.Transaction);
        var spanId1 = DeterministicTraceIdGenerator.CreateSpanId(sessionId, pairId, 10, SpanCorrelationRole.Transaction);
        var requestEvent1 = new SpanEventRecord(
            t0,
            SpanEventKind.RequestSent,
            "request_sent",
            new Dictionary<string, object?> { ["frame"] = 10L });

        var spanContext1 = new PendingSpanContext(
            TraceId: traceId1,
            SpanId: spanId1,
            ParentSpanId: null,
            ServiceName: "Feeder1_Relay",
            OperationName: "Modbus FC03 ReadHoldingRegisters",
            Protocol: ProtocolType.ModbusTcp,
            ClientEndpoint: "SEL_RTAC",
            ServerEndpoint: "Feeder1_Relay",
            Attributes: new Dictionary<string, object?> { ["modbus.unit_id"] = 1 },
            Events: [requestEvent1]);

        engine.RegisterRequest(
            sessionId: sessionId,
            devicePairId: pairId,
            frameNumber: 10,
            timestampUtc: t0,
            transactionId: "TX-10",
            functionCode: 3,
            requestContext: "CTX-10",
            spanContext: spanContext1);

        Assert.True(engine.TryCompleteResponse<string>(
            devicePairId: pairId,
            transactionId: "TX-10",
            responseFrameNumber: 11,
            responseTimestampUtc: t0.AddMilliseconds(25),
            responseFunctionCode: 3,
            isException: false,
            statusCode: TransactionStatusCode.Success,
            out var tx1,
            out var reqCtx1,
            out var outSpanCtx1));

        Assert.Equal("CTX-10", reqCtx1);
        Assert.NotNull(tx1);
        Assert.Equal(traceId1, tx1.TraceId);
        Assert.Equal(spanId1, tx1.SpanId);
        Assert.NotNull(outSpanCtx1);
        Assert.Equal(traceId1, outSpanCtx1.TraceId);
        Assert.Equal(spanId1, outSpanCtx1.SpanId);
        Assert.Equal(t0, outSpanCtx1.RequestTimestampUtc);
        Assert.Equal(10L, outSpanCtx1.RequestFrameNumber);

        var traceId2 = DeterministicTraceIdGenerator.CreateTraceId(sessionId, pairId, 20, SpanCorrelationRole.SboOperate);
        var spanId2 = DeterministicTraceIdGenerator.CreateSpanId(sessionId, pairId, 20, SpanCorrelationRole.SboOperate);
        var parentSpanId2 = DeterministicTraceIdGenerator.CreateSpanId(sessionId, pairId, 18, SpanCorrelationRole.SboSelect);

        var spanContext2 = new PendingSpanContext(
            TraceId: traceId2,
            SpanId: spanId2,
            ParentSpanId: parentSpanId2,
            ServiceName: "Feeder1_Relay",
            OperationName: "DNP3 FC04 Operate",
            Protocol: ProtocolType.Dnp3,
            ClientEndpoint: "SCADA_Master",
            ServerEndpoint: "Feeder1_Relay",
            Attributes: new Dictionary<string, object?>(),
            Events: []);

        engine.RegisterRequest(
            sessionId: sessionId,
            devicePairId: pairId,
            frameNumber: 20,
            timestampUtc: t0.AddMilliseconds(100),
            transactionId: "TX-20",
            functionCode: 4,
            spanContext: spanContext2);

        Assert.True(engine.TryCompleteResponse(
            devicePairId: pairId,
            transactionId: "TX-20",
            responseFrameNumber: 21,
            responseTimestampUtc: t0.AddMilliseconds(140),
            responseFunctionCode: 0x81,
            isException: false,
            statusCode: TransactionStatusCode.Success,
            out var tx2,
            out var outSpanCtx2));

        Assert.NotNull(tx2);
        Assert.Equal(traceId2, tx2.TraceId);
        Assert.Equal(spanId2, tx2.SpanId);
        Assert.NotNull(outSpanCtx2);
        Assert.Equal(parentSpanId2, outSpanCtx2.ParentSpanId);
        Assert.Equal(t0.AddMilliseconds(100), outSpanCtx2.RequestTimestampUtc);
        Assert.Equal(20L, outSpanCtx2.RequestFrameNumber);
    }

    [Fact]
    public void FlushExpiredTimeouts_WithPendingSpanContext_EmitsTimeoutAndTimeoutAtEofSpansUsingVirtualClock()
    {
        var sessionId = Guid.NewGuid();
        var pairId = Guid.NewGuid();
        var engine = new VirtualClockRedEngine(timeoutThresholdMs: 1500);
        var t0 = new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc);

        var trace1 = DeterministicTraceIdGenerator.CreateTraceId(sessionId, pairId, 1, SpanCorrelationRole.Transaction);
        var span1 = DeterministicTraceIdGenerator.CreateSpanId(sessionId, pairId, 1, SpanCorrelationRole.Transaction);
        var reqEvent1 = new SpanEventRecord(
            t0,
            SpanEventKind.RequestSent,
            "request_sent",
            new Dictionary<string, object?> { ["frame"] = 1L });

        engine.RegisterRequest(
            sessionId: sessionId,
            devicePairId: pairId,
            frameNumber: 1,
            timestampUtc: t0,
            transactionId: "TX-1",
            functionCode: 3,
            spanContext: new PendingSpanContext(
                TraceId: trace1,
                SpanId: span1,
                ParentSpanId: null,
                ServiceName: "Feeder1_Relay",
                OperationName: "Modbus FC03 ReadHoldingRegisters",
                Protocol: ProtocolType.ModbusTcp,
                ClientEndpoint: "SEL_RTAC",
                ServerEndpoint: "Feeder1_Relay",
                Attributes: new Dictionary<string, object?> { ["modbus.unit_id"] = 1 },
                Events: [reqEvent1]));

        var trace2 = DeterministicTraceIdGenerator.CreateTraceId(sessionId, pairId, 2, SpanCorrelationRole.Transaction);
        var span2 = DeterministicTraceIdGenerator.CreateSpanId(sessionId, pairId, 2, SpanCorrelationRole.Transaction);
        var req2Time = t0.AddMilliseconds(1000);
        var reqEvent2 = new SpanEventRecord(
            req2Time,
            SpanEventKind.RequestSent,
            "request_sent",
            new Dictionary<string, object?> { ["frame"] = 2L });

        engine.RegisterRequest(
            sessionId: sessionId,
            devicePairId: pairId,
            frameNumber: 2,
            timestampUtc: req2Time,
            transactionId: "TX-2",
            functionCode: 4,
            spanContext: new PendingSpanContext(
                TraceId: trace2,
                SpanId: span2,
                ParentSpanId: null,
                ServiceName: "Feeder1_Relay",
                OperationName: "Modbus FC04 ReadInputRegisters",
                Protocol: ProtocolType.ModbusTcp,
                ClientEndpoint: "SEL_RTAC",
                ServerEndpoint: "Feeder1_Relay",
                Attributes: new Dictionary<string, object?> { ["modbus.unit_id"] = 1 },
                Events: [reqEvent2]));

        var midStream = engine.FlushExpiredTimeouts(t0.AddMilliseconds(1600), isEndOfFile: false);
        var midTx = Assert.Single(midStream.Transactions);
        var midSpan = Assert.Single(midStream.TraceSpans);

        Assert.Equal(trace1, midTx.TraceId);
        Assert.Equal(span1, midTx.SpanId);
        Assert.Equal(trace1, midSpan.TraceId);
        Assert.Equal(span1, midSpan.SpanId);
        Assert.Null(midSpan.ParentSpanId);
        Assert.Equal(t0, midSpan.StartTimeUtc);
        Assert.Equal(t0.AddMilliseconds(1500), midSpan.EndTimeUtc);
        Assert.Equal(1500.0, midSpan.DurationMs, precision: 5);
        Assert.Equal(SpanOriginKind.Timeout, midSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Error, midSpan.StatusCode);
        Assert.Equal("TIMEOUT", midSpan.StatusMessage);
        Assert.Equal(1L, midSpan.RequestFrameNumber);
        Assert.Null(midSpan.ResponseFrameNumber);
        Assert.Equal("TX-1", midSpan.TransactionId);
        Assert.Equal((short)3, midSpan.FunctionCode);
        Assert.Equal(2, midSpan.Events.Count);
        Assert.Equal(SpanEventKind.RequestSent, midSpan.Events[0].Kind);
        Assert.Equal(SpanEventKind.TimeoutExpired, midSpan.Events[1].Kind);
        Assert.Equal(t0.AddMilliseconds(1500), midSpan.Events[1].TimestampUtc);

        var eof = engine.FlushExpiredTimeouts(t0.AddMilliseconds(2000), isEndOfFile: true);
        var eofTx = Assert.Single(eof.Transactions);
        var eofSpan = Assert.Single(eof.TraceSpans);

        Assert.Equal(trace2, eofTx.TraceId);
        Assert.Equal(span2, eofTx.SpanId);
        Assert.Equal(trace2, eofSpan.TraceId);
        Assert.Equal(span2, eofSpan.SpanId);
        Assert.Equal(req2Time, eofSpan.StartTimeUtc);
        Assert.Equal(req2Time.AddMilliseconds(1000), eofSpan.EndTimeUtc);
        Assert.Equal(1000.0, eofSpan.DurationMs, precision: 5);
        Assert.Equal(SpanOriginKind.TimeoutAtEof, eofSpan.OriginKind);
        Assert.Equal(SpanStatusCode.Error, eofSpan.StatusCode);
        Assert.Equal("TIMEOUT_AT_EOF", eofSpan.StatusMessage);
        Assert.Equal(2L, eofSpan.RequestFrameNumber);
        Assert.Null(eofSpan.ResponseFrameNumber);
        Assert.Equal("TX-2", eofSpan.TransactionId);
        Assert.Equal((short)4, eofSpan.FunctionCode);
        Assert.Equal(2, eofSpan.Events.Count);
        Assert.Equal(SpanEventKind.RequestSent, eofSpan.Events[0].Kind);
        Assert.Equal(SpanEventKind.TimeoutExpired, eofSpan.Events[1].Kind);
        Assert.Equal(req2Time.AddMilliseconds(1000), eofSpan.Events[1].TimestampUtc);
    }
}
