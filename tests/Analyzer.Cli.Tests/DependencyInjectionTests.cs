using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Pipeline;
using Analyzer.Core.Services;
using Analyzer.Decoders.Dnp3;
using Analyzer.Decoders.Dnp3.Registry;
using Analyzer.Decoders.Modbus;
using Analyzer.Infrastructure.Mapping;
using Analyzer.Cli;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Analyzer.Cli.Tests;

public class DependencyInjectionTests
{
    [Fact]
    public void AddAnalyzerCoreServices_RegistersManifestAndCsvLoaders()
    {
        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();

        var sp = services.BuildServiceProvider();

        Assert.NotNull(sp.GetService<ManifestParser>());
        Assert.NotNull(sp.GetService<CsvTagMappingLoader>());
    }

    [Fact]
    public void AddAnalyzerCoreServices_ResolvesAllDnp3HandlersAndDecodersAndOrchestrator()
    {
        var services = new ServiceCollection();
        services.AddAnalyzerCoreServices();

        // Provide test engines and sink/source
        services.AddSingleton(new VirtualClockRedEngine(1000));
        services.AddSingleton(new TagResolutionEngine([]));
        services.AddSingleton<IFrameSource>(new TestFrameSource());
        services.AddSingleton<IDataSink>(new TestDataSink());

        var sp = services.BuildServiceProvider();

        var handlers = sp.GetServices<IDnp3ObjectGroupHandler>().ToList();
        Assert.Equal(8, handlers.Count);

        var groups = handlers.Select(h => h.Group).OrderBy(g => g).ToList();
        Assert.Equal(new ushort[] { 1, 2, 10, 12, 20, 22, 30, 32 }, groups);

        var registry = sp.GetService<Dnp3HandlerRegistry>();
        Assert.NotNull(registry);

        var decoders = sp.GetServices<IProtocolDecoder>().ToList();
        Assert.Equal(2, decoders.Count);
        Assert.Contains(decoders, d => d is ModbusTcpDecoder);
        Assert.Contains(decoders, d => d is Dnp3Decoder);

        var orchestrator = sp.GetService<IngestionPipelineOrchestrator>();
        Assert.NotNull(orchestrator);

        var runner = sp.GetService<IAnalysisRunner>();
        Assert.NotNull(runner);
    }

    private sealed class TestFrameSource : IFrameSource
    {
        public async IAsyncEnumerable<DissectedFrame> ReadFramesAsync(
            string pcapFilePath,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
        {
            await Task.Yield();
            yield break;
        }
    }

    private sealed class TestDataSink : IDataSink
    {
        public Task InitializeSessionAsync(TestSession session, IEnumerable<DeviceEndpointPair> pairs, IEnumerable<TagDefinition> tags, CancellationToken ct) => Task.CompletedTask;
        public Task WriteBatchAsync(ProtocolDecodeOutput batch, CancellationToken ct) => Task.CompletedTask;
        public Task UpdateTagInitialStatesAsync(Guid sessionId, CancellationToken ct) => Task.CompletedTask;
        public Task CompleteSessionAsync(Guid sessionId, SessionStatus status, CancellationToken ct) => Task.CompletedTask;
    }
}

