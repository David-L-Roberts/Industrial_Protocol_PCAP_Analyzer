using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Pipeline;
using Analyzer.Core.Services;
using Analyzer.Decoders.Dnp3;
using Analyzer.Decoders.Dnp3.Handlers;
using Analyzer.Decoders.Dnp3.Registry;
using Analyzer.Decoders.Modbus;
using Analyzer.Infrastructure.Mapping;
using Microsoft.Extensions.DependencyInjection;

namespace Analyzer.Cli;

public static class AnalyzerServiceCollectionExtensions
{
    public static IServiceCollection AddAnalyzerCoreServices(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddTransient<ManifestParser>();
        services.AddTransient<CsvTagMappingLoader>();

        // Phase 1 DNP3 Handlers
        services.AddTransient<IDnp3ObjectGroupHandler, Group1BinaryInputStaticHandler>();
        services.AddTransient<IDnp3ObjectGroupHandler, Group2BinaryInputEventHandler>();
        services.AddTransient<IDnp3ObjectGroupHandler, Group10BinaryOutputStatusHandler>();
        services.AddTransient<IDnp3ObjectGroupHandler, Group12CrobControlHandler>();
        services.AddTransient<IDnp3ObjectGroupHandler, Group20RunningCounterHandler>();
        services.AddTransient<IDnp3ObjectGroupHandler, Group22CounterChangeEventHandler>();
        services.AddTransient<IDnp3ObjectGroupHandler, Group30AnalogInputStaticHandler>();
        services.AddTransient<IDnp3ObjectGroupHandler, Group32AnalogInputEventHandler>();

        services.AddTransient<Dnp3HandlerRegistry>();

        services.AddTransient<ModbusTcpDecoder>(sp =>
        {
            var redEngine = sp.GetRequiredService<VirtualClockRedEngine>();
            var tagEngine = sp.GetRequiredService<TagResolutionEngine>();
            var session = sp.GetService<TestSession>();
            bool storeUnmapped = session?.StoreUnmappedRegisters ?? false;
            return new ModbusTcpDecoder(redEngine, tagEngine, storeUnmapped);
        });

        services.AddTransient<Dnp3Decoder>();

        services.AddTransient<IProtocolDecoder>(sp => sp.GetRequiredService<ModbusTcpDecoder>());
        services.AddTransient<IProtocolDecoder>(sp => sp.GetRequiredService<Dnp3Decoder>());

        services.AddTransient<IngestionPipelineOrchestrator>(sp =>
        {
            var frameSource = sp.GetRequiredService<IFrameSource>();
            var decoders = sp.GetServices<IProtocolDecoder>();
            var dataSink = sp.GetRequiredService<IDataSink>();
            var options = sp.GetService<AnalysisOptions>();
            int batchSize = options?.BatchSize ?? IngestionPipelineOrchestrator.DefaultBatchSize;
            return new IngestionPipelineOrchestrator(frameSource, decoders, dataSink, batchSize);
        });
        services.AddTransient<IAnalysisInfrastructureFactory, DefaultAnalysisInfrastructureFactory>();
        services.AddTransient<IAnalysisRunner, AnalysisRunner>();

        return services;
    }
}
