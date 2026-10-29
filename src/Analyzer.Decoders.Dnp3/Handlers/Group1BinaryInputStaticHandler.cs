using Analyzer.Core.Domain;
using Analyzer.Core.Interfaces;
using Analyzer.Core.Services;

namespace Analyzer.Decoders.Dnp3.Handlers;

public class Group1BinaryInputStaticHandler : IDnp3ObjectGroupHandler
{
    private readonly TagResolutionEngine _tagEngine;

    public Group1BinaryInputStaticHandler(TagResolutionEngine tagEngine)
    {
        ArgumentNullException.ThrowIfNull(tagEngine);
        _tagEngine = tagEngine;
    }

    public ushort Group => 1;

    public void ExtractObjects(
        DissectedFrame frame,
        DeviceEndpointPair pair,
        TrafficDirection direction,
        ushort variation,
        ReadOnlySpan<byte> objectData,
        ICollection<ExtractedDataPointRecord> dataPointsOut,
        ICollection<CapturedCommandEventRecord> commandsOut)
    {
        ArgumentNullException.ThrowIfNull(commandsOut);
        Dnp3BinaryGroupHelper.ExtractBinaryGroup(
            _tagEngine,
            frame,
            pair,
            direction,
            Group,
            variation,
            objectData,
            dataPointsOut);
    }
}
