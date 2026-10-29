using System.Diagnostics.CodeAnalysis;
using Analyzer.Core.Interfaces;

namespace Analyzer.Decoders.Dnp3.Registry;

public class Dnp3HandlerRegistry
{
    private readonly Dictionary<ushort, IDnp3ObjectGroupHandler> _handlersByGroup = new();

    public Dnp3HandlerRegistry(IEnumerable<IDnp3ObjectGroupHandler> handlers)
    {
        ArgumentNullException.ThrowIfNull(handlers);

        foreach (var handler in handlers)
        {
            _handlersByGroup[handler.Group] = handler;
        }
    }

    public bool TryGetHandler(ushort group, [NotNullWhen(true)] out IDnp3ObjectGroupHandler? handler) =>
        _handlersByGroup.TryGetValue(group, out handler);
}

