using Analyzer.Core.Domain;
using Analyzer.Infrastructure.Mapping;

namespace Analyzer.Infrastructure.Tests;

public class CsvTagMappingLoaderTests
{
    [Fact]
    public void Parse_ValidCsvWithAllDataTypes_ReturnsScopedTagDefinitions()
    {
        const string csv = """
        Protocol,Address,TagName,DataType,ScaleMultiplier,ScaleOffset,Units,Description
        ModbusTCP,HR:40001,Bus_Volts_A,FLOAT32_BE,0.1,0.0,kV,Phase A Bus Voltage
        ModbusTCP,COIL:00005,Breaker_52A,BOOL,1.0,0.0,,Breaker Status
        ModbusTCP,IR:30010,Temp_C,INT16,0.5,-40.0,degC,
        ModbusTCP,HR:40010,Counter_Lo,UINT16,1.0,0.0,,
        ModbusTCP,HR:40020,Energy_Wh,INT32,10.0,0.0,Wh,Total Energy
        ModbusTCP,HR:40030,Freq_Hz,FLOAT32_SWAPPED,0.01,50.0,Hz,"System Frequency, Nominal 50Hz"
        """;

        var devicePairId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var loader = new CsvTagMappingLoader();

        using var reader = new StringReader(csv);
        var tags = loader.Parse(reader, devicePairId, ProtocolType.ModbusTcp);

        Assert.Equal(6, tags.Count);

        var t0 = tags[0];
        Assert.NotEqual(Guid.Empty, t0.Id);
        Assert.Equal(devicePairId, t0.DevicePairId);
        Assert.Equal("Bus_Volts_A", t0.TagName);
        Assert.Equal(ProtocolAddress.Parse("HR:40001"), t0.ProtocolAddress);
        Assert.Equal(TagDataType.Float32Be, t0.DataType);
        Assert.Equal(0.1, t0.ScaleMultiplier);
        Assert.Equal(0.0, t0.ScaleOffset);
        Assert.Equal("kV", t0.EngineeringUnits);
        Assert.Equal("Phase A Bus Voltage", t0.Description);

        var t1 = tags[1];
        Assert.Equal("Breaker_52A", t1.TagName);
        Assert.Equal(ProtocolAddress.Parse("COIL:00005"), t1.ProtocolAddress);
        Assert.Equal(TagDataType.Bool, t1.DataType);
        Assert.Null(t1.EngineeringUnits);
        Assert.Equal("Breaker Status", t1.Description);

        var t2 = tags[2];
        Assert.Equal(TagDataType.Int16, t2.DataType);
        Assert.Equal(0.5, t2.ScaleMultiplier);
        Assert.Equal(-40.0, t2.ScaleOffset);
        Assert.Equal("degC", t2.EngineeringUnits);
        Assert.Null(t2.Description);

        Assert.Equal(TagDataType.UInt16, tags[3].DataType);
        Assert.Equal(TagDataType.Int32, tags[4].DataType);

        var t5 = tags[5];
        Assert.Equal(TagDataType.Float32Swapped, t5.DataType);
        Assert.Equal("System Frequency, Nominal 50Hz", t5.Description);
    }

    [Theory]
    [InlineData("DNP3,G30V02:Idx0,Feeder_MW,INT16,0.01,0.0,MW,Active Power")]
    [InlineData("ModbusTCP,INVALID_ADDR,Tag1,INT16,1.0,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,,INT16,1.0,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,FLOAT64,1.0,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,INT16,not-a-num,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,INT16,1.0,not-a-num,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,INT16,1.0")]
    public void Parse_InvalidRowOrMismatchedProtocol_ThrowsFormatException(string badRow)
    {
        var csv = $"Protocol,Address,TagName,DataType,ScaleMultiplier,ScaleOffset,Units,Description\n{badRow}";
        var loader = new CsvTagMappingLoader();
        using var reader = new StringReader(csv);

        Assert.Throws<FormatException>(() => loader.Parse(reader, Guid.NewGuid(), ProtocolType.ModbusTcp));
    }

    [Fact]
    public void Parse_DuplicateProtocolAddressInSameDevicePair_ThrowsFormatException()
    {
        const string csv = """
        Protocol,Address,TagName,DataType,ScaleMultiplier,ScaleOffset,Units,Description
        DNP3,G30V02:Idx0,Feeder_MW_1,INT16,0.01,0.0,MW,First
        DNP3,g30v02:idx0,Feeder_MW_2,INT16,0.01,0.0,MW,Duplicate case-insensitive
        """;

        var loader = new CsvTagMappingLoader();
        using var reader = new StringReader(csv);

        Assert.Throws<FormatException>(() => loader.Parse(reader, Guid.NewGuid(), ProtocolType.Dnp3));
    }
}
