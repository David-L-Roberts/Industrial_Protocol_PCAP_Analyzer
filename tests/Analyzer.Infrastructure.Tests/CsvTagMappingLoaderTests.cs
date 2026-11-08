using Analyzer.Core.Domain;
using Analyzer.Infrastructure.Mapping;

namespace Analyzer.Infrastructure.Tests;

public class CsvTagMappingLoaderTests
{
    [Fact]
    public void Parse_ValidNineColumnCsvWithAllDataTypesAndEndianness_ReturnsScopedTagDefinitions()
    {
        const string csv = """
        Protocol,Address,TagName,DataType,Endianness,ScaleMultiplier,ScaleOffset,Units,Description
        ModbusTCP,HR:40001,Bus_Volts_A,FLOAT32,ABCD,0.1,0.0,kV,Phase A Bus Voltage
        ModbusTCP,COIL:00005,Breaker_52A,BOOL,,1.0,0.0,,Breaker Status
        ModbusTCP,IR:30010,Temp_C,INT16,badc,0.5,-40.0,degC,
        ModbusTCP,HR:40010,Counter_Lo,UINT16,dcba,1.0,0.0,,
        ModbusTCP,HR:40020,Energy_Wh,INT32,,10.0,0.0,Wh,Total Energy
        ModbusTCP,HR:40030,Freq_Hz,FLOAT32,CDAB,0.01,50.0,Hz,"System Frequency, Nominal 50Hz"
        ModbusTCP,HR:40040,Total_Cycles,UINT32,ABCD,1.0,0.0,cycles,Unsigned 32-bit Counter
        ModbusTCP,HR:40050,Signed_Energy_Total,INT64,CDAB,0.001,0.0,MWh,Signed 64-bit Total
        ModbusTCP,HR:40060,Unsigned_Energy_Total,UINT64,BADC,0.001,0.0,MWh,Unsigned 64-bit Total
        ModbusTCP,HR:40070,Precision_Freq,FLOAT64,DCBA,1.0,0.0,Hz,64-bit Float Frequency
        """;

        var devicePairId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var loader = new CsvTagMappingLoader();

        using var reader = new StringReader(csv);
        var tags = loader.Parse(reader, devicePairId, ProtocolType.ModbusTcp);

        Assert.Equal(10, tags.Count);

        var t0 = tags[0];
        Assert.NotEqual(Guid.Empty, t0.Id);
        Assert.Equal(devicePairId, t0.DevicePairId);
        Assert.Equal("Bus_Volts_A", t0.TagName);
        Assert.Equal(ProtocolAddress.Parse("HR:40001"), t0.ProtocolAddress);
        Assert.Equal(TagDataType.Float32, t0.DataType);
        Assert.Equal(RegisterEndianness.Abcd, t0.Endianness);
        Assert.Equal(0.1, t0.ScaleMultiplier);
        Assert.Equal(0.0, t0.ScaleOffset);
        Assert.Equal("kV", t0.EngineeringUnits);
        Assert.Equal("Phase A Bus Voltage", t0.Description);

        var t1 = tags[1];
        Assert.Equal("Breaker_52A", t1.TagName);
        Assert.Equal(ProtocolAddress.Parse("COIL:00005"), t1.ProtocolAddress);
        Assert.Equal(TagDataType.Bool, t1.DataType);
        Assert.Equal(RegisterEndianness.Abcd, t1.Endianness);
        Assert.Null(t1.EngineeringUnits);
        Assert.Equal("Breaker Status", t1.Description);

        var t2 = tags[2];
        Assert.Equal(TagDataType.Int16, t2.DataType);
        Assert.Equal(RegisterEndianness.Badc, t2.Endianness);
        Assert.Equal(0.5, t2.ScaleMultiplier);
        Assert.Equal(-40.0, t2.ScaleOffset);
        Assert.Equal("degC", t2.EngineeringUnits);
        Assert.Null(t2.Description);

        Assert.Equal(TagDataType.UInt16, tags[3].DataType);
        Assert.Equal(RegisterEndianness.Dcba, tags[3].Endianness);

        Assert.Equal(TagDataType.Int32, tags[4].DataType);
        Assert.Equal(RegisterEndianness.Abcd, tags[4].Endianness);

        var t5 = tags[5];
        Assert.Equal(TagDataType.Float32, t5.DataType);
        Assert.Equal(RegisterEndianness.Cdab, t5.Endianness);
        Assert.Equal("System Frequency, Nominal 50Hz", t5.Description);

        Assert.Equal(TagDataType.UInt32, tags[6].DataType);
        Assert.Equal(RegisterEndianness.Abcd, tags[6].Endianness);

        Assert.Equal(TagDataType.Int64, tags[7].DataType);
        Assert.Equal(RegisterEndianness.Cdab, tags[7].Endianness);

        Assert.Equal(TagDataType.UInt64, tags[8].DataType);
        Assert.Equal(RegisterEndianness.Badc, tags[8].Endianness);

        Assert.Equal(TagDataType.Float64, tags[9].DataType);
        Assert.Equal(RegisterEndianness.Dcba, tags[9].Endianness);
    }

    [Theory]
    [InlineData("DNP3,G30V02:Idx0,Feeder_MW,INT16,,0.01,0.0,MW,Active Power")]
    [InlineData("ModbusTCP,INVALID_ADDR,Tag1,INT16,ABCD,1.0,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,,INT16,ABCD,1.0,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,FLOAT32_BE,ABCD,1.0,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,FLOAT32_SWAPPED,CDAB,1.0,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,FLOAT128,ABCD,1.0,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,FLOAT32,WXYZ,1.0,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,INT16,ABCD,not-a-num,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,INT16,ABCD,1.0,not-a-num,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,INT16,1.0,0.0,,")]
    [InlineData("ModbusTCP,HR:40001,Tag1,INT16,1.0")]
    public void Parse_InvalidRowOrMismatchedProtocol_ThrowsFormatException(string badRow)
    {
        var csv = $"Protocol,Address,TagName,DataType,Endianness,ScaleMultiplier,ScaleOffset,Units,Description\n{badRow}";
        var loader = new CsvTagMappingLoader();
        using var reader = new StringReader(csv);

        Assert.Throws<FormatException>(() => loader.Parse(reader, Guid.NewGuid(), ProtocolType.ModbusTcp));
    }

    [Fact]
    public void Parse_DuplicateProtocolAddressInSameDevicePair_ThrowsFormatException()
    {
        const string csv = """
        Protocol,Address,TagName,DataType,Endianness,ScaleMultiplier,ScaleOffset,Units,Description
        DNP3,G30V02:Idx0,Feeder_MW_1,INT16,,0.01,0.0,MW,First
        DNP3,g30v02:idx0,Feeder_MW_2,INT16,,0.01,0.0,MW,Duplicate case-insensitive
        """;

        var loader = new CsvTagMappingLoader();
        using var reader = new StringReader(csv);

        Assert.Throws<FormatException>(() => loader.Parse(reader, Guid.NewGuid(), ProtocolType.Dnp3));
    }
}
