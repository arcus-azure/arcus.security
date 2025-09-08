using System;
using Serilog;
using Serilog.Configuration;
using Xunit;

namespace Arcus.Security.Tests.Integration
{
    public static class LoggerSinkConfigurationExtensions
    {
        //
        // Summary:
        //     Adds the Arcus.Testing.XunitLogEventSink to the Serilog configuration to delegate
        //     Serilog log messages to the xUnit test outputWriter.
        //
        // Parameters:
        //   config:
        //     The Serilog sink configuration where the xUnit test logging will be added.
        //
        //   outputWriter:
        //     The xUnit test output writer to write custom test output.
        //
        // Exceptions:
        //   T:System.ArgumentNullException:
        //     Thrown when the config or outputWriter is null.
        public static LoggerConfiguration XunitTestLogging(this LoggerSinkConfiguration config, ITestOutputHelper outputWriter)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }

            if (outputWriter == null)
            {
                throw new ArgumentNullException("outputWriter");
            }

            return config.Sink(new XunitLogEventSink(outputWriter));
        }
    }
}