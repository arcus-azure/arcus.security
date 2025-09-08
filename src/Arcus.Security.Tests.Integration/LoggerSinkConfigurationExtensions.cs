using System;
using Serilog;
using Serilog.Configuration;
using Xunit;

namespace Arcus.Security.Tests.Integration
{
    // TODO: This class is copied from old Arcus.Testing, and should be replaced with a more appropriate one before complete the issue.
    public static class LoggerSinkConfigurationExtensions
    {
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