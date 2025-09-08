using System;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace Arcus.Security.Tests.Integration
{
    public class XunitLogEventSink : ILogEventSink
    {
        private readonly ITestOutputHelper _outputWriter;

        //
        // Summary:
        //     Initializes a new instance of the Arcus.Testing.XunitLogEventSink class.
        //
        // Parameters:
        //   outputWriter:
        //     The xUnit test output writer to write custom test output.
        //
        // Exceptions:
        //   T:System.ArgumentNullException:
        //     Thrown when the outputWriter is null.
        public XunitLogEventSink(ITestOutputHelper outputWriter)
        {
            if (outputWriter == null)
            {
                throw new ArgumentNullException("outputWriter");
            }

            _outputWriter = outputWriter;
        }

        //
        // Summary:
        //     Emit the provided log event to the sink.
        //
        // Parameters:
        //   logEvent:
        //     The log event to write.
        public void Emit(LogEvent logEvent)
        {
            _outputWriter.WriteLine(logEvent.RenderMessage());
        }
    }
}