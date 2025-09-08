using System;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace Arcus.Security.Tests.Integration.Serilog
{
    /// <summary>
    /// <see cref="ILogEventSink"/> representation of an <see cref="ITestOutputHelper"/> instance.
    /// </summary>
    public class XunitLogEventSink : ILogEventSink
    {
        private readonly ITestOutputHelper _outputWriter;

        /// <summary>
        /// Initializes a new instance of the Arcus.Testing.XunitLogEventSink class.
        /// </summary>
        /// <param name="outputWriter">The xUnit test output writer to write custom test output.</param>
        /// <exception cref="ArgumentNullException">Thrown when the outputWriter is null.</exception>
        public XunitLogEventSink(ITestOutputHelper outputWriter)
        {
            ArgumentNullException.ThrowIfNull(outputWriter);

            _outputWriter = outputWriter;
        }

        /// <summary>
        /// Emit the provided log event to the sink.
        /// </summary>
        /// <param name="logEvent">The log event to write.</param>
        public void Emit(LogEvent logEvent)
        {
            _outputWriter.WriteLine(logEvent.RenderMessage());
        }
    }
}