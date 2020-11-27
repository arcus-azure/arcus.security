using System;
using GuardNet;
using Serilog.Core;
using Serilog.Events;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration.Fixture
{
    /// <summary>
    /// xUnit test implementation of an Serilog <see cref="ILogEventSink"/> to delegate Serilog events to the xUnit <see cref="ITestOutputHelper"/>.
    /// </summary>
    public class XunitTestLogSink : ILogEventSink
    {
        private readonly ITestOutputHelper _outputWriter;

        /// <summary>
        /// Initializes a new instance of the <see cref="XunitTestLogSink"/> class.
        /// </summary>
        /// <param name="outputWriter">The xUnit test output helper to delegate the Serilog log events to.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="outputWriter"/> is <c>null</c>.</exception>
        public XunitTestLogSink(ITestOutputHelper outputWriter)
        {
            Guard.NotNull(outputWriter, nameof(outputWriter), "Requires a xUnit test output helper to write Serilog log events to the xUnit test output");
            _outputWriter = outputWriter;
        }

        /// <summary>
        /// Emit the provided log event to the sink.
        /// </summary>
        /// <param name="logEvent">The log event to write.</param>
        public void Emit(LogEvent logEvent)
        {
            string message = logEvent.RenderMessage();
            _outputWriter.WriteLine(message);
        }
    }
}
