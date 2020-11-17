using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Serilog.Core;
using Serilog.Events;

namespace Arcus.Security.Tests.Core.Stubs
{
    /// <summary>
    /// Represents a test <see cref="ILogEventSink"/> implementation to store the Serilog log events in-memory.
    /// </summary>
    public class InMemoryLogSink : ILogEventSink
    {
        private readonly ICollection<LogEvent> _events = new Collection<LogEvent>();

        /// <summary>
        /// Gets the currently logged events; stored in-memory.
        /// </summary>
        public IEnumerable<LogEvent> LogEvents => _events.AsEnumerable();

        /// <summary>
        /// Emit the provided log event to the sink.
        /// </summary>
        /// <param name="logEvent">The log event to write.</param>
        public void Emit(LogEvent logEvent)
        {
            _events.Add(logEvent);
        }
    }
}
