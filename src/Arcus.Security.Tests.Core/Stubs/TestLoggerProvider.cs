using Microsoft.Extensions.Logging;

namespace Arcus.Security.Tests.Core.Stubs
{
    /// <summary>
    /// Represents an <see cref="ILoggerProvider"/> that delegates the logger creation to an fixed instance.
    /// </summary>
    public class TestLoggerProvider : ILoggerProvider
    {
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="TestLoggerProvider"/> class.
        /// </summary>
        public TestLoggerProvider(ILogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Creates a new <see cref="T:Microsoft.Extensions.Logging.ILogger" /> instance.
        /// </summary>
        /// <param name="categoryName">The category name for messages produced by the logger.</param>
        public ILogger CreateLogger(string categoryName)
        {
            return _logger;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
        }
    }
}
