using Microsoft.Extensions.Logging;

namespace Arcus.Testing
{
    internal class CustomLoggerProvider(ILogger logger) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName)
        {
            return logger;
        }

        public void Dispose()
        {
        }
    }
}
