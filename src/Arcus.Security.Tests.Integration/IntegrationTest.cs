using System;
using Arcus.Testing;
using Serilog;
using Serilog.Core;
using Xunit;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Arcus.Security.Tests.Integration
{
    public class IntegrationTest : IDisposable
    {
        private bool _disposed;

        protected IntegrationTest(ITestOutputHelper testOutput)
        {
            Configuration = TestConfig.Create();
            Logger = new XunitTestLogger(testOutput);

            InMemoryLogSink = new InMemoryLogSink();

            var configuration = new LoggerConfiguration()
                .WriteTo.Sink(InMemoryLogSink)
                .WriteTo.XunitTestLogging(testOutput);

            SerilogLogger = configuration.CreateLogger();
        }

        protected TestConfig Configuration { get; }
        protected ILogger Logger { get; }
        protected Logger SerilogLogger { get; }
        protected InMemoryLogSink InMemoryLogSink { get; }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            Dispose(true);
            GC.SuppressFinalize(this);

            _disposed = true;
        }
        
        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary> 
        protected virtual void Dispose(bool disposing)
        {
            SerilogLogger.Dispose();
        }
    }
}