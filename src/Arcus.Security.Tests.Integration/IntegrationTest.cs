using System;
using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Testing.Logging.Extensions;
using Arcus.Testing.Logging;
using Microsoft.Extensions.Configuration;
using Serilog;
using Serilog.Configuration;
using Serilog.Core;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration
{
    public class IntegrationTest : IDisposable
    {
        private bool _disposed;
        
        protected TestConfig Configuration { get; }
        protected Logger Logger { get; }
        protected InMemoryLogSink InMemoryLogSink { get; }

        public IntegrationTest(ITestOutputHelper testOutput)
        {
            // The appsettings.local.json allows users to override (gitignored) settings locally for testing purposes
            Configuration = TestConfig.Create();
            InMemoryLogSink = new InMemoryLogSink();
            
            var configuration = new LoggerConfiguration()
                .WriteTo.XunitTestLogging(testOutput)
                .WriteTo.Sink(InMemoryLogSink)
                .WriteTo.AzureApplicationInsights(Configuration.GetValue<string>("Arcus:ApplicationInsights:InstrumentationKey"));

            Logger = configuration.CreateLogger();
        }

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
            Logger.Dispose();
        }
    }
}