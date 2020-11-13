using System;
using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Testing.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Configuration;
using Serilog.Extensions.Logging;
using Xunit.Abstractions;

namespace Arcus.Security.Tests.Integration
{
    public class IntegrationTest : IDisposable
    {
        private readonly ILoggerFactory _loggerFactory;

        protected TestConfig Configuration { get; }
        protected Microsoft.Extensions.Logging.ILogger Logger { get; }

        public IntegrationTest(ITestOutputHelper testOutput)
        {
            // The appsettings.local.json allows users to override (gitignored) settings locally for testing purposes
            Configuration = TestConfig.Create();
            
            var configuration = new LoggerConfiguration()
                .WriteTo.Sink(new XunitTestLogSink(testOutput))
                .WriteTo.AzureApplicationInsights(Configuration.GetValue<string>("Arcus:ApplicationInsights:InstrumentationKey"));

            _loggerFactory = new SerilogLoggerFactory(configuration.CreateLogger(), dispose: true);
            Logger = _loggerFactory.CreateLogger(nameof(IntegrationTest));
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            _loggerFactory.Dispose();
        }
    }
}