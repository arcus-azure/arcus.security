using System;
using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Security.Tests.Integration.Serilog;
using Arcus.Testing;
using Bogus;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Core;
using Xunit;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Arcus.Security.Tests.Integration
{
    public class IntegrationTest : IDisposable
    {
        private bool _disposed;

        public static readonly Faker Bogus = new();

        protected IntegrationTest(ITestOutputHelper testOutput)
        {
            TestOutput = testOutput;
            Configuration = TestConfig.Create();
            Logger = new XunitTestLogger(testOutput);

            InMemoryLogSink = new InMemoryLogSink();

            var configuration = new LoggerConfiguration()
                .WriteTo.Sink(new XunitLogEventSink(testOutput))
                .WriteTo.Sink(InMemoryLogSink);

            SerilogLogger = configuration.CreateLogger();

            ProviderName = Bogus.PickRandom($"Custom {GetType().Name} provider name", null);
        }

        protected string ProviderName { get; }

        protected Func<string, string> MapSecretName { get; } =
            Bogus.PickRandom(null, Bogus.PickRandom<Func<string, string>>(
                name => name.ToLowerInvariant(),
                name => name.Replace("-", string.Empty),
                name => name.ToUpperInvariant()));

        protected ITestOutputHelper TestOutput { get; }
        protected TestConfig Configuration { get; }
        protected ILogger Logger { get; }
        protected Logger SerilogLogger { get; }
        protected InMemoryLogSink InMemoryLogSink { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="SecretStoreTestContext"/> class.
        /// </summary>
        protected SecretStoreTestContext GivenSecretStore(Action<SecretStoreBuilder> configureSecretStore)
        {
            return GivenSecretStore(configureHost: null, (_, store) => configureSecretStore(store));
        }

        /// <summary>
        /// Creates a new instance of the <see cref="SecretStoreTestContext"/> class.
        /// </summary>
        protected SecretStoreTestContext GivenSecretStore(
            Action<IHostBuilder> configureHost,
            Action<IConfiguration, SecretStoreBuilder> configureSecretStore)
        {
            return SecretStoreTestContext.GivenSecretStore(ProviderName, configureHost, configureSecretStore, Logger);
        }

        /// <summary>
        /// Randomly configures the given <paramref name="options"/>,
        /// used to verify secret provider registrations in different ways.
        /// </summary>
        protected void ConfigureOptions(SecretProviderRegistrationOptions options)
        {
            if (ProviderName != null)
            {
                options.ProviderName = ProviderName;
            }

            if (MapSecretName != null)
            {
                options.MapSecretName(MapSecretName);
            }
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
            SerilogLogger.Dispose();
        }
    }
}