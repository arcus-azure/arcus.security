using System;
using System.Threading.Tasks;
using Arcus.Testing;
using Bogus;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Arcus.Security.Tests.Integration.Fixture
{
    /// <summary>
    /// Represents a test-friendly way to interact with the secret store in a simulated application.
    /// </summary>
    public class SecretStoreTestContext : IAsyncDisposable
    {
        private readonly string _providerName;
        private readonly IHostBuilder _builder;
        private readonly ILogger _logger;
        private IHost _host;
        private bool _isRunning;

        private static readonly Faker Bogus = new();

        private SecretStoreTestContext(string providerName, IHostBuilder builder, ILogger logger)
        {
            _providerName = providerName;
            _builder = builder;
            _logger = logger;
        }

        internal bool SupportSynchronous { get; set; } = true;

        /// <summary>
        /// Creates a new instance of the <see cref="SecretStoreTestContext"/> class.
        /// </summary>
        internal static SecretStoreTestContext GivenSecretStore(string providerName, Action<IConfiguration, SecretStoreBuilder> configureSecretStore, ILogger logger)
        {
            var builder =
                Host.CreateDefaultBuilder()
                    .ConfigureSecretStore((config, store) =>
                    {
                        store.AddProvider(new AlwaysFailSecretProvider(), configureOptions: null);
                        store.AddProvider(new AlwaysNotFoundSecretProvider(), configureOptions: null);

                        configureSecretStore(config, store);
                    })
                    .ConfigureLogging(logging =>
                    {
                        logging.SetMinimumLevel(LogLevel.Trace)
                               .AddProvider(new DelegateLoggerProvider(logger));
                    });

            return new SecretStoreTestContext(providerName, builder, logger);
        }

        private sealed class AlwaysFailSecretProvider : ISecretProvider
        {
            public SecretResult GetSecret(string secretName)
            {
                var exception = new InvalidOperationException("[Test] sabotage secret retrieval with exception");
                if (Bogus.Random.Bool())
                {
                    return SecretResult.Interrupted(secretName, "[Test] sabotage secret retrieval with exception", exception);
                }

                throw exception;
            }
        }

        private sealed class AlwaysNotFoundSecretProvider : ISecretProvider
        {
            public SecretResult GetSecret(string secretName) => SecretResult.NotFound(secretName, "[Test] sabotage secret retrieval with not-found");
        }

        private sealed class DelegateLoggerProvider(ILogger logger) : ILoggerProvider
        {
            public ILogger CreateLogger(string categoryName) => logger;
            public void Dispose() { }
        }

        /// <summary>
        /// Sets up a secret store registration in the simulated application.
        /// </summary>
        public void WhenSecretStore(Action<SecretStoreBuilder> configureSecretStore)
        {
            WhenSecretStore((_, store) => configureSecretStore(store));
        }

        /// <summary>
        /// Sets up a secret store registration in the simulated application.
        /// </summary>
        public void WhenSecretStore(Action<IConfiguration, SecretStoreBuilder> configureSecretStore)
        {
            _builder.ConfigureSecretStore(configureSecretStore);
        }

        public async Task<SecretResult> ShouldFindSecretAsync(string secretName, string secretValue)
        {
            SecretResult result = await ShouldFindSecretAsync(secretName);
            Assert.True(secretValue == result.Value, $"secret store should find secret '{secretName}' with value '{secretValue}', but got '{result.Value}'");

            return result;
        }

        /// <summary>
        /// Verifies if a secret with a given <paramref name="secretName"/> is located in the registered secret store.
        /// </summary>
        public async Task<SecretResult> ShouldFindSecretAsync(string secretName)
        {
            var store = GetStore();

            if (SupportSynchronous)
            {
                using (_logger.BeginScope("synchronous secrets"))
                {
#pragma warning disable S6966 // Should call synchronous method here to verify if both synchronous and asynchronous methods return the same result.
                    SecretResult syncResult = store.GetSecret(secretName);
                    Assert.True(syncResult.IsSuccess, $"synchronously retrieving secret '{secretName}' from secret store should result in a successful result, but wasn't: {syncResult}");
#pragma warning restore S6966
                }
            }

            SecretResult asyncResult;
            using (_logger.BeginScope("asynchronous secrets"))
            {
                asyncResult = await store.GetSecretAsync(secretName);
                Assert.True(asyncResult.IsSuccess, $"asynchronously retrieving secret '{secretName}' from secret store should result in a successful result, but wasn't: {asyncResult}");
            }

            _logger.LogDebug("-----------------------------------------------------------------------------------------------------------------------------------");
            _logger.LogDebug("[Test] verifying secret store infrastructure");
            if (SupportSynchronous && Bogus.Random.Bool())
            {
#pragma warning disable S6966 // Should call synchronous method here to verify if both synchronous and asynchronous methods return the same result.
                SecretResult syncNotFoundResult = store.GetSecret("always-not-found-sync-secret" + Guid.NewGuid());
#pragma warning restore S6966
                Assert.False(syncNotFoundResult.IsSuccess, $"synchronously retrieving a secret that is not available in the secret store should return a failed result, but wasn't: {syncNotFoundResult}");
            }
            else
            {
                SecretResult asyncNotFoundResult = await store.GetSecretAsync("always-not-found-async-secret" + Guid.NewGuid());
                Assert.False(asyncNotFoundResult.IsSuccess, $"asynchronously retrieving a secret that is not available in the secret store should return a failed result, but wasn't: {asyncNotFoundResult}");
            }

            return asyncResult;
        }

        public TProvider ShouldFindProvider<TProvider>(string providerName = null) where TProvider : ISecretProvider
        {
            var store = GetStore();
            var provider = store.GetProvider<TProvider>(providerName ?? _providerName ?? typeof(TProvider).Name);
            Assert.NotNull(provider);

            return provider;
        }

        private ISecretStore GetStore()
        {
            return GetHost().Services.GetRequiredService<ISecretStore>();
        }

        private IHost GetHost()
        {
            if (!_isRunning)
            {
                _host = _builder.Build();
                _isRunning = true;
            }

            return _host;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or
        /// resetting unmanaged resources asynchronously.</summary>
        /// <returns>A task that represents the asynchronous dispose operation.</returns>
        public async ValueTask DisposeAsync()
        {
            await using var disposables = new DisposableCollection(_logger);

            if (_host != null)
            {
                disposables.Add(_host);
            }
        }
    }
}
