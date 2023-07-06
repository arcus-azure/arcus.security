using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Providers.Dapr;
using Arcus.Security.Tests.Integration.Dapr.Resources;
using Arcus.Security.Tests.Integration.Fixture;
using Arcus.Testing.Logging;
using Dapr.Client;
using GuardNet;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Newtonsoft.Json.Linq;
using Polly;
using Serilog;
using Xunit;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace Arcus.Security.Tests.Integration.Dapr.Hosting
{
    /// <summary>
    /// Represents the available teardown options for the <see cref="DaprSidecarFixture"/>.
    /// </summary>
    [Flags]
    public enum TearDownOptions
    {
        /// <summary>
        /// De-activate any additional teardown functionality.
        /// </summary>
        None = 0,

        /// <summary>
        /// Logs the standard output console of the Dapr Sidecar service to the test output during teardown.
        /// </summary>
        LogDaprOutput = 1
    }

    /// <summary>
    /// Represents a test fixture that runs the Dapr Sidecar as a temporary service.
    /// </summary>
    public sealed class DaprSidecarFixture : IAsyncDisposable
    {
        private const string DaprLocalSecretStore = "localsecretstore";

        private readonly Process _process;
        private readonly DaprSidecarOptions _options;
        private readonly ILogger _logger;
        private readonly ICollection<IDisposable> _disposables = new Collection<IDisposable>();

        private DaprSidecarFixture(Process process, int port, DaprSidecarOptions options, ILogger logger)
        {
            Guard.NotNull(process, nameof(process));
            Guard.NotLessThan(port, 0, nameof(port));

            _process = process;
            _options = options;
            _logger = logger ?? NullLogger.Instance;

            Endpoint = new Uri($"http://127.0.0.1:{port}/");
        }

        /// <summary>
        /// Gets the GRPC endpoint where the Dapr Sidecar is hosted.
        /// </summary>
        public Uri Endpoint { get; }

        /// <summary>
        /// Gets or sets the options to manipulate the teardown process of the test fixture.
        /// </summary>
        public TearDownOptions TearDownOptions { get; set; } = TearDownOptions.LogDaprOutput;

        /// <summary>
        /// Starts a new <see cref="DaprSidecarFixture"/> as a temporary service with the provided user-defined options.
        /// </summary>
        /// <param name="configuration">The integration test configuration to retrieve the required hosting-related values.</param>
        /// <param name="logger">The logger instance to write diagnostic trace messages during the startup and teardown of the test fixture.</param>
        /// <param name="configureOptions">The user-defined options to configure the Dapr Sidecar.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="configuration"/> is <c>null</c>.</exception>
        public static async Task<DaprSidecarFixture> StartSideCarAsync(TestConfig configuration, ILogger logger, Action<DaprSidecarOptions> configureOptions)
        {
            Guard.NotNull(configuration, nameof(configuration));
            logger ??= NullLogger.Instance;
            int port = 60002;

            var options = new DaprSidecarOptions();
            configureOptions?.Invoke(options);
            options.WriteSecretStoreConfigToDisk();

            Process process = CreateProcess(configuration, port, options);
            var fixture = new DaprSidecarFixture(process, port, options, logger);
            
            await fixture.StartProcessAsync();
            return fixture;
        }

        private static Process CreateProcess(TestConfig configuration, int port, DaprSidecarOptions options)
        {
            string daprExeFileName = configuration.GetDaprInstallationFileName();

            string vaultArgs = String.Join(" ",
                "run",
                $"--resources-path {nameof(Dapr)}/Resources/{options.StoreType}",
                $"--app-port 6002 --dapr-http-port 3601 --dapr-grpc-port {port}");

            var startInfo = new ProcessStartInfo(daprExeFileName, vaultArgs)
            {
                WorkingDirectory = Directory.GetCurrentDirectory(),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true
            };

            return new Process { StartInfo = startInfo };
        }

        private async Task StartProcessAsync()
        {
            _logger.LogTrace("Starting Dapr Sidecar: {FileName} {Arguments}", _process.StartInfo.FileName, _process.StartInfo.Arguments);
            
            bool isStarted = _process.Start();
            if (!isStarted)
            {
                throw new InvalidOperationException(
                    "Cannot correctly start Dapr Sidecar process due to an unexpected failure, please make sure to check if the provided arguments are correct");
            }

            PolicyResult healthResult = 
                await Policy.TimeoutAsync(TimeSpan.FromSeconds(20))
                            .WrapAsync(Policy.Handle<Exception>()
                                             .WaitAndRetryForeverAsync(_ => TimeSpan.FromMilliseconds(100)))
                            .ExecuteAndCaptureAsync(async () =>
                            {
                                _logger.LogTrace("Checking Dapr Sidecar health...");
                 
                                using var client = new DaprClientBuilder().UseGrpcEndpoint(Endpoint.OriginalString).Build();
                                await client.GetMetadataAsync();
                            });

            if (healthResult.Outcome is OutcomeType.Failure)
            {
                _logger.LogError("Failed to correctly start Dapr Sidecar");
                await StopProcessAsync();

                throw new TimeoutException(
                    "Could not correctly start Dapr Sidecar because the sidecar did not respond with a healthy response in the expected time frame", healthResult.FinalException);
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
            _logger.LogTrace("Dapr Sidecar started at {Endpoint}!", Endpoint);
        }

        /// <summary>
        /// Gets a registered <see cref="ISecretProvider"/> based on the current Dapr sidecar configuration.
        /// </summary>
        /// <param name="configureProvider">The function to configure additional values on the <see cref="DaprSecretProvider"/>.</param>
        /// <param name="logger">The optional logger to include while registering the secret provider.</param>
        public ISecretProvider GetSecretProvider(
            Action<DaprSecretProviderOptions> configureProvider = null,
            Serilog.ILogger logger = null)
        { 
            return CreateSecretProvider(stores => stores.AddDaprSecretStore(_options.StoreName, options =>
            {
                options.GrpcEndpoint = Endpoint.ToString();
                configureProvider?.Invoke(options);
            }), logger);
        }

        /// <summary>
        /// Gets a registered <see cref="ISecretProvider"/> based on the current Dapr sidecar configuration.
        /// </summary>
        /// <param name="implementationFactory">The function to create a custom <see cref="DaprSecretProvider"/>.</param>
        /// <param name="configureProvider">The function to configure additional values on the <see cref="DaprSecretProvider"/>.</param>
        /// <param name="logger">The optional logger to include while registering the secret provider.</param>
        public ISecretProvider GetSecretProvider<TCustom>(
            Func<IServiceProvider, DaprSecretProviderOptions, DaprSidecarOptions, TCustom> implementationFactory,
            Action<DaprSecretProviderOptions> configureProvider = null,
            Serilog.ILogger logger = null)
            where TCustom : DaprSecretProvider
        { 
            return CreateSecretProvider(stores =>
            {
                stores.AddDaprSecretStore(
                    (provider, opt) => implementationFactory(provider, opt, _options), 
                    options =>
                    {
                        options.GrpcEndpoint = Endpoint.ToString();
                        configureProvider?.Invoke(options);
                    });
            }, logger);
        }

        private ISecretProvider CreateSecretProvider(
            Action<SecretStoreBuilder> configureSecretStore,
            Serilog.ILogger logger)
        {
            var builder = new HostBuilder();
            if (logger != null)
            {
                builder.UseSerilog(logger);
            }

            builder.ConfigureLogging(logging =>
            {
                logging.SetMinimumLevel(LogLevel.Trace);
                logging.AddProvider(new CustomLoggerProvider(_logger));
            });

            builder.ConfigureSecretStore((config, stores) =>
            {
                configureSecretStore(stores);
            });

            IHost host = builder.Build();
            _disposables.Add(host);

            IServiceProvider serviceProvider = host.Services;
            return serviceProvider.GetRequiredService<ISecretProvider>();
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources asynchronously.
        /// </summary>
        /// <returns>A task that represents the asynchronous dispose operation.</returns>
        public async ValueTask DisposeAsync()
        {
            await StopProcessAsync();
            Assert.All(_disposables, d => d.Dispose());
        }

        private async Task StopProcessAsync()
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }

            if (TearDownOptions.HasFlag(TearDownOptions.LogDaprOutput))
            {
                _logger.LogTrace("Dapr Sidecar read standard output...");
                string output = await _process.StandardOutput.ReadToEndAsync();
                _logger.LogDebug("Dapr Sidecar console: {Output}", output);
            }

            _logger.LogTrace("Stop Dapr Sidecar at {Endpoint}", Endpoint);
            _process.Dispose();
        }
    }
}
