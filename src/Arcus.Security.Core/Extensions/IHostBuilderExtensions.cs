using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.Configuration;
using System;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Extensions on the <see cref="IHostBuilder"/> to configure the <see cref="ISecretProvider"/> as in a more consumer-friendly manner.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class IHostBuilderExtensions
    {
        /// <summary>
        /// Configure an <see cref="ISecretProvider"/> in the application with a given set of stores configured in the given <paramref name="configureSecretStores"/>.
        /// </summary>
        /// <param name="hostBuilder">The builder to append the secret store configuration to.</param>
        /// <param name="configureSecretStores">The customization of the different target secret store sources to include in the final <see cref="ISecretProvider"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="hostBuilder"/> or <paramref name="configureSecretStores"/> is <c>null</c>.</exception>
        public static IHostBuilder ConfigureSecretStore(this IHostBuilder hostBuilder, Action<IConfiguration, SecretStoreBuilder> configureSecretStores)
        {
            Guard.NotNull(hostBuilder, nameof(hostBuilder), "Requires a host builder to add the secret store");
            Guard.NotNull(configureSecretStores, nameof(configureSecretStores), "Requires a function to register the secret providers in the secret store");

            return ConfigureSecretStore(hostBuilder, (context, config, secretStores) => configureSecretStores(config, secretStores));
        }

        /// <summary>
        /// Configure an <see cref="ISecretProvider"/> in the application with a given set of stores configured in the given <paramref name="configureSecretStores"/>.
        /// </summary>
        /// <param name="hostBuilder">The builder to append the secret store configuration to.</param>
        /// <param name="configureSecretStores">The customization of the different target secret store sources to include in the final <see cref="ISecretProvider"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="hostBuilder"/> or <paramref name="configureSecretStores"/> is <c>null</c>.</exception>
        public static IHostBuilder ConfigureSecretStore(this IHostBuilder hostBuilder, Action<HostBuilderContext, IConfiguration, SecretStoreBuilder> configureSecretStores)
        {
            Guard.NotNull(hostBuilder, nameof(hostBuilder), "Requires a host builder to add the secret store");
            Guard.NotNull(configureSecretStores, nameof(configureSecretStores), "Requires a function to register the secret providers in the secret store");
            
            return hostBuilder.ConfigureServices((context, services) =>
            {
                var builder = new SecretStoreBuilder(services);
                configureSecretStores(context, context.Configuration, builder);
                builder.RegisterSecretStore();
            });
        }
    }
}
