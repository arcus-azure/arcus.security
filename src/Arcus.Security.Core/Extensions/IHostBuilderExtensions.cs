using System;
using Arcus.Security.Core;
using Arcus.Security.Core.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;

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
        public static IHostBuilder ConfigureSecretStore(this IHostBuilder hostBuilder, Action<IConfiguration, SecretStoreBuilder> configureSecretStores)
        {
            return ConfigureSecretStore(hostBuilder, (context, config, secretStores) => configureSecretStores(config, secretStores));
        }

        /// <summary>
        /// Configure an <see cref="ISecretProvider"/> in the application with a given set of stores configured in the given <paramref name="configureSecretStores"/>.
        /// </summary>
        /// <param name="hostBuilder">The builder to append the secret store configuration to.</param>
        /// <param name="configureSecretStores">The customization of the different target secret store sources to include in the final <see cref="ISecretProvider"/>.</param>
        public static IHostBuilder ConfigureSecretStore(this IHostBuilder hostBuilder, Action<HostBuilderContext, IConfiguration, SecretStoreBuilder> configureSecretStores)
        {
            return hostBuilder.ConfigureServices((context, services) =>
            {
                var builder = new SecretStoreBuilder(services);
                configureSecretStores(context, context.Configuration, builder);

                services.TryAddSingleton<ISecretProvider, CompositeSecretProvider>();
            });
        }
    }
}
