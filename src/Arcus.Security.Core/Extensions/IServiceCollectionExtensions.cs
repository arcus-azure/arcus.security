using System;
using Arcus.Security.Core;
using Microsoft.Extensions.Hosting;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extensions on the <see cref="IServiceCollection"/> related to the secret store.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    public static class IServiceCollectionExtensions
    {
        /// <summary>
        /// Configure an <see cref="ISecretProvider"/> in the application with a given set of stores configured in the given <paramref name="configureSecretStores"/>.
        /// </summary>
        /// <param name="services">The services to append the secret store configuration to.</param>
        /// <param name="configureSecretStores">The customization of the different target secret store sources to include in the final <see cref="ISecretProvider"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="services"/> or <paramref name="configureSecretStores"/> is <c>null</c>.</exception>
        public static IServiceCollection AddSecretStore(this IServiceCollection services, Action<SecretStoreBuilder> configureSecretStores)
        {
            if (services is null)
            {
                throw new ArgumentNullException(nameof(services), "Requires a set of services to add the secret store");
            }
            
            if (configureSecretStores is null)
            {
                throw new ArgumentNullException(nameof(configureSecretStores), "Requires a function to register the secret providers in the secret store");
            }

            var builder = new SecretStoreBuilder(services);
            configureSecretStores(builder);
            builder.RegisterSecretStore();

            return services;
        }
    }
}
