using Arcus.Security.Core;
using Arcus.Security.Core.Storage;
using GuardNet;
using Microsoft.Extensions.DependencyInjection;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Represents the entry point for extending the available secret store in the application.
    /// </summary>
    public class SecretStoreBuilder
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SecretStoreBuilder"/> class.
        /// </summary>
        /// <param name="services">The available registered services in the application.</param>
        public SecretStoreBuilder(IServiceCollection services)
        {
            Guard.NotNull(services, nameof(services));
            Services = services;
        }

        /// <summary>
        /// Gets the available registered services in the application.
        /// </summary>
        public IServiceCollection Services { get; }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="secretProvider">The provider which secrets are added to the secret store.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="secretProvider"/>.
        /// </returns>
        public SecretStoreBuilder AddProvider(ISecretProvider secretProvider)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider));
            Services.AddSingleton(new SecretStoreSource(secretProvider));

            return this;
        }
    }
}