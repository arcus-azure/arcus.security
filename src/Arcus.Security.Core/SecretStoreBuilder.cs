using System;
using System.Collections.Generic;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Providers;
using GuardNet;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

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
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="services"/> is <c>null</c>.</exception>
        public SecretStoreBuilder(IServiceCollection services)
        {
            Guard.NotNull(services, nameof(services), "Requires a sequence of registered services to register the secret providers for the secret store");
            Services = services;
        }

        /// <summary>
        /// Gets the available registered services in the application.
        /// </summary>
        public IServiceCollection Services { get; }

        /// <summary>
        /// Gets the available secret sources currently registered to be included in the resulting root secret store.
        /// </summary>
        /// <remarks>
        ///     The series of secret stores is directly publicly available including the operations so future (consumer) extensions can easily low-level manipulate this series during build-up.
        ///     Though, for almost all use-cases, the <see cref="AddProvider(ISecretProvider,Func{string,string})"/> should be sufficient.
        /// </remarks>
        public IList<SecretStoreSource> SecretStoreSources { get; } = new List<SecretStoreSource>();

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="secretProvider">The provider which secrets are added to the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="secretProvider"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider(ISecretProvider secretProvider, Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires a secret provider to add to the secret store");

            if (mutateSecretName is null)
            {
                SecretStoreSources.Add(new SecretStoreSource(secretProvider));
            }
            else
            {
                SecretStoreSources.Add(CreateMutatedSecretSource(serviceProvider => secretProvider, mutateSecretName));
            }
            
            return this;
        }

        /// <summary>
        /// Adds an <see cref="ISecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="createSecretProvider">The function to create a provider which secrets are added to the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <returns>
        ///     The extended secret store with the given <paramref name="createSecretProvider"/> as lazy initialization.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="createSecretProvider"/> is <c>null</c>.</exception>
        public SecretStoreBuilder AddProvider(
            Func<IServiceProvider, ISecretProvider> createSecretProvider,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(createSecretProvider, nameof(createSecretProvider), "Requires a function to create a secret provider to add to the secret store");

            if (mutateSecretName is null)
            {
                SecretStoreSources.Add(new SecretStoreSource(createSecretProvider));
            }
            else
            {
                SecretStoreSources.Add(CreateMutatedSecretSource(createSecretProvider, mutateSecretName));
            }
            
            return this;
        }

        /// <summary>
        /// Builds the secret store and register the store into the <see cref="IServiceCollection"/>.
        /// </summary>
        internal void RegisterSecretStore()
        {
            foreach (SecretStoreSource source in SecretStoreSources)
            {
                if (source is null)
                {
                    continue;
                }

                Services.AddSingleton(serviceProvider =>
                {
                    source.EnsureSecretProviderCreated(serviceProvider);
                    return source;
                });
            }

            Services.TryAddSingleton<ICachedSecretProvider, CompositeSecretProvider>();
            Services.TryAddSingleton<ISecretProvider>(serviceProvider => serviceProvider.GetRequiredService<ICachedSecretProvider>());
        }

        private static SecretStoreSource CreateMutatedSecretSource(
            Func<IServiceProvider, ISecretProvider> createSecretProvider,
            Func<string, string> mutateSecretName)
        {
            return new SecretStoreSource(serviceProvider =>
            {
                ISecretProvider secretProvider = createSecretProvider(serviceProvider);
                if (secretProvider is ICachedSecretProvider cachedSecretProvider)
                {
                    var logger = serviceProvider.GetService<ILogger<MutatedSecretNameCachedSecretProvider>>();
                    return new MutatedSecretNameCachedSecretProvider(cachedSecretProvider, mutateSecretName, logger);
                }
                {
                    var logger = serviceProvider.GetService<ILogger<MutatedSecretNameSecretProvider>>();
                    return new MutatedSecretNameSecretProvider(secretProvider, mutateSecretName, logger);
                }
            });
        }
    }
}