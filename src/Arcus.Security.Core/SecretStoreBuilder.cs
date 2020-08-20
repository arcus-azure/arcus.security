﻿using System;
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
        /// Gets the available secret sources currently registered to be included in the resulting root secret store.
        /// </summary>
        /// <remarks>
        ///     The series of secret stores is directly publicly available including the operations so future (consumer) extensions can easily manipulate this series during build-up.
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
            Guard.NotNull(secretProvider, nameof(secretProvider));

            SecretStoreSources.Add(new SecretStoreSource(secretProvider, mutateSecretName));
            return this;
        }
        
        /// <summary>
        /// Builds the secret store and register the store into the <see cref="IServiceCollection"/>.
        /// </summary>
        internal void RegisterSecretStore()
        {
            foreach (SecretStoreSource source in SecretStoreSources)
            {
                if (source.MutateSecretName is null)
                {
                    Services.AddSingleton(source);
                }
                else
                {
                    Services.AddSingleton(serviceProvider => WrapInMutatedSecretProvider(serviceProvider, source));
                }
            }

            Services.TryAddSingleton<ICachedSecretProvider, CompositeSecretProvider>();
            Services.TryAddSingleton<ISecretProvider>(serviceProvider => serviceProvider.GetRequiredService<ICachedSecretProvider>());
        }

        private static SecretStoreSource WrapInMutatedSecretProvider(IServiceProvider serviceProvider, SecretStoreSource source)
        {
            if (source.CachedSecretProvider is null)
            {
                var logger = serviceProvider.GetService<ILogger<MutatedSecretNameSecretProvider>>();
                var secretProvider = new MutatedSecretNameSecretProvider(source.SecretProvider, source.MutateSecretName, logger);
                return new SecretStoreSource(secretProvider);
            }
            else
            {
                var logger = serviceProvider.GetService<ILogger<MutatedSecretNameCachedSecretProvider>>();
                var secretProvider = new MutatedSecretNameCachedSecretProvider(source.CachedSecretProvider, source.MutateSecretName, logger);
                return new SecretStoreSource(secretProvider);
            }
        }
    }
}