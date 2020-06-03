using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using GuardNet;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Represents the entry point for extending the available secret store in the application.
    /// </summary>
    public class SecretStoreBuilder : ISecretStoreAdditions
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
        /// <returns>
        ///     The extended secret store with the given <paramref name="secretProvider"/>.
        /// </returns>
        public ISecretStoreAdditions AddProvider(ISecretProvider secretProvider)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider));
            SecretStoreSources.Add(new SecretStoreSource(secretProvider));

            return this;
        }
        
        /// <summary>
        /// Adds an <see cref="ICachedSecretProvider"/> implementation to the secret store of the application.
        /// </summary>
        /// <param name="secretProvider">The provider which the secrets are added to the secret store.</param>
        public void AddCachedProvider(ICachedSecretProvider secretProvider)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider));
            SecretStoreSources.Add(new SecretStoreSource(secretProvider));
        }

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        ISecretStoreAdditions ISecretStoreAdditions.WithCaching()
        {
            return AddCachingToPreviousSecretStore(new CacheConfiguration(), new MemoryCache(new MemoryCacheOptions()));
        }

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cachingDuration">The duration for which an entry should be cached.</param>
        ISecretStoreAdditions ISecretStoreAdditions.WithCaching(TimeSpan cachingDuration)
        {
            Guard.For<ArgumentException>(() => cachingDuration <= default(TimeSpan), "Caching duration should be a positive interval");

            return AddCachingToPreviousSecretStore(new CacheConfiguration(cachingDuration), new MemoryCache(new MemoryCacheOptions()));
        }

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cachingDuration">The duration for which an entry should be cached.</param>
        /// <param name="memoryCache">A <see cref="IMemoryCache"/> implementation that can cache data in memory.</param>
        ISecretStoreAdditions ISecretStoreAdditions.WithCaching(TimeSpan cachingDuration, IMemoryCache memoryCache)
        {
            Guard.For<ArgumentException>(() => cachingDuration <= default(TimeSpan), "Caching duration should be a positive interval");

            return AddCachingToPreviousSecretStore(new CacheConfiguration(cachingDuration), memoryCache);
        }

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cacheConfiguration">The <see cref="ICacheConfiguration"/> which defines how the cache works.</param>
        ISecretStoreAdditions ISecretStoreAdditions.WithCaching(ICacheConfiguration cacheConfiguration)
        {
            return AddCachingToPreviousSecretStore(cacheConfiguration, new MemoryCache(new MemoryCacheOptions()));
        }

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cacheConfiguration">The <see cref="ICacheConfiguration"/> which defines how the cache works.</param>
        /// <param name="memoryCache">A <see cref="IMemoryCache"/> implementation that can cache data in memory.</param>
        ISecretStoreAdditions ISecretStoreAdditions.WithCaching(ICacheConfiguration cacheConfiguration, IMemoryCache memoryCache)
        {
            return AddCachingToPreviousSecretStore(cacheConfiguration, memoryCache);
        }

        private ISecretStoreAdditions AddCachingToPreviousSecretStore(
            ICacheConfiguration cacheConfiguration,
            IMemoryCache memoryCache)
        {
            Guard.NotNull(cacheConfiguration, nameof(cacheConfiguration));
            Guard.NotNull(memoryCache, nameof(memoryCache));

            if (SecretStoreSources.Any())
            {
                SecretStoreSource source = SecretStoreSources.Last();
                int index = SecretStoreSources.IndexOf(source);
                if (index != -1)
                {
                    SecretStoreSources[index] = new SecretStoreSource(
                        new CachedSecretProvider(source.SecretProvider, cacheConfiguration, memoryCache));
                }
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
                Services.AddSingleton(source);
            }

            Services.TryAddSingleton<ICachedSecretProvider, CompositeSecretProvider>();
            Services.TryAddSingleton<ISecretProvider>(serviceProvider => serviceProvider.GetRequiredService<ICachedSecretProvider>());
        }
    }
}