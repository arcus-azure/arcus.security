using System;
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
    public class SecretStoreBuilder
    {
        private bool _includeCaching;
        private ICacheConfiguration _cacheConfiguration;
        private IMemoryCache _memoryCache;

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

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cachingDuration">The duration for which an entry should be cached.</param>
        public SecretStoreBuilder WithCaching(TimeSpan cachingDuration)
        {
            Guard.For<ArgumentException>(() => cachingDuration <= default(TimeSpan), "Caching duration should be a positive interval");

            return WithCaching(new CacheConfiguration(cachingDuration));
        }

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cachingDuration">The duration for which an entry should be cached.</param>
        /// <param name="memoryCache">A <see cref="IMemoryCache"/> implementation that can cache data in memory.</param>
        public SecretStoreBuilder WithCaching(TimeSpan cachingDuration, IMemoryCache memoryCache)
        {
            Guard.For<ArgumentException>(() => cachingDuration <= default(TimeSpan), "Caching duration should be a positive interval");

            return WithCaching(new CacheConfiguration(cachingDuration), memoryCache);
        }

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        public SecretStoreBuilder WithCaching()
        {
            return WithCaching(cacheConfiguration: null, memoryCache: null);
        }

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cacheConfiguration">The <see cref="ICacheConfiguration"/> which defines how the cache works.</param>
        public SecretStoreBuilder WithCaching(ICacheConfiguration cacheConfiguration)
        {
            return WithCaching(cacheConfiguration, memoryCache: null);
        }

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cacheConfiguration">The <see cref="ICacheConfiguration"/> which defines how the cache works.</param>
        /// <param name="memoryCache">A <see cref="IMemoryCache"/> implementation that can cache data in memory.</param>
        public SecretStoreBuilder WithCaching(ICacheConfiguration cacheConfiguration, IMemoryCache memoryCache)
        {
            _includeCaching = true;
            _cacheConfiguration = cacheConfiguration;
            _memoryCache = memoryCache;

            return this;
        }

        /// <summary>
        /// Builds the secret store and register the store into the <see cref="IServiceCollection"/>.
        /// </summary>
        internal void RegisterSecretStore()
        {
            if (_includeCaching)
            {
                Services.TryAddSingleton<ICachedSecretProvider>(serviceProvider =>
                {
                    var compositeSecretProvider = ActivatorUtilities.CreateInstance<CompositeSecretProvider>(serviceProvider);
                    return CreateCachedSecretProvider(compositeSecretProvider);
                });
                Services.TryAddSingleton<ISecretProvider>(serviceProvider => serviceProvider.GetRequiredService<ICachedSecretProvider>());
            }
            else
            {
                Services.TryAddSingleton<ISecretProvider, CompositeSecretProvider>();
            }
        }

        private ICachedSecretProvider CreateCachedSecretProvider(ISecretProvider secretProvider)
        {
            if (_memoryCache is null)
            {
                if (_cacheConfiguration is null)
                {
                    return new CachedSecretProvider(secretProvider);
                }

                return new CachedSecretProvider(secretProvider, _cacheConfiguration);
            }

            return new CachedSecretProvider(secretProvider, _cacheConfiguration, _memoryCache);
        }
    }
}