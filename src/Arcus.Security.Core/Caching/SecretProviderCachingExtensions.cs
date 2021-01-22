using System;
using Arcus.Security.Core.Caching.Configuration;
using GuardNet;
using Microsoft.Extensions.Caching.Memory;

namespace Arcus.Security.Core.Caching
{
    /// <summary>
    /// Provide extensions for more fluent/easy composition of adding caching to retrieve Azure Key Vault secrets with the <see cref="CachedSecretProvider"/>.
    /// </summary>
    public static class SecretProviderCachingExtensions
    {
        /// <summary>
        ///     Creates an <see cref="ICachedSecretProvider" /> instance that will use InMemoryCache to get SecretValues from the
        ///     passed secretProvider
        /// </summary>
        /// <param name="secretProvider">
        ///     An instantiated <see cref="ISecretProvider" /> that will only be called if the value is
        ///     not cached
        /// </param>
        /// <param name="cachingDuration">The duration to cache secrets in memory</param>
        /// <param name="memoryCache">
        ///     Optional <see cref="IMemoryCache" /> that can be used for caching.  Defaults to a
        ///     <see cref="MemoryCache" /> instance
        /// </param>
        /// <returns>A secret provider that caches values</returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> or <paramref name="memoryCache"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="cachingDuration"/> is outside the bounds of a valid cache duration.</exception>
        public static ICachedSecretProvider WithCaching(this ISecretProvider secretProvider, TimeSpan cachingDuration, IMemoryCache memoryCache)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires a secret provider to create a cached version");
            Guard.For<ArgumentOutOfRangeException>(() => cachingDuration <= default(TimeSpan), "Requires a caching duration of a positive time interval");
            Guard.NotNull(memoryCache, nameof(memoryCache), "Requires a memory cache to store the cached results");
            
            return new CachedSecretProvider(secretProvider, new CacheConfiguration(cachingDuration), memoryCache);
        }

        /// <summary>
        ///     Creates an <see cref="ICachedSecretProvider" /> instance that will use InMemoryCache to get SecretValues from the
        ///     passed secretProvider
        /// </summary>
        /// <param name="secretProvider">
        ///     An instantiated <see cref="ISecretProvider" /> that will only be called if the value is
        ///     not cached
        /// </param>
        /// <param name="cachingDuration">The duration to cache secrets in memory</param>
        /// <returns>A secret provider that caches values</returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="cachingDuration"/> is outside the bounds of a valid cache duration.</exception>
        public static ICachedSecretProvider WithCaching(this ISecretProvider secretProvider, TimeSpan cachingDuration)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires a secret provider to create a cached version");
            Guard.For<ArgumentOutOfRangeException>(() => cachingDuration <= default(TimeSpan), "Requires a caching duration of a positive time interval");

            return new CachedSecretProvider(secretProvider, new CacheConfiguration(cachingDuration));
        }

        /// <summary>
        ///     Creates an <see cref="ICachedSecretProvider" /> instance that will use InMemoryCache to get SecretValues from the
        ///     passed secretProvider
        /// </summary>
        /// <param name="secretProvider">
        ///     An instantiated <see cref="ISecretProvider" /> that will only be called if the value is
        ///     not cached
        /// </param>
        /// <returns>A secret provider that caches values</returns>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public static ICachedSecretProvider WithCaching(this ISecretProvider secretProvider)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires a secret provider to create a cached version");

            return new CachedSecretProvider(secretProvider);
        }
    }
}