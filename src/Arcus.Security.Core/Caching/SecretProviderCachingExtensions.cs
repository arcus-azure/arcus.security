using System;
using System.Collections.Generic;
using System.Text;
using Arcus.Security.Core.Interfaces;
using Microsoft.Extensions.Caching.Memory;

namespace Arcus.Security.Core.Caching
{
    public static class SecretProviderCachingExtensions
    {
        /// <summary>
        /// Creates an <see cref="ICachedSecretProvider"/> instance that will use InMemoryCache to get SecretValues from the passed secretProvider
        /// </summary>
        /// <param name="secretProvider">An instantiated <see cref="ISecretProvider"/> that will only be called if the value is not cached</param>
        /// <param name="cachingDuration">The duration to cache secrets in memory</param>
        /// <param name="memoryCache">Optional <see cref="IMemoryCache"/> that can be used for caching.  Defaults to a <see cref="MemoryCache"/> instance</param>
        /// <returns>A secret provider that caches values</returns>
        public static ICachedSecretProvider WithCaching(this ISecretProvider secretProvider, TimeSpan cachingDuration, IMemoryCache memoryCache)
        {
            return new CachedSecretProvider(secretProvider, cachingDuration, memoryCache);
        }

        /// <summary>
        /// Creates an <see cref="ICachedSecretProvider"/> instance that will use InMemoryCache to get SecretValues from the passed secretProvider
        /// </summary>
        /// <param name="secretProvider">An instantiated <see cref="ISecretProvider"/> that will only be called if the value is not cached</param>
        /// <param name="cachingDuration">The duration to cache secrets in memory</param>
        /// <returns>A secret provider that caches values</returns>
        public static ICachedSecretProvider WithCaching(this ISecretProvider secretProvider, TimeSpan cachingDuration)
        {
            return new CachedSecretProvider(secretProvider, cachingDuration);
        }

        /// <summary>
        /// Creates an <see cref="ICachedSecretProvider"/> instance that will use InMemoryCache to get SecretValues from the passed secretProvider
        /// </summary>
        /// <param name="secretProvider">An instantiated <see cref="ISecretProvider"/> that will only be called if the value is not cached</param>
        /// <returns>A secret provider that caches values</returns>
        public static ICachedSecretProvider WithCaching(this ISecretProvider secretProvider)
        {
            return new CachedSecretProvider(secretProvider);
        }
    }
}
