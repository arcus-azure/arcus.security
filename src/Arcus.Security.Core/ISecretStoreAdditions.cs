using System;
using Arcus.Security.Core.Caching.Configuration;
using Microsoft.Extensions.Caching.Memory;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Represents the additional configurations for the registered secret store.
    /// </summary>
    public interface ISecretStoreAdditions
    {
        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        ISecretStoreAdditions WithCaching();

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cachingDuration">The duration for which an entry should be cached.</param>
        ISecretStoreAdditions WithCaching(TimeSpan cachingDuration);

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cachingDuration">The duration for which an entry should be cached.</param>
        /// <param name="memoryCache">A <see cref="IMemoryCache"/> implementation that can cache data in memory.</param>
        ISecretStoreAdditions WithCaching(TimeSpan cachingDuration, IMemoryCache memoryCache);

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cacheConfiguration">The <see cref="ICacheConfiguration"/> which defines how the cache works.</param>
        ISecretStoreAdditions WithCaching(ICacheConfiguration cacheConfiguration);

        /// <summary>
        /// Include caching in the resulting secret source.
        /// </summary>
        /// <param name="cacheConfiguration">The <see cref="ICacheConfiguration"/> which defines how the cache works.</param>
        /// <param name="memoryCache">A <see cref="IMemoryCache"/> implementation that can cache data in memory.</param>
        ISecretStoreAdditions WithCaching(ICacheConfiguration cacheConfiguration, IMemoryCache memoryCache);
    }
}