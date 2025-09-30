using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace Arcus.Security.Core
{
    /// <summary>
    /// Represents the exposed functionality of the secret store.
    /// </summary>
    [Obsolete("Will be removed in v3.0 in favor of a new " + nameof(Security.ISecretStore) + " interface in the 'Arcus.Security' namespace")]
    public interface ISecretStore
    {
        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        ISecretProvider GetProvider(string name);

        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <typeparam name="TSecretProvider">The concrete <see cref="ISecretProvider"/> type.</typeparam>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="InvalidCastException">Thrown when the registered <see cref="ISecretProvider"/> cannot be cast to the specific <typeparamref name="TSecretProvider"/>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when multiple <see cref="ISecretProvider"/> were registered with the same name.</exception>
        TSecretProvider GetProvider<TSecretProvider>(string name) where TSecretProvider : ISecretProvider;

        /// <summary>
        /// Gets the registered named <see cref="ICachedSecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ICachedSecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ICachedSecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="NotSupportedException">
        ///     Thrown when their was either none of the registered secret providers are registered as <see cref="ICachedSecretProvider"/> instances
        ///     or there was an <see cref="ISecretProvider"/> registered but not with caching.
        /// </exception>
        ICachedSecretProvider GetCachedProvider(string name);

        /// <summary>
        /// Gets the registered named <see cref="ICachedSecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ICachedSecretProvider"/> in the secret store.</param>
        /// <typeparam name="TCachedSecretProvider">The concrete <see cref="ICachedSecretProvider"/> type.</typeparam>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ICachedSecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="NotSupportedException">
        ///     Thrown when none of the registered secret providers are registered as <see cref="ICachedSecretProvider"/> instances
        ///     or there was an <see cref="ISecretProvider"/> registered but not with caching.
        /// </exception>
        /// <exception cref="InvalidCastException">Thrown when the registered <see cref="ICachedSecretProvider"/> cannot be cast to the specific <typeparamref name="TCachedSecretProvider"/>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when multiple <see cref="ICachedSecretProvider"/> were registered with the same name.</exception>
        TCachedSecretProvider GetCachedProvider<TCachedSecretProvider>(string name) where TCachedSecretProvider : ICachedSecretProvider;
    }
}

namespace Arcus.Security
{
    /// <summary>
    /// Represents the central point of contact to retrieve secrets from registered <see cref="ISecretProvider"/>s in the user application.
    /// </summary>
    public interface ISecretStore : ISecretProvider, ISecretStoreContext
    {
        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <typeparam name="TProvider">The concrete type of the secret provider implementation.</typeparam>
        /// <param name="providerName">
        ///     The name of the concrete secret provider implementation;
        ///     uses the type name of the type in case none is provided.
        /// </param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="providerName"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when no secret provider(s) was found with the provided <paramref name="providerName"/>.</exception>
        /// <exception cref="InvalidCastException">Thrown when the found secret provider can't be cast to the provided <typeparamref name="TProvider"/>.</exception>
        TProvider GetProvider<TProvider>(string providerName) where TProvider : ISecretProvider;

        /// <summary>
        /// Gets the secret by its name from the registered provider.
        /// </summary>
        /// <param name="secretName">The name to identity the stored secret.</param>
        /// <param name="configureOptions">The function to configure the optional options that manipulate the secret retrieval.</param>
        /// <returns>
        ///     <para>[Success] when the secret with the provided <paramref name="secretName"/> was found;</para>
        ///     <para>[Failure] when the secret could not be retrieved via the provider.</para>
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        Task<SecretResult> GetSecretAsync(string secretName, Action<SecretOptions> configureOptions);

        /// <summary>
        /// Gets the secret by its name from the registered provider.
        /// </summary>
        /// <param name="secretName">The name to identity the stored secret.</param>
        /// <param name="configureOptions">The function to configure the optional options that manipulate the secret retrieval.</param>
        /// <returns>
        ///     <para>[Success] when the secret with the provided <paramref name="secretName"/> was found;</para>
        ///     <para>[Failure] when the secret could not be retrieved via the provider.</para>
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        SecretResult GetSecret(string secretName, Action<SecretOptions> configureOptions);
    }

    /// <summary>
    /// Extensions on the <see cref="ISecretStore"/> to ease the migration process.
    /// </summary>
    public static class SecretStoreExtensions
    {
        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="store">The registered secret store to retrieve a single/subset secret provider from.</param>
        /// <param name="providerName">
        ///     The name of the concrete secret provider implementation;
        ///     uses the type name of the type in case none is provided.
        /// </param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="providerName"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when no secret provider(s) was found with the provided <paramref name="providerName"/>.</exception>
        public static ISecretProvider GetProvider(this ISecretStore store, string providerName)
        {
            return store.GetProvider<ISecretProvider>(providerName);
        }

        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="store"></param>
        /// <param name="name">The name that was used to register the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <typeparam name="TSecretProvider">The concrete <see cref="ISecretProvider"/> type.</typeparam>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="InvalidCastException">Thrown when the registered <see cref="ISecretProvider"/> cannot be cast to the specific <typeparamref name="TSecretProvider"/>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when multiple <see cref="ISecretProvider"/> were registered with the same name.</exception>
        [Obsolete("Will be removed in v3.0 in favor of a new interface 'Arcus.Security.ISecretProvider'")]
        public static TSecretProvider GetProvider<TSecretProvider>(this ISecretStore store, string name) where TSecretProvider : Core.ISecretProvider
        {
            var provider = store.GetProvider<ISecretProvider>(name);
            if (provider is not TSecretProvider concrete)
            {
                throw new InvalidCastException($"Cannot cast the registered '{name}' secret provider to a '{nameof(TSecretProvider)}' implementation");
            }

            return concrete;
        }

        /// <summary>
        /// Gets the registered named <see cref="ICachedSecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="store"></param>
        /// <param name="name">The name that was used to register the <see cref="ICachedSecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ICachedSecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="NotSupportedException">
        ///     Thrown when their was either none of the registered secret providers are registered as <see cref="ICachedSecretProvider"/> instances
        ///     or there was an <see cref="ISecretProvider"/> registered but not with caching.
        /// </exception>
        [Obsolete("Will be removed in v3.0 as secret caching will happen on the secret store itself")]
        public static ICachedSecretProvider GetCachedProvider(this ISecretStore store, string name)
        {
            var provider = store.GetProvider<ISecretProvider>(name);
            if (provider is not ICachedSecretProvider cached)
            {
                throw new InvalidCastException($"Cannot cast the registered '{name}' secret provider to a '{nameof(ICachedSecretProvider)}' implementation");
            }

            return cached;
        }

        /// <summary>
        /// Gets the registered named <see cref="ICachedSecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="store"></param>
        /// <param name="name">The name that was used to register the <see cref="ICachedSecretProvider"/> in the secret store.</param>
        /// <typeparam name="TCachedSecretProvider">The concrete <see cref="ICachedSecretProvider"/> type.</typeparam>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ICachedSecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="NotSupportedException">
        ///     Thrown when none of the registered secret providers are registered as <see cref="ICachedSecretProvider"/> instances
        ///     or there was an <see cref="ISecretProvider"/> registered but not with caching.
        /// </exception>
        /// <exception cref="InvalidCastException">Thrown when the registered <see cref="ICachedSecretProvider"/> cannot be cast to the specific <typeparamref name="TCachedSecretProvider"/>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when multiple <see cref="ICachedSecretProvider"/> were registered with the same name.</exception>
        [Obsolete("Will be removed in v3.0 as secret caching will happen on the secret store itself")]
        public static TCachedSecretProvider GetCachedProvider<TCachedSecretProvider>(this ISecretStore store, string name) where TCachedSecretProvider : ICachedSecretProvider
        {
            var provider = store.GetProvider<ISecretProvider>(name);
            if (provider is not TCachedSecretProvider cached)
            {
                throw new InvalidCastException($"Cannot cast the registered '{name}' secret provider to a '{nameof(TCachedSecretProvider)}' implementation");
            }

            return cached;
        }
    }

    /// <summary>
    /// Represents the options to manipulate the behavior of 
    /// </summary>
    public class SecretOptions
    {
        /// <summary>
        /// Gets or sets a value indicating whether the secret retrieval is allowed to use a cached secret;
        /// if <c>false</c>, the secret provider will always retrieve the fresh secret from the underlying store.
        /// (Default: <c>true</c>)
        /// </summary>
        public bool UseCache { get; set; } = true;
    }

    /// <summary>
    /// Extensions on the <see cref="ISecretStore"/> for easier usage.
    /// </summary>
    // ReSharper disable once InconsistentNaming
    internal static class ISecretStoreExtensions
    {
        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="store">The registered secret store in the application.</param>
        /// <param name="providerName">
        ///     The name of the concrete secret provider implementation;
        ///     uses the FQN (fully-qualified name) of the type in case none is provided.
        /// </param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="providerName"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when no secret provider(s) was found with the provided <paramref name="providerName"/>.</exception>
        public static ISecretProvider GetProvider(this ISecretStore store, string providerName)
        {
            return store.GetProvider<ISecretProvider>(providerName);
        }
    }

    /// <summary>
    /// Represents the current user-configurable situation of an <see cref="ISecretStore"/> implementation,
    /// a.k.a. all extra options the user set during the secret store registration.
    /// </summary>
    public interface ISecretStoreContext
    {
        /// <summary>
        /// Gets the service to interact with the possible configured cache on the secret store.
        /// </summary>
        SecretStoreCaching Cache { get; }
    }

    /// <summary>
    /// Represents the service to interact with the cache of the secret store.
    /// </summary>
    public class SecretStoreCaching
    {
        private IMemoryCache _cache = new NullMemoryCache();
        private MemoryCacheEntryOptions _cacheEntry = new();

        internal void SetDuration(TimeSpan duration)
        {
            _cache = new MemoryCache(new MemoryCacheOptions());
            _cacheEntry = new MemoryCacheEntryOptions().SetSlidingExpiration(duration);
        }

        internal bool TryGetCachedSecret(string secretName, SecretOptions secretOptions, ILogger logger, out SecretResult secret)
        {
            if (secretOptions.UseCache && _cache.TryGetValue(secretName, out secret))
            {
                logger.LogSecretFoundInCache(secretName, _cacheEntry.SlidingExpiration);
                return true;
            }

            secret = null;
            return false;
        }

        internal void UpdateSecretInCache(string secretName, SecretResult result, ILogger logger, SecretOptions options = null)
        {
            if (result.IsSuccess && (options is null || options.UseCache))
            {
                if (_cache is not NullMemoryCache)
                {
                    logger.LogSecretRefreshInCache(secretName, _cacheEntry.SlidingExpiration);
                }

                _cache.Set(secretName, result, _cacheEntry);
            }
        }

        /// <summary>
        /// Removes a secret from the cache on the secret provider,
        /// so that the next time this secret is retrieved, a fresh secret is provided from the registered <see cref="ISecretProvider"/>.
        /// </summary>
        public Task InvalidateSecretAsync(string secretName)
        {
            _cache.Remove(secretName);
            return Task.CompletedTask;
        }

        internal sealed class NullMemoryCache : IMemoryCache
        {
            public ICacheEntry CreateEntry(object key) => NullCacheEntry.Default;
            public void Remove(object key) { }
            public void Dispose() { }
            public bool TryGetValue(object key, out object value)
            {
                value = null;
                return false;
            }
        }

        internal sealed class NullCacheEntry : ICacheEntry
        {
            internal static NullCacheEntry Default { get; } = new();

            public object Key { get; }
            public object Value { get; set; }
            public DateTimeOffset? AbsoluteExpiration { get; set; }
            public TimeSpan? AbsoluteExpirationRelativeToNow { get; set; }
            public TimeSpan? SlidingExpiration { get; set; }
            public IList<IChangeToken> ExpirationTokens { get; }
            public IList<PostEvictionCallbackRegistration> PostEvictionCallbacks { get; }
            public CacheItemPriority Priority { get; set; }
            public long? Size { get; set; }
            public void Dispose() { }
        }
    }

}
