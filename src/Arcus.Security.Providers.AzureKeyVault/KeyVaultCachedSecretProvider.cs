using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using Microsoft.Extensions.Caching.Memory;

namespace Arcus.Security.Providers.AzureKeyVault
{
    /// <summary>
    /// Represents an <see cref="KeyVaultSecretProvider"/> instance with additional specific caching operations.
    /// </summary>
    [Obsolete("Will be removed in v3.0 as secret caching will be done on the secret store itself")]
    public class KeyVaultCachedSecretProvider : CachedSecretProvider
    {
        private readonly KeyVaultSecretProvider _secretProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultCachedSecretProvider"/> class.
        /// </summary>
        /// <param name="secretProvider">The inner Azure Key Vault secret provider to provide secrets.</param>
        /// <param name="cacheConfiguration">The custom caching configuration that defines how the cache works.</param>
        /// <param name="memoryCache">The custom memory cache implementation that stores the cached secrets in memory.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="secretProvider"/>, <paramref name="cacheConfiguration"/>, or <paramref name="memoryCache"/> is <c>null</c>.
        /// </exception>
        public KeyVaultCachedSecretProvider(KeyVaultSecretProvider secretProvider, ICacheConfiguration cacheConfiguration, IMemoryCache memoryCache)
            : base(secretProvider, cacheConfiguration, memoryCache)
        {
            _secretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultCachedSecretProvider"/> class
        /// with standard generated <see cref="MemoryCache"/> and custom <paramref name="cacheConfiguration"/>.
        /// </summary>
        /// <param name="secretProvider">The inner Azure Key Vault secret provider to retrieve secrets.</param>
        /// <param name="cacheConfiguration">The custom caching configuration that defines how the cache works.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> or the <paramref name="cacheConfiguration"/> is <c>null</c>.</exception>
        public KeyVaultCachedSecretProvider(KeyVaultSecretProvider secretProvider, ICacheConfiguration cacheConfiguration)
            : base(secretProvider, cacheConfiguration)
        {
            _secretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultCachedSecretProvider"/> class
        /// with a standard generated <see cref="MemoryCache "/> and default cache duration <see cref="TimeSpan "/> of 5 minutes.
        /// </summary>
        /// <param name="secretProvider">The inner Azure Key Vault secret provider to provide secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProvider"/> is <c>null</c>.</exception>
        public KeyVaultCachedSecretProvider(KeyVaultSecretProvider secretProvider) : base(secretProvider)
        {
            _secretProvider = secretProvider ?? throw new ArgumentNullException(nameof(secretProvider));
        }

        /// <summary>
        /// Stores a secret value with a given secret name.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="secretValue">The value of the secret.</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the latest information for the given secret.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> or the <paramref name="secretValue"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given <paramref name="secretName"/>.</exception>
        public virtual async Task<Secret> StoreSecretAsync(string secretName, string secretValue)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to store a secret in Azure Key Vault", nameof(secretName));
            }

            if (string.IsNullOrWhiteSpace(secretValue))
            {
                throw new ArgumentException("Requires a non-blank secret value to store a secret in Azure Key Vault", nameof(secretName));
            }

            Secret secret = await _secretProvider.StoreSecretAsync(secretName, secretValue);
            MemoryCache.Set(secretName, new[] { secret }, CacheEntry);

            return secret;
        }
    }
}
