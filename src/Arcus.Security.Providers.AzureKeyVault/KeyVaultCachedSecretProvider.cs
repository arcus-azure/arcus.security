using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using GuardNet;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Caching.Memory;

namespace Arcus.Security.Providers.AzureKeyVault
{
    /// <summary>
    /// Represents an <see cref="KeyVaultSecretProvider"/> instance with additional specific caching operations.
    /// </summary>
    public class KeyVaultCachedSecretProvider : CachedSecretProvider
    {
        private readonly KeyVaultSecretProvider _secretProvider;

        /// <summary>
        /// Gets the regular expression that can check if the Azure Key Vault URI matches the <see cref="KeyVaultSecretProvider.SecretNamePattern"/>. (See https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning).
        /// </summary>
        protected readonly Regex SecretNameRegex = new Regex(KeyVaultSecretProvider.SecretNamePattern, RegexOptions.Compiled);

        /// <summary>
        /// Creating a new CachedSecretProvider with all required information
        /// </summary>
        /// <param name="secretProvider">The internal <see cref="ISecretProvider"/> used to retrieve the actual Secret Value, when not cached</param>
        /// <param name="cacheConfiguration">The <see cref="ICacheConfiguration"/> which defines how the cache works</param>
        /// <param name="memoryCache">A <see cref="IMemoryCache"/> implementation that can cache data in memory.</param>
        /// <exception cref="ArgumentNullException">The secretProvider and memoryCache parameters must not be null</exception>
        public KeyVaultCachedSecretProvider(KeyVaultSecretProvider secretProvider, ICacheConfiguration cacheConfiguration, IMemoryCache memoryCache) 
            : base(secretProvider, cacheConfiguration, memoryCache)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires an Azure Key Vault secret provider to provide additional caching operations");
            _secretProvider = secretProvider;
        }

        /// <inheritdoc />
        /// <summary>
        /// Creating a new CachedSecretProvider with a standard generated MemoryCache
        /// </summary>
        public KeyVaultCachedSecretProvider(KeyVaultSecretProvider secretProvider, ICacheConfiguration cacheConfiguration) 
            : base(secretProvider, cacheConfiguration)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires an Azure Key Vault secret provider to provide additional caching operations");
            _secretProvider = secretProvider;
        }

        /// <inheritdoc />
        /// <summary>
        /// Creating a new CachedSecretProvider with a standard generated MemoryCache and default TimeSpan of 5 minutes
        /// </summary>
        public KeyVaultCachedSecretProvider(KeyVaultSecretProvider secretProvider) : base(secretProvider)
        {
            Guard.NotNull(secretProvider, nameof(secretProvider), "Requires an Azure Key Vault secret provider to provide additional caching operations");
            _secretProvider = secretProvider;
        }

        /// <summary>
        /// Stores a secret value with a given secret name
        /// </summary>
        /// <param name="secretName">The name of the secret</param>
        /// <param name="secretValue">The value of the secret</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the latest information for the given secret</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="ArgumentException">The <paramref name="secretValue"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretValue"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        /// <exception cref="KeyVaultErrorException">The call for a secret resulted in an invalid response</exception>
        public virtual async Task<Secret> StoreSecretAsync(string secretName, string secretValue)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to request a secret in Azure Key Vault");
            Guard.NotNullOrWhitespace(secretValue, nameof(secretValue), "Requires a non-blank secret value to store a secret in Azure Key Vault");
            Guard.For<FormatException>(() => !SecretNameRegex.IsMatch(secretName), "Requires a secret name in the correct format to request a secret in Azure Key Vault, see https://docs.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#objects-identifiers-and-versioning");

            Secret secret = await _secretProvider.StoreSecretAsync(secretName, secretValue);
            MemoryCache.Set(secretName, secret, CacheEntry);

            return secret;
        }
    }
}
