﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using GuardNet;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Core
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation representing a series of <see cref="ISecretProvider"/> implementations.
    /// </summary>
    internal class CompositeSecretProvider : ICachedSecretProvider
    {
        private readonly IEnumerable<SecretStoreSource> _secretProviders;
        private readonly ILogger<CompositeSecretProvider> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompositeSecretProvider"/> class.
        /// </summary>
        public CompositeSecretProvider(IEnumerable<SecretStoreSource> secretProviderSources, ILogger<CompositeSecretProvider> logger)
        {
            Guard.NotNull(secretProviderSources, nameof(secretProviderSources));
            Guard.For<ArgumentException>(() => secretProviderSources.Any(source => source?.SecretProvider is null), "None of the registered secret providers should be 'null'");
            
            _secretProviders = secretProviderSources;
            _logger = logger ?? NullLogger<CompositeSecretProvider>.Instance;
        }

        /// <summary>
        /// Gets the cache-configuration for this instance.
        /// </summary>
        public ICacheConfiguration Configuration => null;

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrEmpty(secretName, nameof(secretName));

            string secretValue = await WithChildSecretStoreAsync(
                secretName, source => source.SecretProvider.GetRawSecretAsync(secretName));
            
            return secretValue;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNullOrEmpty(secretName, nameof(secretName));

            Secret secret = await WithChildSecretStoreAsync(
                secretName, source => source.SecretProvider.GetSecretAsync(secretName));

            return secret;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="Task{TResult}"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> GetRawSecretAsync(string secretName, bool ignoreCache)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName));

            string secretValue = await WithChildSecretStoreAsync(secretName, async source =>
            {
                if (source.CachedSecretProvider is null)
                {
                    return null;
                }

                string found = await source.CachedSecretProvider.GetRawSecretAsync(secretName, ignoreCache);
                return found;
            });

            return secretValue;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <param name="ignoreCache">Indicates if the cache should be used or skipped</param>
        /// <returns>Returns a <see cref="Task{TResult}"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The name must not be empty</exception>
        /// <exception cref="ArgumentNullException">The name must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName, bool ignoreCache)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName));

            Secret secret = await WithChildSecretStoreAsync(secretName, async source =>
            {
                if (source.CachedSecretProvider is null)
                {
                    return null;
                }

                Secret found = await source.CachedSecretProvider.GetSecretAsync(secretName, ignoreCache);
                return found;
            });

            return secret;
        }

        /// <summary>
        /// Removes the secret with the given <paramref name="secretName"/> from the cache;
        /// so the next time <see cref="CachedSecretProvider.GetSecretAsync(string)"/> is called, a new version of the secret will be added back to the cache.
        /// </summary>
        /// <param name="secretName">The name of the secret that should be removed from the cache.</param>
        public async Task InvalidateSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName));

            ICachedSecretProvider provider = await WithChildSecretStoreAsync(secretName, async source =>
            {
                if (source.CachedSecretProvider is null)
                {
                    return null;
                }

                Secret secret = await source.CachedSecretProvider.GetSecretAsync(secretName);
                return secret is null ? null : source.CachedSecretProvider;
            });

            await provider.InvalidateSecretAsync(secretName);
        }

        private async Task<T> WithChildSecretStoreAsync<T>(string secretName, Func<SecretStoreSource, Task<T>> callRegisteredStore) where T : class
        {
            if (!_secretProviders.Any())
            {
                var noRegisteredException = new KeyNotFoundException("No secret providers are configured to retrieve the secret from");
                throw new SecretNotFoundException(secretName, noRegisteredException);
            }

            foreach (SecretStoreSource source in _secretProviders)
            {
                try
                {
                    T result = await callRegisteredStore(source);
                    if (!(result is null))
                    {
                        return result;
                    }
                    
                }
                catch (Exception exception)
                {
                    _logger.LogTrace(exception, "Secret provider {Type} doesn't contain secret with name {SecretName}", source.SecretProvider.GetType().Name, secretName);
                }
            }

            var noneFoundException = new KeyNotFoundException("None of the configured secret providers contains the requested secret");
            throw new SecretNotFoundException(secretName, noneFoundException);
        }
    }
}