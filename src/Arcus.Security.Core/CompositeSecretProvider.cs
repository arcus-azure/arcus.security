using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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
        private readonly IEnumerable<CriticalExceptionFilter> _criticalExceptionFilters;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompositeSecretProvider"/> class.
        /// </summary>
        /// <param name="secretProviderSources">The sequence of all available registered secret provider registrations.</param>
        /// <param name="criticalExceptionFilters">The sequence of all available registered critical exception filters.</param>
        /// <param name="logger">The logger instance to write diagnostic messages during the retrieval of secrets via the registered <paramref name="secretProviderSources"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProviderSources"/> or <paramref name="criticalExceptionFilters"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretProviderSources"/> of the <paramref name="criticalExceptionFilters"/> contains any <c>null</c> values.</exception>
        public CompositeSecretProvider(
            IEnumerable<SecretStoreSource> secretProviderSources, 
            IEnumerable<CriticalExceptionFilter> criticalExceptionFilters,
            ILogger<CompositeSecretProvider> logger)
        {
            Guard.NotNull(secretProviderSources, nameof(secretProviderSources), "Requires a series of registered secret provider registrations to retrieve secrets");
            Guard.NotNull(criticalExceptionFilters, nameof(criticalExceptionFilters), "Requires a series of registered critical exception filters to determine if a thrown exception is critical");
            Guard.For<ArgumentException>(() => secretProviderSources.Any(source => source is null), "Requires all registered secret provider registrations to be not 'null'");
            Guard.For<ArgumentException>(() => criticalExceptionFilters.Any(filter => filter is null), "Requires all registered critical exception filters to be not 'null'");
            
            _secretProviders = secretProviderSources;
            _criticalExceptionFilters = criticalExceptionFilters;
            _logger = logger ?? NullLogger<CompositeSecretProvider>.Instance;
        }

        /// <summary>
        /// Gets the cache-configuration for this instance.
        /// </summary>
        /// <remarks>
        ///     Will always return <c>null</c> because several cached secret providers can be registered with different caching configuration,
        ///     and there also could be none configured for caching.
        /// </remarks>
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");

            string secretValue = await WithSecretStoreAsync(
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");

            Secret secret = await WithSecretStoreAsync(
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");

            string secretValue = await WithCachedSecretStoreAsync(secretName, async source =>
            {
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");

            Secret secret = await WithCachedSecretStoreAsync(secretName, async source =>
            {
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the secret");

            ICachedSecretProvider provider = await WithCachedSecretStoreAsync(secretName, async source =>
            {
                Secret secret = await source.CachedSecretProvider.GetSecretAsync(secretName);
                return secret is null ? null : source.CachedSecretProvider;
            });

            await provider.InvalidateSecretAsync(secretName);
        }

        private async Task<T> WithCachedSecretStoreAsync<T>(
            string secretName,
            Func<SecretStoreSource, Task<T>> callRegisteredStore) where T : class
        {
            return await  WithSecretStoreAsync(secretName, async source =>
            {
                if (source.CachedSecretProvider is null)
                {
                    return null;
                }

                return await callRegisteredStore(source);
            });
        }

        private async Task<T> WithSecretStoreAsync<T>(string secretName, Func<SecretStoreSource, Task<T>> callRegisteredStore) where T : class
        {
            if (!_secretProviders.Any())
            {
                var noRegisteredException = new KeyNotFoundException("No secret providers are configured to retrieve the secret from");
                throw new SecretNotFoundException(secretName, noRegisteredException);
            }

            var criticalExceptions = new Collection<Exception>();
            foreach (SecretStoreSource source in _secretProviders)
            {
                try
                {
                    Task<T> resultAsync = callRegisteredStore(source);
                    if (resultAsync is null)
                    {
                        continue;
                    }

                    T result = await resultAsync;
                    if (result is null)
                    {
                        continue;
                    }

                    return result;
                }
                catch (Exception exception) when (IsCriticalException(exception))
                {
                    _logger.LogError(exception, "Exception of type '{ExceptionType}' is considered an critical exception", exception.GetType().Name);
                    criticalExceptions.Add(exception);
                }
                catch (Exception exception)
                {
                    _logger.LogTrace(exception, "Secret provider '{Type}' doesn't contain secret with name {SecretName}", source.SecretProvider.GetType(), secretName);
                }
            }

            if (criticalExceptions.Count <= 0)
            {
                var noneFoundException = new KeyNotFoundException("None of the configured secret providers was able to retrieve the requested secret");
                throw new SecretNotFoundException(secretName, noneFoundException);
            }

            if (criticalExceptions.Count == 1)
            {
                throw criticalExceptions[0];
            }

            throw new AggregateException(
                $"None of the configured secret providers was able to retrieve the secret while {criticalExceptions.Count} critical exceptions were thrown", 
                criticalExceptions);
        }

        private bool IsCriticalException(Exception exceptionCandidate)
        {
            return _criticalExceptionFilters.Any(filter =>
            {
                try
                {
                    return filter.IsCritical(exceptionCandidate);
                }
                catch (Exception exception)
                {
                    _logger.LogWarning(exception, "Failed to determining critical exception for exception type '{ExceptionType}'", filter.ExceptionType.Name);
                    return false;
                }
            });
        }
    }
}
