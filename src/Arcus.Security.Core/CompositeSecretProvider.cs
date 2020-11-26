using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using GuardNet;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Arcus.Security.Core
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation representing a series of <see cref="ISecretProvider"/> implementations.
    /// </summary>
    internal class CompositeSecretProvider : ICachedSecretProvider, ISecretStore
    {
        private readonly IEnumerable<SecretStoreSource> _secretProviders;
        private readonly IEnumerable<CriticalExceptionFilter> _criticalExceptionFilters;
        private readonly SecretStoreAuditingOptions _auditingOptions;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompositeSecretProvider"/> class.
        /// </summary>
        /// <param name="secretProviderSources">The sequence of all available registered secret provider registrations.</param>
        /// <param name="criticalExceptionFilters">The sequence of all available registered critical exception filters.</param>
        /// <param name="auditingOptions">The customized options to configure the auditing of the secret store.</param>
        /// <param name="logger">The logger instance to write diagnostic messages during the retrieval of secrets via the registered <paramref name="secretProviderSources"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProviderSources"/> or <paramref name="criticalExceptionFilters"/> or <paramref name="auditingOptions"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretProviderSources"/> of the <paramref name="criticalExceptionFilters"/> contains any <c>null</c> values.</exception>
        public CompositeSecretProvider(
            IEnumerable<SecretStoreSource> secretProviderSources, 
            IEnumerable<CriticalExceptionFilter> criticalExceptionFilters,
            IOptions<SecretStoreAuditingOptions> auditingOptions,
            ILogger<CompositeSecretProvider> logger)
        {
            Guard.NotNull(secretProviderSources, nameof(secretProviderSources), "Requires a series of registered secret provider registrations to retrieve secrets");
            Guard.NotNull(criticalExceptionFilters, nameof(criticalExceptionFilters), "Requires a series of registered critical exception filters to determine if a thrown exception is critical");
            Guard.NotNull(auditingOptions, nameof(auditingOptions), "Requires a set of options to configure the auditing of the secret store");
            Guard.For<ArgumentException>(() => secretProviderSources.Any(source => source is null), "Requires all registered secret provider registrations to be not 'null'");
            Guard.For<ArgumentException>(() => criticalExceptionFilters.Any(filter => filter is null), "Requires all registered critical exception filters to be not 'null'");
            Guard.NotNull<SecretStoreAuditingOptions, ArgumentException>(auditingOptions.Value, "Requires a value for the set of options to configure the auditing of the secret store");

            _secretProviders = secretProviderSources;
            _criticalExceptionFilters = criticalExceptionFilters;
            _auditingOptions = auditingOptions.Value;
            _logger = logger ?? NullLogger<CompositeSecretProvider>.Instance;
        }

        /// <summary>
        /// Gets the cache-configuration for this instance.
        /// </summary>
        /// <remarks>
        ///     Will always throw an <see cref="NotSupportedException"/> because several cached secret providers can be registered with different caching configuration,
        ///     and there also could be none configured for caching.
        /// </remarks>
        /// <exception cref="NotSupportedException">
        ///     Thrown every time because the <see cref="CompositeSecretProvider"/> cannot determine the caching configuration from the different registered <see cref="ICachedSecretProvider"/>s.
        /// </exception>
        public ICacheConfiguration Configuration =>
            throw new NotSupportedException(
                "Getting the cache configuration directly from the secret store is not supported, "
                + $"please use another way to access the configuration or implement your own '{nameof(ICachedSecretProvider)}' to use this within your secret provider");

        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <typeparam name="TSecretProvider">The concrete <see cref="ISecretProvider"/> type.</typeparam>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">
        ///     Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>,
        ///     or there were multiple <see cref="ISecretProvider"/> instances registered with the same name.
        /// </exception>
        /// <exception cref="InvalidCastException">Thrown when the registered <see cref="ISecretProvider"/> cannot be cast to the specific <typeparamref name="TSecretProvider"/>.</exception>
        public TSecretProvider GetProvider<TSecretProvider>(string name) where TSecretProvider : ISecretProvider
        {
            Guard.NotNullOrWhitespace(name, nameof(name), "Requires a non-blank name to retrieve the registered named secret provider");
            
            ISecretProvider provider = GetProvider(name);
            if (provider is TSecretProvider concreteProvider)
            {
                return concreteProvider;
            }

            throw new InvalidCastException($"Cannot cast registered {nameof(ISecretProvider)} with name '{name}' to type '{typeof(TSecretProvider).Name}'");
        }

        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">
        ///     Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>,
        ///     or there were multiple <see cref="ISecretProvider"/> instances registered with the same name.
        /// </exception>
        public ISecretProvider GetProvider(string name)
        {
            Guard.NotNullOrWhitespace(name, nameof(name), "Requires a non-blank name to retrieve the registered named secret provider");

            SecretStoreSource source = GetSecretSource(name);
            return source.SecretProvider;
        }

        /// <summary>
        /// Gets the registered named <see cref="ICachedSecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ICachedSecretProvider"/> in the secret store.</param>
        /// <typeparam name="TCachedSecretProvider">The concrete <see cref="ICachedSecretProvider"/> type.</typeparam>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">
        ///     Thrown when there was no <see cref="ICachedSecretProvider"/> found in the secret store with the given <paramref name="name"/>,
        ///     or there were multiple <see cref="ICachedSecretProvider"/> instances registered with the same name.
        /// </exception>
        /// <exception cref="NotSupportedException">Thrown when there was an <see cref="ICachedSecretProvider"/> registered but not with caching.</exception>
        /// <exception cref="InvalidCastException">Thrown when the registered <see cref="ICachedSecretProvider"/> cannot be cast to the specific <typeparamref name="TCachedSecretProvider"/>.</exception>
        public TCachedSecretProvider GetCachedProvider<TCachedSecretProvider>(string name) where TCachedSecretProvider : ICachedSecretProvider
        {
            Guard.NotNullOrWhitespace(name, nameof(name), "Requires a non-blank name to retrieve the registered named secret provider");

            ICachedSecretProvider provider = GetCachedProvider(name);
            if (provider is TCachedSecretProvider concreteProvider)
            {
                return concreteProvider;
            }

            throw new InvalidCastException($"Cannot cast registered {nameof(ICachedSecretProvider)} with name '{name}' to type '{typeof(TCachedSecretProvider).Name}'");
        }

        /// <summary>
        /// Gets the registered named <see cref="ICachedSecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ICachedSecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">
        ///     Thrown when there was no <see cref="ICachedSecretProvider"/> found in the secret store with the given <paramref name="name"/>,
        ///     or there were multiple <see cref="ICachedSecretProvider"/> instances registered with the same name.
        /// </exception>
        /// <exception cref="NotSupportedException">Thrown when there was an <see cref="ISecretProvider"/> registered but not with caching.</exception>
        public ICachedSecretProvider GetCachedProvider(string name)
        {
            Guard.NotNullOrWhitespace(name, nameof(name), "Requires a non-blank name to retrieve the registered named secret provider");

            SecretStoreSource source = GetSecretSource(name);
            if (source.CachedSecretProvider is null)
            {
                throw new NotSupportedException(
                    $"Found a registered {nameof(ISecretProvider)} with the name '{name}' in the secret store, but was not configured for caching. "
                    + $"Please use the {nameof(GetProvider)} instead or configure the registered provider with caching");
            }

            return source.CachedSecretProvider;
        }

        private SecretStoreSource GetSecretSource(string name)
        {
            IEnumerable<SecretStoreSource> matchingProviders =
                _secretProviders.Where(provider => provider.Options.Name == name);

            int count = matchingProviders.Count();
            if (count is 0)
            {
                throw new KeyNotFoundException(
                    $"Could not retrieve the named {nameof(ISecretProvider)} because no provider was registered with the name '{name}'");
            }

            if (count > 1)
            {
                throw new KeyNotFoundException(
                    $"Could not retrieve the named {nameof(ISecretProvider)} because more than one provider was registered with the name '{name}'");
            }

            SecretStoreSource firstProvider = matchingProviders.First();
            return firstProvider;
        }

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

            string secretValue = await WithCachedSecretStoreAsync(
                secretName, source => source.CachedSecretProvider.GetRawSecretAsync(secretName, ignoreCache));

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

            Secret secret = await WithCachedSecretStoreAsync(
                secretName, source => source.CachedSecretProvider.GetSecretAsync(secretName, ignoreCache));

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

            await WithCachedSecretStoreAsync(secretName, async source =>
            {
                Task invalidateSecretAsync = source.CachedSecretProvider.InvalidateSecretAsync(secretName);
                if (invalidateSecretAsync is null)
                {
                    return null;
                }

                await invalidateSecretAsync;
                return "ignored result";
            });
        }

        private async Task<T> WithCachedSecretStoreAsync<T>(
            string secretName,
            Func<SecretStoreSource, Task<T>> callRegisteredProvider) where T : class
        {
            return await  WithSecretStoreAsync(secretName, async source =>
            {
                if (source.CachedSecretProvider is null)
                {
                    return null;
                }

                Task<T> registeredProvider = callRegisteredProvider(source);
                if (registeredProvider is null)
                {
                    return null;
                }

                return await registeredProvider;
            });
        }

        private async Task<T> WithSecretStoreAsync<T>(string secretName, Func<SecretStoreSource, Task<T>> callRegisteredProvider) where T : class
        {
            EnsureAnySecretProvidersConfigured(secretName);

            var criticalExceptions = new Collection<Exception>();
            foreach (SecretStoreSource source in _secretProviders)
            {
                try
                {
                    T result = await GetSecretFromProviderAsync(secretName, source, callRegisteredProvider);
                    if (result is null)
                    {
                        continue;
                    }

                    LogPossibleCriticalExceptions(secretName, criticalExceptions);
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

            throw DetermineSecretStoreException(secretName, criticalExceptions);
        }

        private void EnsureAnySecretProvidersConfigured(string secretName)
        {
            if (!_secretProviders.Any())
            {
                _logger.LogError("No secret providers are configured in the secret store to retrieve the secret from, please configure at least one secret provider with the '{Extension}' extension in the startup of your application",
                                 nameof(IHostBuilderExtensions.ConfigureSecretStore));

                var noRegisteredException = new KeyNotFoundException("No secret providers are configured to retrieve the secret from");
                throw new SecretNotFoundException(secretName, noRegisteredException);
            }
        }

        private async Task<T> GetSecretFromProviderAsync<T>(
            string secretName, 
            SecretStoreSource source, 
            Func<SecretStoreSource, Task<T>> callRegisteredProvider) where T : class
        {
            if (_auditingOptions.EmitSecurityEvents)
            {
                _logger.LogSecurityEvent("Get Secret", new Dictionary<string, object>
                {
                    ["SecretName"] = secretName,
                    ["SecretProvider"] = source.SecretProvider.GetType().Name
                }); 
            }

            Task<T> resultAsync = callRegisteredProvider(source);
            if (resultAsync is null)
            {
                return null;
            }

            T result = await resultAsync;
            return result;
        }

        private void LogPossibleCriticalExceptions(string secretName, IEnumerable<Exception> criticalExceptions)
        {
            if (criticalExceptions.Any())
            {
                _logger.LogWarning("Found secret with name '{SecretName}' but at the cost of {ExceptionCount} critical exceptions", secretName, criticalExceptions.Count());

                foreach (Exception criticalException in criticalExceptions)
                {
                    _logger.LogWarning(criticalException, "Critical exception thrown during retrieval of secret with name '{SecretName}'", secretName);
                }
            }

            _logger.LogInformation("Found secret with name '{SecretName}'", secretName);
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

        private Exception DetermineSecretStoreException(string secretName, IEnumerable<Exception> criticalExceptions)
        {
            if (!criticalExceptions.Any())
            {
                _logger.LogError("None of the configured {Count} configured secret providers was able to retrieve the requested secret with name '{SecretName}'",
                                 _secretProviders.Count(), secretName);

                var noneFoundException = new KeyNotFoundException($"None of the {_secretProviders.Count()} configured secret providers was able to retrieve the requested secret with name '{secretName}'");
                return new SecretNotFoundException(secretName, noneFoundException);
            }

            if (criticalExceptions.Count() == 1)
            {
                return criticalExceptions.First();
            }

            return new AggregateException(
                $"None of the configured secret providers was able to retrieve the secret with name '{secretName}' while {criticalExceptions.Count()} critical exceptions were thrown",
                criticalExceptions);
        }
    }
}
