using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Core
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation representing a series of <see cref="ISecretProvider"/> implementations.
    /// </summary>
    internal class CompositeSecretProvider : ICachedSecretProvider, IVersionedSecretProvider, ISecretStore, ISyncSecretProvider
    {
        private readonly SecretStoreSource[] _secretProviders;
        private readonly CriticalExceptionFilter[] _criticalExceptionFilters;
        private readonly SecretStoreAuditingOptions _auditingOptions;
        private readonly IDictionary<string, Lazy<ISecretProvider>> _groupedSecretStores;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompositeSecretProvider"/> class.
        /// </summary>
        /// <param name="secretProviderSources">The sequence of all available registered secret provider registrations.</param>
        /// <param name="criticalExceptionFilters">The sequence of all available registered critical exception filters.</param>
        /// <param name="auditingOptions">The customized options to configure the auditing of the secret store.</param>
        /// <param name="logger">The logger instance to write diagnostic messages during the retrieval of secrets via the registered <paramref name="secretProviderSources"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProviderSources"/>, or <paramref name="criticalExceptionFilters"/> or <paramref name="auditingOptions"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretProviderSources"/> or <paramref name="criticalExceptionFilters"/> contains any <c>null</c> values.</exception>
        public CompositeSecretProvider(
            IEnumerable<SecretStoreSource> secretProviderSources, 
            IEnumerable<CriticalExceptionFilter> criticalExceptionFilters,
            SecretStoreAuditingOptions auditingOptions,
            ILogger<CompositeSecretProvider> logger)
        {
            if (secretProviderSources is null)
            {
                throw new ArgumentNullException(nameof(secretProviderSources));
            }

            if (criticalExceptionFilters is null)
            {
                throw new InvalidOperationException(nameof(criticalExceptionFilters));
            }

            SecretStoreSource[] sourcesArr = secretProviderSources.ToArray();
            CriticalExceptionFilter[] filtersArr = criticalExceptionFilters.ToArray();
            if (sourcesArr.Any(s => s is null))
            {
                throw new ArgumentException("One or more secret sources are 'null'", nameof(secretProviderSources));
            }

            if (filtersArr.Any(f => f is null))
            {
                throw new ArgumentException("One or more exception filters are 'null'", nameof(criticalExceptionFilters));
            }

            _secretProviders = sourcesArr;
            _criticalExceptionFilters = filtersArr;
            _auditingOptions = auditingOptions ?? new SecretStoreAuditingOptions();
            _logger = logger ?? NullLogger<CompositeSecretProvider>.Instance;

            _groupedSecretStores = CreateGroupedSecretProviders(sourcesArr, filtersArr, auditingOptions, logger);
            HasCachedSecretProviders = sourcesArr.Any(provider => provider.CachedSecretProvider != null);
            HasSyncSecretProviders = sourcesArr.Any(provider => provider.SyncSecretProvider != null);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CompositeSecretProvider"/> class.
        /// </summary>
        /// <param name="secretProviderSources">The sequence of all available registered secret provider registrations.</param>
        /// <param name="criticalExceptionFilters">The sequence of all available registered critical exception filters.</param>
        /// <param name="auditingOptions">The customized options to configure the auditing of the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="secretProviderSources"/>, <paramref name="criticalExceptionFilters"/> or <paramref name="auditingOptions"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretProviderSources"/> or <paramref name="criticalExceptionFilters"/> contains any <c>null</c> values.</exception>
        public CompositeSecretProvider(
            IEnumerable<SecretStoreSource> secretProviderSources, 
            IEnumerable<CriticalExceptionFilter> criticalExceptionFilters,
            SecretStoreAuditingOptions auditingOptions)
            : this(secretProviderSources, criticalExceptionFilters, auditingOptions, NullLogger<CompositeSecretProvider>.Instance)
        {
        }

        /// <summary>
        /// Gets the flag indicating whether or not this secret store has any <see cref="ICachedSecretProvider"/> registrations.
        /// </summary>
        private bool HasCachedSecretProviders { get; }

        /// <summary>
        /// Gets the flag indicating whether or not this secret store has any <see cref="ISyncSecretProvider"/> registrations.
        /// </summary>
        private bool HasSyncSecretProviders { get; }

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
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="InvalidCastException">Thrown when the registered <see cref="ISecretProvider"/> cannot be cast to the specific <typeparamref name="TSecretProvider"/>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when multiple <see cref="ISecretProvider"/> were registered with the same name.</exception>
        public TSecretProvider GetProvider<TSecretProvider>(string name) where TSecretProvider : ISecretProvider
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException("Requires a non-blank name to retrieve the registered named secret provider", nameof(name));
            }

            ISecretProvider provider = GetProvider(name);
            if (provider is TSecretProvider concreteProvider)
            {
                return concreteProvider;
            }
            
            if (provider is CompositeSecretProvider)
            {
                throw new InvalidOperationException(
                    $"Cannot cast registered {nameof(ISecretProvider)} with name '{name}' to type '{typeof(TSecretProvider).Name}' " +
                    $"because multiple secret providers were registered with the name '{name}', " +
                    $"use the non-generic '{nameof(GetProvider)}' to retrieve them");
            }

            throw new InvalidCastException(
                $"Cannot cast registered {nameof(ISecretProvider)} with name '{name}' to type '{typeof(TSecretProvider).Name}'");
        }

        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        public ISecretProvider GetProvider(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException("Requires a non-blank name to retrieve the registered named secret provider", nameof(name));
            }

            ISecretProvider subset = GetSingleOrSubsetSecretProvider(name);
            return subset;
        }

        /// <summary>
        /// Gets the registered named <see cref="ICachedSecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ICachedSecretProvider"/> in the secret store.</param>
        /// <typeparam name="TCachedSecretProvider">The concrete <see cref="ICachedSecretProvider"/> type.</typeparam>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ICachedSecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        /// <exception cref="NotSupportedException">
        ///     Thrown when their was either none of the registered secret providers are registered as <see cref="ICachedSecretProvider"/> instances
        ///     or there was an <see cref="ISecretProvider"/> registered but not with caching.
        /// </exception>
        /// <exception cref="InvalidCastException">Thrown when the registered <see cref="ICachedSecretProvider"/> cannot be cast to the specific <typeparamref name="TCachedSecretProvider"/>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when multiple <see cref="ICachedSecretProvider"/> were registered with the same name.</exception>
        public TCachedSecretProvider GetCachedProvider<TCachedSecretProvider>(string name) where TCachedSecretProvider : ICachedSecretProvider
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException("Requires a non-blank name to retrieve the registered named secret provider", nameof(name));
            }

            if (!HasCachedSecretProviders)
            {
                throw new NotSupportedException(
                    $"Cannot use cached secret store operation because none of the secret providers in the secret store were registered as cached secret providers ({nameof(ICachedSecretProvider)})");
            }

            ICachedSecretProvider provider = GetCachedProvider(name);
            if (provider is TCachedSecretProvider concreteProvider)
            {
                return concreteProvider;
            }

            if (provider is CompositeSecretProvider)
            {
                throw new InvalidOperationException(
                    $"Cannot cast registered {nameof(ICachedSecretProvider)} with name '{name}' to type '{typeof(TCachedSecretProvider).Name}' " +
                    $"because multiple secret providers were registered with the name '{name}', " +
                    $"use the non-generic '{nameof(GetCachedProvider)}' to retrieve them");
            }

            throw new InvalidCastException(
                $"Cannot cast registered {nameof(ICachedSecretProvider)} with name '{name}' to type '{typeof(TCachedSecretProvider).Name}'");
        }

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
        public ICachedSecretProvider GetCachedProvider(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException("Requires a non-blank name to retrieve the registered named secret provider", nameof(name));
            }

            if (!HasCachedSecretProviders)
            {
                throw new NotSupportedException(
                    $"Cannot use cached secret store operation because none of the secret providers in the secret store were registered as cached secret providers ({nameof(ICachedSecretProvider)})");
            }

            ISecretProvider source = GetSingleOrSubsetSecretProvider(name);
            if (source is ICachedSecretProvider cachedSource)
            {
                return cachedSource;
            }

            throw new NotSupportedException(
                $"Found a registered {nameof(ISecretProvider)} with the name '{name}' in the secret store, but was not configured for caching. "
                + $"Please use the {nameof(GetProvider)} instead or configure the registered provider with caching");
        }

        private ISecretProvider GetSingleOrSubsetSecretProvider(string name)
        {
            if (_groupedSecretStores.TryGetValue(name, out Lazy<ISecretProvider> subsetSecretStore))
            {
                return subsetSecretStore.Value;
            }

            throw new KeyNotFoundException(
                $"Could not retrieve the named {nameof(ISecretProvider)} because no secret provider was registered with the name '{name}'");
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        public string GetRawSecret(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            return WithSecretStore(secretName, source =>
            {
                if (source.SyncSecretProvider != null)
                {
                    string secretValue = source.SyncSecretProvider.GetRawSecret(secretName);
                    return secretValue;
                }

                _logger.LogTrace("Cannot get secret '{SecretName}' via synchronous '{MethodName}' because the registered secret provider '{SecretProviderName}' does not implement '{Interface}'", secretName, nameof(GetSecret), source.Options?.Name ?? source.SecretProvider.GetType().Name, nameof(ISyncSecretProvider));
                return null;
            });
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        public Secret GetSecret(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            return WithSecretStore(secretName, source =>
            {
                if (source.SyncSecretProvider != null)
                {
                    Secret secret = source.SyncSecretProvider.GetSecret(secretName);
                    return secret;
                }

                _logger.LogTrace("Cannot get secret '{SecretName}' via synchronous '{MethodName}' because the registered secret provider '{SecretProviderName}' does not implement '{Interface}'", secretName, nameof(GetSecret), source.Options?.Name ?? source.SecretProvider.GetType().Name, nameof(ISyncSecretProvider));
                return null;
            });
        }

        /// <summary>
        /// Retrieves all the allowed versions of a secret value, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        internal async Task<IEnumerable<Secret>> GetSecretsAsync(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            IEnumerable<Secret> secretValues = 
                await WithSecretStoreAsync(secretName, async source =>
                {
                    if (source.Options.TryGetAllowedSecretVersions(secretName, out int allowedVersions))
                    {
                        if (source.VersionedSecretProvider != null)
                        {
                            IEnumerable<Secret> secrets = await source.VersionedSecretProvider.GetSecretsAsync(secretName, allowedVersions);
                            return secrets.ToArray();
                        }

                        _logger.LogTrace("Cannot get all the allowed versions of secret '{SecretName}' because the registered secret provider '{SecretProviderName}' does not implement '{SecretVersionsProviderName}'", secretName, source.Options?.Name ?? source.SecretProvider.GetType().Name, nameof(IVersionedSecretProvider));
                    }

                    Secret secret = await source.SecretProvider.GetSecretAsync(secretName);
                    if (secret is null)
                    {
                        return null;
                    }

                    return new[] { secret };
                });

            return secretValues.ToArray();
        }

        /// <summary>
        /// Retrieves all the allowed versions of a secret value, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        internal async Task<IEnumerable<string>> GetRawSecretsAsync(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            IEnumerable<string> secretValues = 
                await WithSecretStoreAsync(secretName, async source =>
                {
                    if (source.Options.TryGetAllowedSecretVersions(secretName, out int allowedVersions))
                    {
                        if (source.VersionedSecretProvider != null)
                        {
                            IEnumerable<string> secretValues = await source.VersionedSecretProvider.GetRawSecretsAsync(secretName, allowedVersions);
                            return secretValues.ToArray();
                        }

                        _logger.LogTrace("Cannot get all the allowed versions of secret '{SecretName}' because the registered secret provider '{SecretProviderName}' does not implement '{SecretVersionsProviderName}'", secretName, source.Options?.Name ?? source.SecretProvider.GetType().Name, nameof(IVersionedSecretProvider));
                    }

                    string secretValue = await source.SecretProvider.GetRawSecretAsync(secretName);
                    if (secretValue is null)
                    {
                        return null;
                    }

                    return new[] { secretValue };
                });

            return secretValues.ToArray();
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret value, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        public async Task<IEnumerable<string>> GetRawSecretsAsync(string secretName, int amountOfVersions)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            if (amountOfVersions < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(amountOfVersions), amountOfVersions, "Requires at least 1 secret version to retrieve the secret in the secret store");
            }

            IEnumerable<string> secretValues = 
                await WithSecretStoreAsync(secretName, async source =>
                {
                    if (source.VersionedSecretProvider != null)
                    {
                        IEnumerable<string> secretValues = await source.VersionedSecretProvider.GetRawSecretsAsync(secretName, amountOfVersions);
                        return secretValues.ToArray();
                    }

                    string secretValue = await source.SecretProvider.GetRawSecretAsync(secretName);
                    if (secretValue is null)
                    {
                        return null;
                    }

                    return new[] { secretValue };
                });

            return secretValues.ToArray();
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        public async Task<IEnumerable<Secret>> GetSecretsAsync(string secretName, int amountOfVersions)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            if (amountOfVersions < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(amountOfVersions), amountOfVersions, "Requires at least 1 secret version to retrieve the secret in the secret store");
            }

            IEnumerable<Secret> secretValues = 
                await WithSecretStoreAsync(secretName, async source =>
                {
                    if (source.VersionedSecretProvider != null)
                    {
                        IEnumerable<Secret> secrets = await source.VersionedSecretProvider.GetSecretsAsync(secretName, amountOfVersions);
                        return secrets.ToArray();
                    }

                    Secret secret = await source.SecretProvider.GetSecretAsync(secretName);
                    if (secret is null)
                    {
                        return null;
                    }

                    return new[] { secret };
                });

            return secretValues.ToArray();
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
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

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
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

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
        /// <exception cref="NotSupportedException">Thrown when none of the registered secret providers are registered as <see cref="ICachedSecretProvider"/> instances.</exception>
        public async Task<string> GetRawSecretAsync(string secretName, bool ignoreCache)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

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
        /// <exception cref="NotSupportedException">Thrown when none of the registered secret providers are registered as <see cref="ICachedSecretProvider"/> instances.</exception>
        public async Task<Secret> GetSecretAsync(string secretName, bool ignoreCache)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

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
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to look up the secret", nameof(secretName));
            }

            await WithCachedSecretStoreAsync(secretName, async source =>
            {
                Task invalidateSecretAsync = source.CachedSecretProvider.InvalidateSecretAsync(secretName);
                if (invalidateSecretAsync is null)
                {
                    return null;
                }

                await invalidateSecretAsync;
                return "ignored result";
            }, eventName: "Invalidate Secret");
        }

        private async Task<T> WithCachedSecretStoreAsync<T>(
            string secretName,
            Func<SecretStoreSource, Task<T>> callRegisteredProvider,
            string eventName = "Get Secret") where T : class
        {
            if (!HasCachedSecretProviders)
            {
                throw new NotSupportedException(
                    $"Cannot use cached secret store operation because none of the secret providers in the secret store were registered as cached secret providers ({nameof(ICachedSecretProvider)})");
            }
            return await WithSecretStoreAsync(secretName, async source =>
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
            }, eventName);
        }

        private async Task<T> WithSecretStoreAsync<T>(
            string secretName, 
            Func<SecretStoreSource, Task<T>> callRegisteredProvider, 
            string eventName = "Get Secret") where T : class
        {
            EnsureAnySecretProvidersConfigured(secretName);

            var criticalExceptions = new Collection<Exception>();
            foreach (SecretStoreSource source in _secretProviders)
            {
                try
                {
                    T result = await GetSecretFromProviderAsync(secretName, source, callRegisteredProvider, eventName);
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

        private T WithSecretStore<T>(
            string secretName,
            Func<SecretStoreSource, T> callRegisteredProvider,
            string eventName = "Get Secret") where T : class
        {
            if (!HasSyncSecretProviders)
            {
                throw new NotSupportedException(
                    $"Cannot use synchronous secret store operation because none of the secret providers in the secret store were registered as synchronous secret providers ({nameof(ISyncSecretProvider)})");
            }

            var criticalExceptions = new Collection<Exception>();
            foreach (SecretStoreSource source in _secretProviders)
            {
                try
                {
                    T result = GetSecretFromProvider(secretName, source, callRegisteredProvider, eventName);
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
                _logger.LogError(
                    "No secret providers are configured in the secret store to retrieve the secret from, please configure at least one secret provider with the '{Extension}' extension in the startup of your application",
                    nameof(IHostBuilderExtensions.ConfigureSecretStore));

                var noRegisteredException = new KeyNotFoundException("No secret providers are configured to retrieve the secret from");
                throw new SecretNotFoundException(secretName, noRegisteredException);
            }
        }

        private async Task<T> GetSecretFromProviderAsync<T>(
            string secretName, 
            SecretStoreSource source, 
            Func<SecretStoreSource, Task<T>> callRegisteredProvider,
            string eventName) where T : class
        {
            LogSecurityEvent(source, secretName, eventName);

            Task<T> resultAsync = callRegisteredProvider(source);
            if (resultAsync is null)
            {
                return null;
            }

            T result = await resultAsync;
            return result;
        }

        private T GetSecretFromProvider<T>(
            string secretName,
            SecretStoreSource source,
            Func<SecretStoreSource, T> callRegisteredProvider,
            string eventName)
        {
            LogSecurityEvent(source, secretName, eventName);

            T result = callRegisteredProvider(source);
            return result;
        }

        private void LogSecurityEvent(SecretStoreSource source, string secretName, string eventName)
        {
            if (_auditingOptions.EmitSecurityEvents)
            {
                _logger.LogSecurityEvent(eventName, new Dictionary<string, object>
                {
                    ["SecretName"] = secretName,
                    ["SecretProvider"] = source.Options?.Name ?? source.SecretProvider.GetType().Name
                });
            }
        }

        private void LogPossibleCriticalExceptions(string secretName, IReadOnlyCollection<Exception> criticalExceptions)
        {
            if (criticalExceptions.Any())
            {
                _logger.LogWarning("Found secret with name '{SecretName}' but at the cost of {ExceptionCount} critical exceptions", secretName, criticalExceptions.Count());

                foreach (Exception criticalException in criticalExceptions)
                {
                    _logger.LogWarning(criticalException, "Critical exception thrown during retrieval of secret with name '{SecretName}'", secretName);
                }
            }

            _logger.LogTrace("Found secret with name '{SecretName}'", secretName);
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

        private Exception DetermineSecretStoreException(string secretName, IReadOnlyCollection<Exception> criticalExceptions)
        {
            if (!criticalExceptions.Any())
            {
                _logger.LogError(
                    "None of the configured {Count} configured secret providers was able to retrieve the requested secret with name '{SecretName}'",
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

        private static IDictionary<string, Lazy<ISecretProvider>> CreateGroupedSecretProviders(
            IEnumerable<SecretStoreSource> secretProviders,
            IEnumerable<CriticalExceptionFilter> criticalExceptionFilters,
            SecretStoreAuditingOptions auditingOptions,
            ILogger<CompositeSecretProvider> logger)
        {
            return secretProviders
                   .Where(source => source.Options.Name != null)
                   .GroupBy(source => source.Options.Name)
                   .ToDictionary(group => group.Key, group =>
                   {
                       return new Lazy<ISecretProvider>(() =>
                       {
                           if (group.Count() == 1)
                           {
                               SecretStoreSource source = group.First();
                               return source.CachedSecretProvider ?? source.SecretProvider;
                           }

                           return new CompositeSecretProvider(group, criticalExceptionFilters, auditingOptions, logger);
                       });
                   });
        }
    }
}
