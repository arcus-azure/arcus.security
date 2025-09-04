using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

#pragma warning disable CS0612 // Type or member is obsolete
#pragma warning disable CS0618 // Type or member is obsolete: options will be removed in v3.0.

namespace Arcus.Security
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation representing a series of <see cref="ISecretProvider"/> implementations.
    /// </summary>
    internal class CompositeSecretProvider : ICachedSecretProvider, IVersionedSecretProvider, Core.ISecretStore, ISyncSecretProvider, ISecretStore
    {
        private readonly IReadOnlyCollection<SecretProviderRegistration> _registrations;
        private readonly Dictionary<string, Lazy<ISecretProvider>> _secretProviderByName;
        private readonly ILogger _logger;

        [Obsolete] private readonly IReadOnlyCollection<CriticalExceptionFilter> _criticalExceptionFilters;
        [Obsolete] private readonly SecretStoreAuditingOptions _auditing;

        internal CompositeSecretProvider(
            IEnumerable<SecretProviderRegistration> providerRegistrations,
            IEnumerable<CriticalExceptionFilter> exceptionFilters,
            SecretStoreCaching caching,
            SecretStoreAuditingOptions auditing,
            ILogger logger)
        {
            ArgumentNullException.ThrowIfNull(providerRegistrations);
            ArgumentNullException.ThrowIfNull(exceptionFilters);
            ArgumentNullException.ThrowIfNull(auditing);
            ArgumentNullException.ThrowIfNull(caching);

            _registrations = providerRegistrations.ToArray();
            _criticalExceptionFilters = exceptionFilters.ToArray();
            _auditing = auditing;
            _logger = logger ?? NullLogger.Instance;

            _secretProviderByName =
                _registrations.GroupBy(r => r.Options.ProviderName)
                              .ToDictionary(g => g.Key, g => new Lazy<ISecretProvider>(() => g.Count() is 1 ? g.Single().Provider : new CompositeSecretProvider(g, _criticalExceptionFilters, caching, _auditing, _logger)));

            Cache = caching;
        }

        /// <summary>
        /// Gets the service to interact with the possible configured cache on the secret store.
        /// </summary>
        public SecretStoreCaching Cache { get; }

        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <typeparam name="TProvider">The concrete type of the secret provider implementation.</typeparam>
        /// <param name="providerName">
        ///     The name of the concrete secret provider implementation;
        ///     uses the FQN (fully-qualified name) of the type in case none is provided.
        /// </param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="providerName"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when no secret provider(s) was found with the provided <paramref name="providerName"/>.</exception>
        /// <exception cref="InvalidCastException">Thrown when the found secret provider can't be cast to the provided <typeparamref name="TProvider"/>.</exception>
        TProvider ISecretStore.GetProvider<TProvider>(string providerName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(providerName);

            if (_secretProviderByName.TryGetValue(providerName, out var provider))
            {
                if (provider.Value is TProvider concreteProvider)
                {
                    return concreteProvider;
                }

                throw new InvalidCastException(
                    $"Cannot cast the secret provider '{providerName}' to type '{typeof(TProvider).Name}' because more than a single provider was registered with this name, " +
                    $"please unique names during secret provider registration in the secret store when you want to retrieve their concrete type afterwards, " +
                    $"otherwise use 'ISecretProvider subset = store.GetProvider(\"{providerName}\")' to retrieve a subset of secret providers with the same name");
            }

            throw new KeyNotFoundException(
                $"Cannot find secret provider with name '{providerName}' in the secret store: {Environment.NewLine}" +
                _secretProviderByName.Keys.Select(k => $"- {k}{Environment.NewLine}").Aggregate((x, y) => x + y) +
                $"please make sure that you choose one of these names or register the secret provider(s) with another name using 'options => options.ProviderName = \"{providerName}\"'");
        }

        /// <summary>
        /// Gets the secret by its name from the registered provider.
        /// </summary>
        /// <param name="secretName">The name to identity the stored secret.</param>
        /// <returns>
        ///     <para>[Success] when the secret with the provided <paramref name="secretName"/> was found;</para>
        ///     <para>[Failure] when the secret could not be retrieved via the provider.</para>
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        SecretResult ISecretProvider.GetSecret(string secretName) => GetSecret(secretName, configureOptions: null);

        /// <summary>
        /// Gets the secret by its name from the registered provider.
        /// </summary>
        /// <param name="secretName">The name to identity the stored secret.</param>
        /// <returns>
        ///     <para>[Success] when the secret with the provided <paramref name="secretName"/> was found;</para>
        ///     <para>[Failure] when the secret could not be retrieved via the provider.</para>
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        Task<SecretResult> ISecretProvider.GetSecretAsync(string secretName) => GetSecretAsync(secretName, configureOptions: null);

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
        public SecretResult GetSecret(string secretName, Action<SecretOptions> configureOptions)
        {
            return GetSecretCoreAsync(secretName, (provider, name) => Task.FromResult(provider.GetSecret(name)), configureOptions).Result;
        }

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
        public Task<SecretResult> GetSecretAsync(string secretName, Action<SecretOptions> configureOptions)
        {
            return GetSecretCoreAsync(secretName, (provider, name) => provider.GetSecretAsync(name), configureOptions);
        }

        private async Task<SecretResult> GetSecretCoreAsync(
           string secretName,
           Func<ISecretProvider, string, Task<SecretResult>> getSecretAsync,
           Action<SecretOptions> configureOptions)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
            var options = new SecretOptions();
            configureOptions?.Invoke(options);

            var failures = new Collection<(string providerName, SecretResult)>();
            foreach (SecretProviderRegistration source in _registrations)
            {
                string providerName = source.Options.ProviderName;
                try
                {
                    var mapped = source.Options.SecretNameMapper(secretName);
                    if (Cache.TryGetCachedSecret(secretName, options, out SecretResult cached))
                    {
                        return cached;
                    }

                    LogSecurityEvent(source, secretName, "Get Secret");

                    SecretResult result = await getSecretAsync(source.Provider, mapped);
                    if (result is null)
                    {
                        _logger.LogWarning("Secret store could not found secret '{SecretName}' in secret provider '{ProviderName}' as it returned 'null' upon querying provider", secretName, providerName);
                        continue;
                    }

                    if (result.IsSuccess)
                    {
                        _logger.LogDebug("Secret store found secret '{SecretName}' in secret provider '{ProviderName}'", secretName, providerName);
                        Cache.UpdateSecretInCache(secretName, result, options);
                        return result;
                    }

                    _logger.LogDebug("Secret store could not found secret '{SecretName}' in secret provider '{ProviderName}'", secretName, providerName);
                    failures.Add((providerName, result));
                }
                catch (Exception exception)
                {
                    failures.Add((providerName, SecretResult.Interrupted($"Secret provider '{providerName}' failed to query secret '{secretName}' due to an unexpected failure", exception)));
                    _logger.LogWarning(exception, "Secret store failed to query secret '{SecretName}' in secret provider '{ProviderName}' due to an exception while querying for the secret", secretName, providerName);
                }
            }

            SecretResult finalFailure = CreateFinalFailureSecretResult(secretName, failures);
            return finalFailure;
        }


        private SecretResult CreateFinalFailureSecretResult(string secretName, Collection<(string providerName, SecretResult result)> failures)
        {
            string messages = failures.Count == 0
                ? "No secret providers were registered in the secret store"
                : string.Concat(failures.Select(failure => $"{Environment.NewLine}\t- ({failure.providerName}): {failure.result.Failure} {failure.result.FailureMessage}"));

            var failureMessage = $"No registered secret provider could found secret '{secretName}': {messages}";
            var failureCauses = failures.Where(f => f.result.FailureCause != null).Select(f => f.result.FailureCause).ToArray();

            if (failureCauses.Length <= 0)
            {
                return SecretResult.NotFound(failureMessage);
            }

            var failureCause = failureCauses.Length == 1
                ? failureCauses[0]
                : new AggregateException(failureCauses);

            _logger.LogError(failureCause, failureMessage);

            return failures.Any(f => f.result.Failure is SecretFailure.Interrupted)
                ? SecretResult.Interrupted(failureMessage, failureCause)
                : SecretResult.NotFound(failureMessage, failureCause);
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
        [Obsolete("Will be removed in v3.0 as caching will be handled by the secret store itself")]
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
        [Obsolete("Will be removed in v3.0 in favor of using a new interface")]
        public TSecretProvider GetProvider<TSecretProvider>(string name) where TSecretProvider : Core.ISecretProvider
        {
            var provider = ((ISecretStore) this).GetProvider<ISecretProvider>(name);
            if (provider is CompositeSecretProvider and TSecretProvider typed)
            {
                return typed;
            }

            if (provider is SecretStoreBuilder.DeprecatedSecretProviderAdapter { DeprecatedProvider: TSecretProvider deprecated })
            {
                return deprecated;
            }

            throw new InvalidOperationException(
                $"[warning]: the deprecated 'Arcus.Security.Core.ISecretStore' is used here to retrieve a secret provider." +
                $"Cannot cast the secret provider '{name}' to type '{nameof(Core.ISecretProvider)}' because more than a single provider was registered with this name, " +
                $"please unique names during secret provider registration in the secret store when you want to retrieve their concrete type afterwards, " +
                $"otherwise use 'ISecretProvider subset = store.GetProvider(\"{name}\")' to retrieve a subset of secret providers with the same name");

        }

        /// <summary>
        /// Gets the registered named <see cref="ISecretProvider"/> from the secret store.
        /// </summary>
        /// <param name="name">The name that was used to register the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="name"/> is blank.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there was no <see cref="ISecretProvider"/> found in the secret store with the given <paramref name="name"/>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of using a new interface")]
        public Core.ISecretProvider GetProvider(string name)
        {
            var provider = ((ISecretStore) this).GetProvider<ISecretProvider>(name);
            if (provider is CompositeSecretProvider subset)
            {
                return subset;
            }

            if (provider is SecretStoreBuilder.DeprecatedSecretProviderAdapter deprecated)
            {
                return deprecated.DeprecatedProvider;
            }

            throw new InvalidOperationException(
                $"[warning]: the deprecated 'Arcus.Security.Core.ISecretStore' is used here to retrieve a secret provider." +
                $"Cannot cast the secret provider '{name}' to type '{nameof(Core.ISecretProvider)}' because more than a single provider was registered with this name, " +
                $"please unique names during secret provider registration in the secret store when you want to retrieve their concrete type afterwards, " +
                $"otherwise use 'ISecretProvider subset = store.GetProvider(\"{name}\")' to retrieve a subset of secret providers with the same name");
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
        [Obsolete("Will be removed in v3.0 as caching is handled by the secret store itself")]
        public TCachedSecretProvider GetCachedProvider<TCachedSecretProvider>(string name) where TCachedSecretProvider : ICachedSecretProvider
        {
            var provider = ((ISecretStore) this).GetProvider<ISecretProvider>(name);
            if (provider is CompositeSecretProvider and TCachedSecretProvider typed)
            {
                return typed;
            }

            if (provider is SecretStoreBuilder.DeprecatedSecretProviderAdapter { DeprecatedProvider: TCachedSecretProvider cachedProvider })
            {
                return cachedProvider;
            }

            throw new InvalidOperationException(
                $"[warning]: the deprecated 'Arcus.Security.Core.ISecretStore' is used here to retrieve a secret provider." +
                $"Cannot cast the secret provider '{name}' to type '{typeof(TCachedSecretProvider).Name}' because more than a single provider was registered with this name, " +
                $"please unique names during secret provider registration in the secret store when you want to retrieve their concrete type afterwards, " +
                $"otherwise use 'ISecretProvider subset = store.GetProvider(\"{name}\")' to retrieve a subset of secret providers with the same name");
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
        [Obsolete("Will be removed in v3.0 as caching is handled via the secret store itself")]
        public ICachedSecretProvider GetCachedProvider(string name)
        {
            var provider = ((ISecretStore) this).GetProvider<ISecretProvider>(name);
            if (provider is CompositeSecretProvider subset)
            {
                return subset;
            }

            if (provider is SecretStoreBuilder.DeprecatedSecretProviderAdapter { DeprecatedProvider: ICachedSecretProvider cachedProvider })
            {
                return cachedProvider;
            }

            throw new InvalidOperationException(
                $"[warning]: the deprecated 'Arcus.Security.Core.ISecretStore' is used here to retrieve a secret provider." +
                $"Cannot cast the secret provider '{name}' to type '{nameof(ICachedSecretProvider)}' because more than a single provider was registered with this name, " +
                $"please unique names during secret provider registration in the secret store when you want to retrieve their concrete type afterwards, " +
                $"otherwise use 'ISecretProvider subset = store.GetProvider(\"{name}\")' to retrieve a subset of secret providers with the same name");
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecretAsync) + " instead")]
        public string GetRawSecret(string secretName)
        {
            SecretResult result = GetSecret(secretName, configureOptions: null);
            return result.IsSuccess ? result.Value : throw NotFoundOrCritical(secretName, result);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
        public Secret GetSecret(string secretName)
        {
            SecretResult result = GetSecret(secretName, configureOptions: null);
            return result.IsSuccess ? new Secret(result.Value, result.Version, result.Expiration) : throw NotFoundOrCritical(secretName, result);
        }

        [Obsolete]
        private Exception NotFoundOrCritical(string secretName, SecretResult result)
        {
            if (result.FailureCause != null && IsCriticalException(result.FailureCause))
            {
                return result.FailureCause;
            }

            return new SecretNotFoundException(secretName);
        }

        [Obsolete]
        private bool IsCriticalException(Exception exceptionCandidate)
        {
            return _criticalExceptionFilters.Count > 0 && _criticalExceptionFilters.Any(filter =>
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

        [Obsolete]
        private void LogSecurityEvent(SecretProviderRegistration source, string secretName, string eventName)
        {
            if (_auditing.EmitSecurityEvents)
            {
                _logger.LogSecurityEvent(eventName, new Dictionary<string, object>
                {
                    ["SecretName"] = secretName,
                    ["SecretProvider"] = source.Options.ProviderName
                });
            }
        }

        /// <summary>
        /// Retrieves all the allowed versions of a secret value, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        [Obsolete("Will be removed in v3.0 as versioned secrets will be moved to concrete implementations")]
        internal Task<IEnumerable<Secret>> GetSecretsAsync(string secretName)
        {
            throw new NotSupportedException(
                "Secret store does not support versioned secrets anymore directly on the secret store, " +
                "please retrieve the concrete implementation of your secret provider and call versioned secrets-functionality directly on the provider instead");
        }

        /// <summary>
        /// Retrieves all the allowed versions of a secret value, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecretsAsync) + " instead")]
        internal Task<IEnumerable<string>> GetRawSecretsAsync(string secretName)
        {
            throw new NotSupportedException(
                "Secret store does not support versioned secrets anymore directly on the secret store, " +
                "please retrieve the concrete implementation of your secret provider and call versioned secrets-functionality directly on the provider instead");
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret value, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecretsAsync) + " instead")]
        public Task<IEnumerable<string>> GetRawSecretsAsync(string secretName, int amountOfVersions)
        {
            throw new NotSupportedException(
                "Secret store does not support versioned secrets anymore directly on the secret store, " +
                "please retrieve the concrete implementation of your secret provider and call versioned secrets-functionality directly on the provider instead");
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        [Obsolete("Will be removed in v3.0 as versioned secrets will be moved to concrete implementations")]
        public Task<IEnumerable<Secret>> GetSecretsAsync(string secretName, int amountOfVersions)
        {
            throw new NotSupportedException(
                "Secret store does not support versioned secrets anymore directly on the secret store, " +
                "please retrieve the concrete implementation of your secret provider and call versioned secrets-functionality directly on the provider instead");
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecretAsync) + " instead")]
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            SecretResult result = await GetSecretAsync(secretName, configureOptions: null);
            return result.IsSuccess ? result.Value : throw NotFoundOrCritical(secretName, result);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="System.ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="System.ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            SecretResult result = await GetSecretAsync(secretName, configureOptions: null);
            return result.IsSuccess ? new Secret(result.Value, result.Version, result.Expiration) : throw NotFoundOrCritical(secretName, result);
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
        [Obsolete("Will be removed in v3 in favor of solely using " + nameof(GetSecretAsync) + " instead")]
        public async Task<string> GetRawSecretAsync(string secretName, bool ignoreCache)
        {
            SecretResult result = await GetSecretAsync(secretName, options => options.UseCache = !ignoreCache);
            return result.IsSuccess ? result.Value : throw NotFoundOrCritical(secretName, result);
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
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
        public async Task<Secret> GetSecretAsync(string secretName, bool ignoreCache)
        {
            SecretResult result = await GetSecretAsync(secretName, options => options.UseCache = !ignoreCache);
            return result.IsSuccess ? new Secret(result.Value, result.Version, result.Expiration) : throw NotFoundOrCritical(secretName, result);
        }

        /// <summary>
        /// Removes the secret with the given <paramref name="secretName"/> from the cache;
        /// so the next time <see cref="CachedSecretProvider.GetSecretAsync(string)"/> is called, a new version of the secret will be added back to the cache.
        /// </summary>
        /// <param name="secretName">The name of the secret that should be removed from the cache.</param>
        [Obsolete("Will be removed in v3.0 as invalidating secrets should happen via the " + nameof(ISecretStoreContext))]
        public async Task InvalidateSecretAsync(string secretName)
        {
            await Cache.InvalidateSecretAsync(secretName);
        }
    }
}
