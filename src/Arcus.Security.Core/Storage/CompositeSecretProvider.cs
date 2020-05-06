using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using GuardNet;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Core.Storage
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation representing a series of <see cref="ISecretProvider"/> implementations.
    /// </summary>
    internal class CompositeSecretProvider : ISecretProvider
    {
        private readonly IEnumerable<ISecretProvider> _secretProviders;
        private readonly ILogger<CompositeSecretProvider> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompositeSecretProvider"/> class.
        /// </summary>
        public CompositeSecretProvider(IEnumerable<SecretStoreSource> secretProviderSources, ILogger<CompositeSecretProvider> logger)
        {
            Guard.NotNull(secretProviderSources, nameof(secretProviderSources));
            Guard.For<ArgumentException>(() => secretProviderSources.Any(source => source?.SecretProvider is null), "None of the registered secret providers should be 'null'");
            
            _secretProviders = secretProviderSources.Select(source => source.SecretProvider);
            _logger = logger ?? NullLogger<CompositeSecretProvider>.Instance;
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
            Guard.NotNullOrEmpty(secretName, nameof(secretName));

            Secret secret = await GetSecretAsync(secretName);
            return secret?.Value;
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

            if (!_secretProviders.Any())
            {
                var keyNotFoundException = new KeyNotFoundException("No secret providers are configured to retrieve the secret from");
                throw new SecretNotFoundException(secretName, keyNotFoundException);
            }

            Secret secret = await GetSecretFromProvidersAsync(secretName);
            return secret;
        }

        private async Task<Secret> GetSecretFromProvidersAsync(string secretName)
        {
            foreach (ISecretProvider secretProvider in _secretProviders)
            {
                try
                {
                    Secret secret = await secretProvider.GetSecretAsync(secretName);
                    if (!(secret?.Value is null))
                    {
                        return secret;
                    }
                }
                catch (Exception exception)
                {
                    _logger.LogTrace(exception, "Secret provider {Type} doesn't contain secret with name {SecretName}", secretProvider.GetType().Name, secretName);
                }
            }

            var keyNotFoundException = new KeyNotFoundException("None of the configured secret providers contains the requested secret");
            throw new SecretNotFoundException(secretName, keyNotFoundException);
        }
    }
}