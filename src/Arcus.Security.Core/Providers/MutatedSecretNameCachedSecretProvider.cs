using System;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using Microsoft.Extensions.Logging;

namespace Arcus.Security.Core.Providers
{
    /// <summary>
    /// Represents an <see cref="ICachedSecretProvider"/> that can mutate the secret name provided before looking up the secret.
    /// </summary>
    public class MutatedSecretNameCachedSecretProvider : MutatedSecretNameSecretProvider, ICachedSecretProvider
    {
        private readonly ICachedSecretProvider _implementation;

        /// <summary>
        /// Initializes a new instance of the <see cref="MutatedSecretNameSecretProvider"/> class.
        /// </summary>
        /// <param name="implementation">The actual <see cref="ISecretProvider"/> implementation to look up the secret.</param>
        /// <param name="mutateSecretName">The function to mutate the name of the secret before looking up the secret.</param>
        /// <param name="logger">The instance to log diagnostic messages during the secret name mutation.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="implementation"/> or the <paramref name="mutateSecretName"/> is <c>null</c>.
        /// </exception>
        public MutatedSecretNameCachedSecretProvider(
            ICachedSecretProvider implementation,
            Func<string, string> mutateSecretName,
            ILogger logger)
            : base(implementation, mutateSecretName, logger)
        {
            if (implementation is null)
            {
                throw new ArgumentNullException(nameof(implementation), "Requires a secret provider instance to pass the mutated")
            }

            _implementation = implementation;
        }

        /// <summary>
        /// Gets the cache-configuration for this instance.
        /// </summary>
        public ICacheConfiguration Configuration => _implementation.Configuration;

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
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            string secretValue = await SafeguardMutateSecretAsync(secretName, mutatedSecretName =>
            {
                return _implementation.GetRawSecretAsync(mutatedSecretName, ignoreCache);
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
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            Secret secret = await SafeguardMutateSecretAsync(secretName, mutatedSecretName =>
            {
                return _implementation.GetSecretAsync(mutatedSecretName, ignoreCache);
            });

            return secret;
        }

        /// <summary>
        /// Removes the secret with the given <paramref name="secretName"/> from the cache;
        /// so the next time <see cref="ISecretProvider.GetSecretAsync(string)"/> is called, a new version of the secret will be added back to the cache.
        /// </summary>
        /// <param name="secretName">The name of the secret that should be removed from the cache.</param>
        public async Task InvalidateSecretAsync(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name when mutating secret names", nameof(secretName));
            }

            await SafeguardMutateSecretAsync(secretName, async mutatedSecretName => 
            {
                await _implementation.InvalidateSecretAsync(mutatedSecretName);
            });
        }
    }
}