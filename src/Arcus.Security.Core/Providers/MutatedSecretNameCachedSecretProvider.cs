using System;
using System.Threading.Tasks;
using Arcus.Security.Core.Caching;
using Arcus.Security.Core.Caching.Configuration;
using GuardNet;
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
            Guard.NotNull(implementation, nameof(implementation), "Requires an secret provider instance to pass the mutated secret name to");
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name when mutating secret names");

            string mutatedSecretName = MutateSecretName(secretName);
            Task<string> rawSecretAsync = _implementation.GetRawSecretAsync(mutatedSecretName, ignoreCache);

            if (rawSecretAsync is null)
            {
                throw new SecretNotFoundException(mutatedSecretName);
            }

            try
            {
                return await rawSecretAsync;
            }
            catch (Exception exception)
            {
                Logger.LogError(
                    exception, "Failure during retrieving secret '{MutatedSecretName}' that was mutated from '{OriginalSecretName}'", mutatedSecretName, secretName);

                throw new SecretNotFoundException(mutatedSecretName, exception);
            }
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name when mutating secret names");

            string mutatedSecretName = MutateSecretName(secretName);
            Task<Secret> secretAsync = _implementation.GetSecretAsync(mutatedSecretName, ignoreCache);

            if (secretAsync is null)
            {
                throw new SecretNotFoundException(mutatedSecretName);
            }

            try
            {
                return await secretAsync;
            }
            catch (Exception exception)
            {
                Logger.LogError(
                    exception, "Failure during retrieving secret '{MutatedSecretName}' that was mutated from '{OriginalSecretName}'", mutatedSecretName, secretName);

                throw new SecretNotFoundException(mutatedSecretName, exception);
            }
        }

        /// <summary>
        /// Removes the secret with the given <paramref name="secretName"/> from the cache;
        /// so the next time <see cref="ISecretProvider.GetSecretAsync(string)"/> is called, a new version of the secret will be added back to the cache.
        /// </summary>
        /// <param name="secretName">The name of the secret that should be removed from the cache.</param>
        public async Task InvalidateSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name when mutating secret names");

            string mutatedSecretName = MutateSecretName(secretName);
            Task invalidateSecretAsync = _implementation.InvalidateSecretAsync(mutatedSecretName);

            if (invalidateSecretAsync is null)
            {
                throw new SecretNotFoundException(mutatedSecretName);
            }

            try
            {
                await invalidateSecretAsync;
            }
            catch (Exception exception)
            {
                Logger.LogError(
                    exception, "Failure during invalidating secret '{MutatedSecretName}' that was mutated from '{OriginalSecretName}'", mutatedSecretName, secretName);

                throw new SecretNotFoundException(mutatedSecretName, exception);
            }
        }
    }
}