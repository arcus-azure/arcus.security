using System;
using System.Threading.Tasks;
using GuardNet;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Arcus.Security.Core.Providers
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider"/> that can mutate the secret name provided before looking up the secret.
    /// </summary>
    public class MutatedSecretNameSecretProvider : ISecretProvider
    {
        private readonly Func<string, string> _mutateSecretName;
        private readonly ISecretProvider _implementation;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="MutatedSecretNameSecretProvider"/> class.
        /// </summary>
        /// <param name="implementation">The actual <see cref="ISecretProvider"/> implementation to look up the secret.</param>
        /// <param name="mutateSecretName">The function to mutate the name of the secret before looking up the secret.</param>
        /// <param name="logger">The instance to log diagnostic messages during the secret name mutation.</param>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when the <paramref name="implementation"/> or the <paramref name="mutateSecretName"/> is <c>null</c>.
        /// </exception>
        public MutatedSecretNameSecretProvider(ISecretProvider implementation, Func<string, string> mutateSecretName, ILogger<MutatedSecretNameSecretProvider> logger)
        {
            Guard.NotNull(implementation, nameof(implementation));
            Guard.NotNull(mutateSecretName, nameof(mutateSecretName));

            _mutateSecretName = mutateSecretName;
            _implementation = implementation;
            _logger = logger ?? NullLogger<MutatedSecretNameSecretProvider>.Instance;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name when mutating secret names");

            string mutatedSecretName = MutateSecretName(secretName);
            Task<string> rawSecretAsync = _implementation.GetRawSecretAsync(mutatedSecretName);

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
                _logger.LogError(
                    exception, "Failure during retrieving secret '{MutatedSecretName}' that was mutated from '{OriginalSecretName}'", mutatedSecretName, secretName);

                throw new SecretNotFoundException(mutatedSecretName, exception);
            }
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public async Task<Secret> GetSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name when mutating secret names");

            string mutatedSecretName = MutateSecretName(secretName);
            Task<Secret> secretAsync = _implementation.GetSecretAsync(mutatedSecretName);

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
                _logger.LogError(
                    exception, "Failure during retrieving secret '{MutatedSecretName}' that was mutated from '{OriginalSecretName}'", mutatedSecretName, secretName);
                
                throw new SecretNotFoundException(mutatedSecretName, exception);
            }
        }

        private string MutateSecretName(string secretName)
        {
            try
            {
                _logger.LogTrace("Start mutating secret name '{SecretName}'...", secretName);
                string mutateSecretName = _mutateSecretName(secretName);
                _logger.LogInformation("Secret name '{OriginalSecretName}' mutated to '{MutatedSecretName}'", secretName, mutateSecretName);

                return mutateSecretName;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Failure during secret name mutation of '{SecretName}'", secretName);
                throw new NotSupportedException(
                    $"The secret '{secretName}' was not correct input for the secret name mutation expression", exception);
            }
        }
    }
}
