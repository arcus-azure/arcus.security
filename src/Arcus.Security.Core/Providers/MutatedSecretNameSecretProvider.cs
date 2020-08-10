using System;
using System.Threading.Tasks;
using GuardNet;

namespace Arcus.Security.Core.Providers
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider"/> that can mutate the secret name provided before looking up the secret.
    /// </summary>
    public class MutatedSecretNameSecretProvider : ISecretProvider
    {
        private readonly Func<string, string> _mutateSecretName;
        private readonly ISecretProvider _implementation;

        /// <summary>
        /// Initializes a new instance of the <see cref="MutatedSecretNameSecretProvider"/> class.
        /// </summary>
        /// <param name="implementation">The actual <see cref="ISecretProvider"/> implementation to look up the secret.</param>
        /// <param name="mutateSecretName">The function to mutate the name of the secret before looking up the secret.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="implementation"/> or the <paramref name="mutateSecretName"/> is <c>null</c>.</exception>
        public MutatedSecretNameSecretProvider(ISecretProvider implementation, Func<string, string> mutateSecretName)
        {
            Guard.NotNull(implementation, nameof(implementation));
            Guard.NotNull(mutateSecretName, nameof(mutateSecretName));

            _mutateSecretName = mutateSecretName;
            _implementation = implementation;
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
            secretName = _mutateSecretName(secretName);
            Task<string> rawSecretAsync = _implementation.GetRawSecretAsync(secretName);

            if (rawSecretAsync is null)
            {
                throw new SecretNotFoundException(secretName);
            }

            return await rawSecretAsync;

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
            secretName = _mutateSecretName(secretName);
            Task<Secret> secretAsync = _implementation.GetSecretAsync(secretName);

            if (secretAsync is null)
            {
                throw new SecretNotFoundException(secretName);
            }

            return await secretAsync;
        }
    }
}
