using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Microsoft.Extensions.Configuration.Json;

namespace Arcus.Security.Providers.UserSecrets
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that provides user secrets.
    /// </summary>
    public class UserSecretsSecretProvider : ISyncSecretProvider
    {
        private readonly JsonConfigurationProvider _jsonProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserSecretsSecretProvider"/> class.
        /// </summary>
        /// <param name="jsonProvider">The JSON configuration instance to provide the loaded user secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="jsonProvider"/> is <c>null</c>.</exception>
        public UserSecretsSecretProvider(JsonConfigurationProvider jsonProvider)
        {
            _jsonProvider = jsonProvider ?? throw new ArgumentNullException(nameof(jsonProvider));
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<Secret> GetSecretAsync(string secretName)
        {
            Secret secret = GetSecret(secretName);
            return Task.FromResult(secret);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<string> GetRawSecretAsync(string secretName)
        {
            string secretValue = GetRawSecret(secretName);
            return Task.FromResult(secretValue);
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
            string secretValue = GetRawSecret(secretName);
            if (secretValue is null)
            {
                return null;
            }

            return new Secret(secretValue);
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
                throw new ArgumentException("Requires a non-blank secret name to look up the user secret value", nameof(secretName));
            }

            if (_jsonProvider.TryGet(secretName, out string value))
            {
                return value;
            }

            return null;
        }
    }
}
