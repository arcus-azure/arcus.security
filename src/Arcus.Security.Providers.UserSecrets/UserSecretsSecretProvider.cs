using System;
using System.Threading.Tasks;
using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.Configuration.Json;

namespace Arcus.Security.Providers.UserSecrets
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that provides user secrets.
    /// </summary>
    public class UserSecretsSecretProvider : ISecretProvider
    {
        private readonly JsonConfigurationProvider _jsonProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="UserSecretsSecretProvider"/> class.
        /// </summary>
        /// <param name="jsonProvider">The JSON configuration instance to provide the loaded user secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="jsonProvider"/> is <c>null</c>.</exception>
        public UserSecretsSecretProvider(JsonConfigurationProvider jsonProvider)
        {
            Guard.NotNull(jsonProvider, nameof(jsonProvider), "Requires a JSON configuration instance to provide user secrets");
            _jsonProvider = jsonProvider;
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the user secret value");

            string secretValue = await GetRawSecretAsync(secretName);
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
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public Task<string> GetRawSecretAsync(string secretName)
        {
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to look up the user secret value");

            if (_jsonProvider.TryGet(secretName, out string value))
            {
                return Task.FromResult(value);
            }

            return Task.FromResult<string>(null);
        }
    }
}
