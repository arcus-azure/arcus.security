using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.Configuration.KeyPerFile;
using System;
using System.Threading.Tasks;

namespace Arcus.Security.Providers.DockerSecrets
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider" /> that provides access to the Docker secrets mounted into the Docker container as files.
    /// </summary>
    public class DockerSecretsSecretProvider : ISecretProvider
    {
        private readonly KeyPerFileConfigurationProvider _provider;

        /// <summary>
        /// Initializes a new instance of the <see cref="DockerSecretsSecretProvider"/> class.
        /// </summary>
        /// <param name="configurationSource">The configuration source that provides the Docker secrets mounted as files in the container.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="configurationSource"/> is <c>null</c></exception>
        public DockerSecretsSecretProvider(KeyPerFileConfigurationSource configurationSource)
        {
            Guard.NotNull(configurationSource, nameof(configurationSource));
            _provider = new KeyPerFileConfigurationProvider(configurationSource);
            _provider.Load();
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to retrieve a Docker secret");

            if (_provider.TryGet(secretName, out string value))
            {
                return Task.FromResult(value);
            }

            return Task.FromResult<string>(null);
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
            Guard.NotNullOrWhitespace(secretName, nameof(secretName), "Requires a non-blank secret name to retrieve a Docker secret");

            string secretValue = await GetRawSecretAsync(secretName);
            if (secretValue == null)
            {
                return null;
            }

            return new Secret(secretValue);
        }
    }
}
