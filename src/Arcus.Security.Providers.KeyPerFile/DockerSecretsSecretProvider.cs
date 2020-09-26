using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.Configuration.KeyPerFile;
using System;
using System.Threading.Tasks;

namespace Arcus.Security.Providers.DockerSecrets
{
    public class DockerSecretsSecretProvider : ISecretProvider
    {
        private readonly KeyPerFileConfigurationProvider _provider;

        /// <summary>
        /// Initializes a new instance of the <see cref="DockerSecretsSecretProvider"/> class.
        /// </summary>
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
            string secretValue = await GetRawSecretAsync(secretName);
            if (secretValue == null)
            {
                return null;
            }

            return new Secret(secretValue);
        }
    }
}
