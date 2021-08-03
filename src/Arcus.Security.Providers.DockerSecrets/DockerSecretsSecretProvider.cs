using Arcus.Security.Core;
using GuardNet;
using Microsoft.Extensions.Configuration.KeyPerFile;
using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.FileProviders;

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
        /// <param name="secretsDirectoryPath">The directory path inside the Docker container where the secrets are located.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretsDirectoryPath"/> is blank or not an absolute path.</exception>
        /// <exception cref="DirectoryNotFoundException">Thrown when the <paramref name="secretsDirectoryPath"/> is not found on the system.</exception>
        public DockerSecretsSecretProvider(string secretsDirectoryPath)
        {
            Guard.NotNullOrWhitespace(secretsDirectoryPath, nameof(secretsDirectoryPath), "Requires a directory path inside the Docker container where the secrets are located");
            Guard.For(() => !Path.IsPathRooted(secretsDirectoryPath), 
                new ArgumentException("Requires an absolute directory path inside the Docker container to located the secrets", nameof(secretsDirectoryPath)));

            if (!Directory.Exists(secretsDirectoryPath))
            {
                throw new DirectoryNotFoundException($"The directory {secretsDirectoryPath} which is configured as secretsDirectoryPath does not exist.");
            }

            var configuration = new KeyPerFileConfigurationSource
            {
                FileProvider = new PhysicalFileProvider(secretsDirectoryPath),
                Optional = false
            };

            var provider = new KeyPerFileConfigurationProvider(configuration);
            provider.Load();

            _provider = provider;
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
    }
}
