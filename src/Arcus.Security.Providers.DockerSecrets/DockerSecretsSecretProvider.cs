using System;
using System.IO;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Microsoft.Extensions.Configuration.KeyPerFile;
using Microsoft.Extensions.FileProviders;
#pragma warning disable S1133

namespace Arcus.Security.Providers.DockerSecrets
{
    /// <summary>
    /// Represents an <see cref="ISecretProvider" /> that provides access to the Docker secrets mounted into the Docker container as files.
    /// </summary>
#pragma warning disable S3881 // Constructor will be solely internal in v3.0.
#pragma warning disable CS0612 // Type or member is obsolete: synchronous secret provider interface will be removed in v3.0.
    public class DockerSecretsSecretProvider : ISyncSecretProvider, ISecretProvider, IDisposable
#pragma warning restore CS0612 // Type or member is obsolete
#pragma warning restore S3881
    {
        private readonly KeyPerFileConfigurationProvider _provider;

        private DockerSecretsSecretProvider(KeyPerFileConfigurationProvider provider)
        {
            _provider = provider;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DockerSecretsSecretProvider"/> class.
        /// </summary>
        /// <param name="secretsDirectoryPath">The directory path inside the Docker container where the secrets are located.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretsDirectoryPath"/> is blank or not an absolute path.</exception>
        /// <exception cref="DirectoryNotFoundException">Thrown when the <paramref name="secretsDirectoryPath"/> is not found on the system.</exception>
        [Obsolete("Will be removed in v3.0 in favor of internal creation")]
        public DockerSecretsSecretProvider(string secretsDirectoryPath)
        {
            if (string.IsNullOrWhiteSpace(secretsDirectoryPath))
            {
                throw new ArgumentException("Requires a directory path inside the Docker container where the secrets are located", nameof(secretsDirectoryPath));
            }

            if (!Path.IsPathRooted(secretsDirectoryPath))
            {
                throw new ArgumentException("Requires an absolute directory path inside the Docker container to located the secrets", nameof(secretsDirectoryPath));
            }

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

        internal static DockerSecretsSecretProvider CreateAt(string secretsDirectoryPath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretsDirectoryPath);
            if (!Path.IsPathRooted(secretsDirectoryPath))
            {
                throw new ArgumentException("Requires an absolute directory path inside the Docker container to located the secrets", nameof(secretsDirectoryPath));
            }

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

            return new DockerSecretsSecretProvider(provider);
        }

        /// <summary>
        /// Gets the secret by its name from the registered provider.
        /// </summary>
        /// <param name="secretName">The name to identity the stored secret.</param>
        /// <returns>
        ///     <para>[Success] when the secret with the provided <paramref name="secretName"/> was found;</para>
        ///     <para>[Failure] when the secret could not be retrieved via the provider.</para>
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        SecretResult ISecretProvider.GetSecret(string secretName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);

            return _provider.TryGet(secretName, out string secretValue)
                ? SecretResult.Success(secretName, secretValue)
                : SecretResult.NotFound($"cannot found secret '{secretName}' in Docker Secrets");
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
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
        [Obsolete("Will be removed in v3.0 as raw secrets are no longer supported")]
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
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
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
        [Obsolete("Will be removed in v3.0 as raw secrets are no longer supported")]
        public string GetRawSecret(string secretName)
        {
            SecretResult result = ((ISecretProvider) this).GetSecret(secretName);
            return result.IsSuccess ? result.Value : null;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            _provider?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
