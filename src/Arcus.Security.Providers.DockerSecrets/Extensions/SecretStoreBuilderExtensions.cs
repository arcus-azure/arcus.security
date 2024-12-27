using System;
using System.IO;
using Arcus.Security.Providers.DockerSecrets;
using Microsoft.Extensions.Configuration.KeyPerFile;
using Microsoft.Extensions.FileProviders;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Extensions on the <see cref="SecretStoreBuilder" /> to easily provide access to Docker secrets in the secret store.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// Adds Docker secrets (mounted as files in the Docker container) to the secret store.
        /// </summary>
        /// <param name="builder">The builder to add the Docker secrets provider to.</param>
        /// <param name="directoryPath">The path inside the container where the Docker secrets are located.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Throw when the <paramref name="directoryPath"/> is blank or is not an absolute path.</exception>
        public static SecretStoreBuilder AddDockerSecrets(this SecretStoreBuilder builder, string directoryPath, Func<string, string> mutateSecretName = null)
        {
            return AddDockerSecrets(builder, directoryPath, name: null, mutateSecretName: mutateSecretName);
        }

        /// <summary>
        /// Adds Docker secrets (mounted as files in the Docker container) to the secret store.
        /// </summary>
        /// <param name="builder">The builder to add the Docker secrets provider to.</param>
        /// <param name="directoryPath">The path inside the container where the Docker secrets are located.</param>
        /// <param name="name">The unique name to register this HashiCorp provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Throw when the <paramref name="directoryPath"/> is blank or is not an absolute path.</exception>
        /// <exception cref="DirectoryNotFoundException">Thrown when the <paramref name="directoryPath"/> is not found on the system.</exception>
        public static SecretStoreBuilder AddDockerSecrets(
            this SecretStoreBuilder builder, 
            string directoryPath, 
            string name,
            Func<string, string> mutateSecretName)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (string.IsNullOrWhiteSpace(directoryPath))
            {
                throw new ArgumentException("Requires a non-blank directory path inside the Docker container to locate the secrets", nameof(directoryPath));
            }

            if (!Path.IsPathRooted(directoryPath))
            {
                throw new ArgumentException("Requires an absolute directory path inside the Docker container to located the secrets", nameof(directoryPath));
            }

            if (!Directory.Exists(directoryPath))
            {
                throw new DirectoryNotFoundException($"The directory {directoryPath} which is configured as secretsDirectoryPath does not exist.");
            }

            var configuration = new KeyPerFileConfigurationSource
            {
                FileProvider = new PhysicalFileProvider(directoryPath),
                Optional = false
            };

            var provider = new KeyPerFileConfigurationProvider(configuration);
            provider.Load();
            
            return builder.AddProvider(new DockerSecretsSecretProvider(directoryPath), options =>
            {
                options.Name = name;
                options.MutateSecretName = mutateSecretName;
            });
        }
    }
}
