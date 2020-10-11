using System;
using Arcus.Security.Providers.DockerSecrets;
using GuardNet;
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
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c></exception>
        /// <exception cref="ArgumentException">Throw when the <paramref name="directoryPath"/> is blank</exception>
        public static SecretStoreBuilder AddDockerSecrets(this SecretStoreBuilder builder, string directoryPath)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Docker secrets to");
            Guard.NotNullOrWhitespace(directoryPath, nameof(directoryPath), "Requires a non-blank directory path to locate the Docker secrets");

            return builder.AddProvider(new DockerSecretsSecretProvider(directoryPath));
        }
    }
}
