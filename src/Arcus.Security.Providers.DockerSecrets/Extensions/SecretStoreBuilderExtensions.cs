using System;
using Arcus.Security.Core;
using Arcus.Security.Providers.DockerSecrets;
using GuardNet;

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
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c></exception>
        /// <exception cref="ArgumentException">Throw when the <paramref name="directoryPath"/> is blank</exception>
        public static SecretStoreBuilder AddDockerSecrets(this SecretStoreBuilder builder, string directoryPath, Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Docker secrets to");
            Guard.NotNullOrWhitespace(directoryPath, nameof(directoryPath), "Requires a non-blank directory path to locate the Docker secrets");

            return AddDockerSecrets(builder, directoryPath, options => options.MutateSecretName = mutateSecretName);
        }

        /// <summary>
        /// Adds Docker secrets (mounted as files in the Docker container) to the secret store.
        /// </summary>
        /// <param name="builder">The builder to add the Docker secrets provider to.</param>
        /// <param name="directoryPath">The path inside the container where the Docker secrets are located.</param>
        /// <param name="configureOptions">The function to configure the registration of the <see cref="ISecretProvider"/> in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c></exception>
        /// <exception cref="ArgumentException">Throw when the <paramref name="directoryPath"/> is blank</exception>
        public static SecretStoreBuilder AddDockerSecrets(
            this SecretStoreBuilder builder, 
            string directoryPath, 
            Action<SecretProviderOptions> configureOptions)
        {
            Guard.NotNull(builder, nameof(builder), "Requires a secret store builder to add the Docker secrets to");
            Guard.NotNullOrWhitespace(directoryPath, nameof(directoryPath), "Requires a non-blank directory path to locate the Docker secrets");

            return builder.AddProvider(new DockerSecretsSecretProvider(directoryPath), configureOptions);
        }
    }
}
