using System;
using System.IO;
using Arcus.Security.Providers.DockerSecrets;

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
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 in favor of not using optional arguments, use the with the secret provider exposed options to mutate the secret name, or use the one without the optional argument for the default registration")]
#pragma warning restore S1133
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
#pragma warning disable S1133
        [Obsolete("Will be removed in v3.0 in favor of exposing the secret provider options directly to configure the provider")]
#pragma warning restore S1133
        public static SecretStoreBuilder AddDockerSecrets(
            this SecretStoreBuilder builder,
            string directoryPath,
            string name,
            Func<string, string> mutateSecretName)
        {
            ArgumentNullException.ThrowIfNull(builder);

            return builder.AddProvider(DockerSecretsSecretProvider.CreateAt(directoryPath), options =>
            {
                options.Name = name;
                options.MutateSecretName = mutateSecretName;
            });
        }
    }
}
