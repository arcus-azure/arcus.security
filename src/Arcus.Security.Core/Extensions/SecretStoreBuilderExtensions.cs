using System;
using Arcus.Security.Core.Providers;
using GuardNet;
using Microsoft.Extensions.Configuration;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Extends the <see cref="SecretStoreBuilder"/> to provide additional secret sources.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the environment.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="target">The target on which the environment variables should be retrieved.</param>
        /// <param name="version">The fixed version to attach to each environment variable.</param>
        public static SecretStoreBuilder AddEnvironmentVariables(
            this SecretStoreBuilder builder,
            EnvironmentVariableTarget target = EnvironmentVariableSecretProvider.DefaultTarget,
            string version = EnvironmentVariableSecretProvider.DefaultVersion)
        {
            Guard.NotNull(builder, nameof(builder));
            Guard.NotNull(version, nameof(version));

            return builder.AddProvider(new EnvironmentVariableSecretProvider(target, version));
        }

        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the <see cref="IConfiguration"/>.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="configuration">The configuration of the application, containing secrets.</param>
        /// <param name="version">The fixed version to attach to each configured variable.</param>
        public static SecretStoreBuilder AddConfiguration(
            this SecretStoreBuilder builder,
            IConfiguration configuration,
            string version = ConfigurationSecretProvider.DefaultVersion)
        {
            Guard.NotNull(builder, nameof(builder));
            Guard.NotNull(version, nameof(version));

            return builder.AddProvider(new ConfigurationSecretProvider(configuration, version));
        }
    }
}
