using System;
using Arcus.Security.Core.Providers;
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
        /// Adds a secret source to the secret store of the application that gets its secrets from the environment (target: <see cref="EnvironmentVariableTarget.Process"/>).
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        public static SecretStoreBuilder AddEnvironmentVariables(this SecretStoreBuilder builder)
        {
            ArgumentNullException.ThrowIfNull(builder);
            return builder.AddProvider(new EnvironmentVariableSecretProvider());
        }

        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the <see cref="IConfiguration"/>.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="configuration">The configuration of the application, containing secrets.</param>
        public static SecretStoreBuilder AddConfiguration(this SecretStoreBuilder builder, IConfiguration configuration)
        {
            ArgumentNullException.ThrowIfNull(builder);
            return builder.AddProvider(new ConfigurationSecretProvider(configuration));
        }
    }

    /// <summary>
    /// Extends the <see cref="SecretStoreBuilder"/> to provide additional secret sources.
    /// </summary>
    public static class DeprecatedSecretStoreBuilderExtensions
    {
        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the environment.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="target">The target on which the environment variables should be retrieved.</param>
        /// <param name="prefix">The optional prefix which will be prepended to the secret name when retrieving environment variables.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="target"/> is outside the bounds of the enumeration.</exception>
        [Obsolete("Will be removed in v3.0 in favor of configuring the secret provider registration with options")]
        public static SecretStoreBuilder AddEnvironmentVariables(
            this SecretStoreBuilder builder,
            EnvironmentVariableTarget target = EnvironmentVariableSecretProvider.DefaultTarget,
            string prefix = null,
            Func<string, string> mutateSecretName = null)
        {
            return AddEnvironmentVariables(builder, target, prefix, name: null, mutateSecretName: mutateSecretName);
        }


        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the environment.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="target">The target on which the environment variables should be retrieved.</param>
        /// <param name="prefix">The optional prefix which will be prepended to the secret name when retrieving environment variables.</param>
        /// <param name="name">The unique name to register this Environment Variables provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="target"/> is outside the bounds of the enumeration.</exception>
        [Obsolete("Will be removed in v3.0 in favor of configuring the secret provider registration with options")]
        public static SecretStoreBuilder AddEnvironmentVariables(
            this SecretStoreBuilder builder,
            EnvironmentVariableTarget target,
            string prefix,
            string name,
            Func<string, string> mutateSecretName)
        {
            ArgumentNullException.ThrowIfNull(builder);

            if (!Enum.IsDefined(typeof(EnvironmentVariableTarget), target))
            {
                throw new ArgumentException($"Requires an environment variable target of either '{EnvironmentVariableTarget.Process}', '{EnvironmentVariableTarget.Machine}', or '{EnvironmentVariableTarget.User}'");
            }

            return builder.AddProvider(new EnvironmentVariableSecretProvider(target, prefix), options =>
            {
                options.Name = name;
                options.MutateSecretName = mutateSecretName;
            });
        }

        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the <see cref="IConfiguration"/>.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="configuration">The configuration of the application, containing secrets.</param>
        /// <param name="mutateSecretName">The function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of configuring the secret provider registration with options")]
        public static SecretStoreBuilder AddConfiguration(
            this SecretStoreBuilder builder,
            IConfiguration configuration,
            Func<string, string> mutateSecretName = null)
        {
            return AddConfiguration(builder, configuration, name: null, mutateSecretName: mutateSecretName);
        }


        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the <see cref="IConfiguration"/>.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="configuration">The configuration of the application, containing secrets.</param>
        /// <param name="name">The unique name to register this Configuration provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of configuring the secret provider registration with options")]
        public static SecretStoreBuilder AddConfiguration(
            this SecretStoreBuilder builder,
            IConfiguration configuration,
            string name,
            Func<string, string> mutateSecretName)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(configuration);

            return builder.AddProvider(new ConfigurationSecretProvider(configuration), options =>
            {
                options.Name = name;
                options.MutateSecretName = mutateSecretName;
            });
        }
    }
}
