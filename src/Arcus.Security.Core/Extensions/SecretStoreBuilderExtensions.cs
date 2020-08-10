﻿using System;
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
        /// /// <param name="prefix">The optional prefix which will be prepended to the secret name when retrieving environment variables.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        public static SecretStoreBuilder AddEnvironmentVariables(
            this SecretStoreBuilder builder,
            EnvironmentVariableTarget target = EnvironmentVariableSecretProvider.DefaultTarget,
            string prefix = null,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder));

            return builder.AddProvider(new EnvironmentVariableSecretProvider(target, prefix), mutateSecretName);
        }

        /// <summary>
        /// Adds a secret source to the secret store of the application that gets its secrets from the <see cref="IConfiguration"/>.
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="configuration">The configuration of the application, containing secrets.</param>
        /// <param name="mutateSecretName">The function to mutate the secret name before looking it up.</param>
        public static SecretStoreBuilder AddConfiguration(
            this SecretStoreBuilder builder,
            IConfiguration configuration,
            Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder));

            return builder.AddProvider(new ConfigurationSecretProvider(configuration), mutateSecretName);
        }
    }
}
