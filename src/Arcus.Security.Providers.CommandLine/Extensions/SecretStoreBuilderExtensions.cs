﻿using System;
using Arcus.Security.Providers.CommandLine;
using Microsoft.Extensions.Configuration.CommandLine;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Provides a series of extensions to add the command line types to the secret store.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// Adds command line arguments as secrets to the secret store.
        /// </summary>
        /// <param name="builder">The secret store to add the command line arguments to.</param>
        /// <param name="arguments">The command line arguments that will be considered secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="arguments"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddCommandLine(this SecretStoreBuilder builder, string[] arguments)
        {
            return AddCommandLine(builder, arguments, name: null);
        }

        /// <summary>
        /// Adds command line arguments as secrets to the secret store.
        /// </summary>
        /// <param name="builder">The secret store to add the command line arguments to.</param>
        /// <param name="arguments">The command line arguments that will be considered secrets.</param>
        /// <param name="name">The unique name to register this provider in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="arguments"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddCommandLine(this SecretStoreBuilder builder, string[] arguments, string name)
        {
            return AddCommandLine(builder, arguments, name, mutateSecretName: null);
        }

        /// <summary>
        /// Adds command line arguments as secrets to the secret store.
        /// </summary>
        /// <param name="builder">The secret store to add the command line arguments to.</param>
        /// <param name="arguments">The command line arguments that will be considered secrets.</param>
        /// <param name="mutateSecretName">The function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="arguments"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddCommandLine(this SecretStoreBuilder builder, string[] arguments, Func<string, string> mutateSecretName)
        {
            return AddCommandLine(builder, arguments, name: null, mutateSecretName: mutateSecretName);
        }

        /// <summary>
        /// Adds command line arguments as secrets to the secret store.
        /// </summary>
        /// <param name="builder">The secret store to add the command line arguments to.</param>
        /// <param name="arguments">The command line arguments that will be considered secrets.</param>
        /// <param name="name">The unique name to register this provider in the secret store.</param>
        /// <param name="mutateSecretName">The function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="arguments"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddCommandLine(this SecretStoreBuilder builder, string[] arguments, string name, Func<string, string> mutateSecretName)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (arguments is null)
            {
                throw new ArgumentNullException(nameof(arguments));
            }

            var configProvider = new CommandLineConfigurationProvider(arguments);
            configProvider.Load();
            
            var secretProvider = new CommandLineSecretProvider(configProvider);
            return builder.AddProvider(secretProvider, options =>
            {
                options.Name = name;
                options.MutateSecretName = mutateSecretName;
            });
        }
    }
}
