using System;
using Arcus.Security.Providers.CommandLine;

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
            return AddCommandLine(builder, arguments, configureOptions: null);
        }

        /// <summary>
        /// Adds command line arguments as secrets to the secret store.
        /// </summary>
        /// <param name="builder">The secret store to add the command line arguments to.</param>
        /// <param name="arguments">The command line arguments that will be considered secrets.</param>
        /// <param name="configureOptions">The optional function to manipulate the registration of the secret provider.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="arguments"/> is <c>null</c>.</exception>
        internal static SecretStoreBuilder AddCommandLine(this SecretStoreBuilder builder, string[] arguments, Action<SecretProviderRegistrationOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            return builder.AddProvider(CommandLineSecretProvider.CreateFor(arguments), configureOptions);
        }
    }

    /// <summary>
    /// Provides a series of extensions to add the command line types to the secret store.
    /// </summary>
    public static class DeprecatedSecretStoreBuilderExtensions
    {
        /// <summary>
        /// Adds command line arguments as secrets to the secret store.
        /// </summary>
        /// <param name="builder">The secret store to add the command line arguments to.</param>
        /// <param name="arguments">The command line arguments that will be considered secrets.</param>
        /// <param name="name">The unique name to register this provider in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="arguments"/> is <c>null</c>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of not using optional arguments, use the with the secret provider exposed options to mutate the secret name, or use the one without the optional argument for the default registration")]
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
        [Obsolete("Will be removed in v3.0 in favor of not using optional arguments, use the with the secret provider exposed options to mutate the secret name, or use the one without the optional argument for the default registration")]
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
        [Obsolete("Will be removed in v3.0 in favor of not using optional arguments, use the with the secret provider exposed options to mutate the secret name, or use the one without the optional argument for the default registration")]
        public static SecretStoreBuilder AddCommandLine(this SecretStoreBuilder builder, string[] arguments, string name, Func<string, string> mutateSecretName)
        {
            return builder.AddCommandLine(arguments, options =>
            {
                options.ProviderName = name;
                options.MapSecretName(mutateSecretName);
            });
        }
    }
}
