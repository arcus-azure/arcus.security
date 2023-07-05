using System;
using Arcus.Security.Providers.Dapr;
using GuardNet;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Extensions on the <see cref="SecretStoreBuilder"/> to add the secrets from the Dapr secret store.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// Adds the secrets from the Dapr secret store.
        /// </summary>
        /// <param name="builder">The builder instance to add the secret source to.</param>
        /// <param name="secretStore">The name of the Dapr secret store to include in the secret store.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretStore"/> is blank.</exception>
        public static SecretStoreBuilder AddDaprSecretStore(
            this SecretStoreBuilder builder,
            string secretStore)
        {
            Guard.NotNull(builder, nameof(builder));
            Guard.NotNullOrWhitespace(secretStore, nameof(secretStore));

            return AddDaprSecretStore(builder, secretStore, configureOptions: null);
        }

        /// <summary>
        /// Adds the secrets from the Dapr secret store.
        /// </summary>
        /// <param name="builder">The builder instance to add the secret source to.</param>
        /// <param name="secretStore">The name of the Dapr secret store to include in the secret store.</param>
        /// <param name="configureOptions">The function to create an optional set of options to manipulate the basic behavior of how the secrets should be retrieved.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretStore"/> is blank.</exception>
        public static SecretStoreBuilder AddDaprSecretStore(
            this SecretStoreBuilder builder,
            string secretStore,
            Action<DaprSecretProviderOptions> configureOptions)
        {
            Guard.NotNull(builder, nameof(builder));
            Guard.NotNullOrWhitespace(secretStore, nameof(secretStore));

            return AddDaprSecretStore(builder, (provider, options) =>
            {
                var logger = provider.GetService<ILogger<DaprSecretProvider>>();
                return new DaprSecretProvider(secretStore, options, logger);
            }, configureOptions);
        }

        /// <summary>
        /// Adds the secrets from the Dapr secret store.
        /// </summary>
        /// <typeparam name="TCustom">The custom implementation of the <see cref="DaprSecretProvider"/>.</typeparam>
        /// <param name="builder">The builder instance to add the secret source to.</param>
        /// <param name="implementationFactory">The function to create a custom instance of the <see cref="DaprSecretProvider"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddDaprSecretStore<TCustom>(
            this SecretStoreBuilder builder,
            Func<IServiceProvider, TCustom> implementationFactory)
            where TCustom : DaprSecretProvider
        {
            Guard.NotNull(builder, nameof(builder));
            Guard.NotNull(implementationFactory, nameof(implementationFactory));

            return builder.AddProvider(implementationFactory, configureOptions: null);
        }

        /// <summary>
        /// Adds the secrets from the Dapr secret store.
        /// </summary>
        /// <typeparam name="TCustom">The custom implementation of the <see cref="DaprSecretProvider"/>.</typeparam>
        /// <param name="builder">The builder instance to add the secret source to.</param>
        /// <param name="implementationFactory">The function to create a custom instance of the <see cref="DaprSecretProvider"/>.</param>
        /// <param name="configureOptions">The function to create an optional set of options to manipulate the basic behavior of how the secrets should be retrieved.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        public static SecretStoreBuilder AddDaprSecretStore<TCustom>(
            this SecretStoreBuilder builder,
            Func<IServiceProvider, DaprSecretProviderOptions, TCustom> implementationFactory,
            Action<DaprSecretProviderOptions> configureOptions)
            where TCustom : DaprSecretProvider
        {
            Guard.NotNull(builder, nameof(builder));
            Guard.NotNull(implementationFactory, nameof(implementationFactory));

            var options = new DaprSecretProviderOptions();
            configureOptions?.Invoke(options);

            return builder.AddProvider(
                provider => implementationFactory(provider, options), 
                configureOptions: null);
        }
    }
}
