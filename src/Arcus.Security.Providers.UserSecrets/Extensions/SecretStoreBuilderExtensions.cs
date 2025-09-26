using System;
using System.Reflection;
using Arcus.Security.Providers.UserSecrets;
using Microsoft.Extensions.Configuration.UserSecrets;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// <see cref="SecretStoreBuilder"/> extensions for adding user secrets to the secret store.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <typeparam name="T">The type from the assembly to search for an instance of <see cref="UserSecretsIdAttribute"/>.</typeparam>
        /// <param name="builder">The builder to create the secret store.</param>
        public static SecretStoreBuilder AddUserSecrets<T>(this SecretStoreBuilder builder) where T : class
        {
            return AddUserSecrets<T>(builder, configureOptions: null);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <typeparam name="T">The type from the assembly to search for an instance of <see cref="UserSecretsIdAttribute"/>.</typeparam>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="configureOptions">The optional function to manipulate the registration of the secret provider.</param>
        public static SecretStoreBuilder AddUserSecrets<T>(this SecretStoreBuilder builder, Action<SecretProviderRegistrationOptions> configureOptions)
            where T : class
        {
            Assembly assembly = typeof(T).GetTypeInfo().Assembly;
            return AddUserSecrets(builder, assembly);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source. This searches <paramref name="assembly"/> for an instance
        /// of <see cref="UserSecretsIdAttribute"/>, which specifies a user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="assembly">The assembly with the <see cref="UserSecretsIdAttribute" />.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or the <paramref name="assembly"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the passed <paramref name="assembly"/> has no User Secrets attribute defined.</exception>
        public static SecretStoreBuilder AddUserSecrets(this SecretStoreBuilder builder, Assembly assembly)
        {
            return AddUserSecrets(builder, assembly, configureOptions: null);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source. This searches <paramref name="assembly"/> for an instance
        /// of <see cref="UserSecretsIdAttribute"/>, which specifies a user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="assembly">The assembly with the <see cref="UserSecretsIdAttribute" />.</param>
        /// <param name="configureOptions">The optional function to manipulate the registration of the secret provider.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or the <paramref name="assembly"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the passed <paramref name="assembly"/> has no User Secrets attribute defined.</exception>
        public static SecretStoreBuilder AddUserSecrets(
            this SecretStoreBuilder builder,
            Assembly assembly,
            Action<SecretProviderRegistrationOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(assembly);

            var attribute = assembly.GetCustomAttribute<UserSecretsIdAttribute>();
            if (attribute is null)
            {
                string assemblyName = assembly.GetName().Name;
                throw new InvalidOperationException(
                    $"Could not find '{nameof(UserSecretsIdAttribute)}' on assembly '{assemblyName}'. "
                    + $"Check that the project for '{assemblyName}' has set the 'UserSecretsId' build property.");
            }

            return AddUserSecrets(builder, attribute.UserSecretsId, configureOptions);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="userSecretsId">The user secrets ID.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="userSecretsId"/> is blank.</exception>
        public static SecretStoreBuilder AddUserSecrets(this SecretStoreBuilder builder, string userSecretsId)
        {
            return AddUserSecrets(builder, userSecretsId, configureOptions: null);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="userSecretsId">The user secrets ID.</param>
        /// <param name="configureOptions">The optional function to manipulate the registration of the secret provider.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="userSecretsId"/> is blank.</exception>
        public static SecretStoreBuilder AddUserSecrets(
            this SecretStoreBuilder builder,
            string userSecretsId,
            Action<SecretProviderRegistrationOptions> configureOptions)
        {
            ArgumentNullException.ThrowIfNull(builder);
            return builder.AddProvider(UserSecretsSecretProvider.CreateFor(userSecretsId), configureOptions);
        }
    }

    /// <summary>
    /// <see cref="SecretStoreBuilder"/> extensions for adding user secrets to the secret store.
    /// </summary>
    public static class DeprecatedSecretStoreBuilderExtensions
    {
        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <typeparam name="T">The type from the assembly to search for an instance of <see cref="UserSecretsIdAttribute"/>.</typeparam>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the assembly containing <typeparamref name="T"/> does not have <see cref="UserSecretsIdAttribute"/>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of exposing the secret provider options directly")]
        public static SecretStoreBuilder AddUserSecrets<T>(
            this SecretStoreBuilder builder,
            Func<string, string> mutateSecretName = null) where T : class
        {
            return AddUserSecrets<T>(builder, name: null, mutateSecretName);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <typeparam name="T">The type from the assembly to search for an instance of <see cref="UserSecretsIdAttribute"/>.</typeparam>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="name">The unique name to register this UserSecrets provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the assembly containing <typeparamref name="T"/> does not have <see cref="UserSecretsIdAttribute"/>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of exposing the secret provider options directly")]
        public static SecretStoreBuilder AddUserSecrets<T>(
            this SecretStoreBuilder builder,
            string name,
            Func<string, string> mutateSecretName) where T : class
        {
            Assembly assembly = typeof(T).GetTypeInfo().Assembly;
            return AddUserSecrets(builder, assembly, name, mutateSecretName);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source. This searches <paramref name="assembly"/> for an instance
        /// of <see cref="UserSecretsIdAttribute"/>, which specifies a user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="assembly">The assembly with the <see cref="UserSecretsIdAttribute" />.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="assembly"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when <paramref name="assembly"/> does not have a valid <see cref="UserSecretsIdAttribute"/>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of exposing the secret provider options directly")]
        public static SecretStoreBuilder AddUserSecrets(this SecretStoreBuilder builder, Assembly assembly, Func<string, string> mutateSecretName = null)
        {
            return AddUserSecrets(builder, assembly, name: null, mutateSecretName);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source. This searches <paramref name="assembly"/> for an instance
        /// of <see cref="UserSecretsIdAttribute"/>, which specifies a user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="assembly">The assembly with the <see cref="UserSecretsIdAttribute" />.</param>
        /// <param name="name">The unique name to register this UserSecrets provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> or <paramref name="assembly"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when <paramref name="assembly"/> does not have a valid <see cref="UserSecretsIdAttribute"/>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of exposing the secret provider options directly")]
        public static SecretStoreBuilder AddUserSecrets(
            this SecretStoreBuilder builder,
            Assembly assembly,
            string name,
            Func<string, string> mutateSecretName)
        {
            ArgumentNullException.ThrowIfNull(assembly);

            var attribute = assembly.GetCustomAttribute<UserSecretsIdAttribute>();
            if (attribute is null)
            {
                string assemblyName = assembly.GetName().Name;
                throw new InvalidOperationException(
                    $"Could not find '{nameof(UserSecretsIdAttribute)}' on assembly '{assemblyName}'. "
                    + $"Check that the project for '{assemblyName}' has set the 'UserSecretsId' build property.");
            }

            return AddUserSecrets(builder, attribute.UserSecretsId, name, mutateSecretName);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="userSecretsId">The user secrets ID.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="userSecretsId"/> is blank.</exception>
        [Obsolete("Will be removed in v3.0 in favor of exposing the secret provider options directly")]
        public static SecretStoreBuilder AddUserSecrets(this SecretStoreBuilder builder, string userSecretsId, Func<string, string> mutateSecretName = null)
        {
            return AddUserSecrets(builder, userSecretsId, name: null, mutateSecretName);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="userSecretsId">The user secrets ID.</param>
        /// <param name="name">The unique name to register this UserSecrets provider in the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="userSecretsId"/> is blank.</exception>
        [Obsolete("Will be removed in v3.0 in favor of exposing the secret provider options directly")]
        public static SecretStoreBuilder AddUserSecrets(
            this SecretStoreBuilder builder,
            string userSecretsId,
            string name,
            Func<string, string> mutateSecretName)
        {
            return builder.AddUserSecrets(userSecretsId, options =>
            {
                if (!string.IsNullOrWhiteSpace(name))
                {
                    options.ProviderName = name;
                }

                if (mutateSecretName != null)
                {
                    options.MapSecretName(mutateSecretName);
                }
            });
        }
    }
}
