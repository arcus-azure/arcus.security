using System;
using System.IO;
using System.Reflection;
using Arcus.Security.Core;
using Arcus.Security.Providers.UserSecrets;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.FileProviders;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// <see cref="SecretStoreBuilder"/> extensions for adding user secrets to the secret store.
    /// </summary>
    public static class SecretStoreBuilderExtensions
    {
        private const string SecretsFileName = "secrets.json";

        /// <summary>
        /// <para>Adds the user secrets secret source with specified user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <typeparam name="T">The type from the assembly to search for an instance of <see cref="UserSecretsIdAttribute"/>.</typeparam>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="builder"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the assembly containing <typeparamref name="T"/> does not have <see cref="UserSecretsIdAttribute"/>.</exception>
        public static SecretStoreBuilder AddUserSecrets<T>(
            this SecretStoreBuilder builder,
            Func<string, string> mutateSecretName = null) where T : class
        {
            return AddUserSecrets<T>(builder, options => options.MutateSecretName = mutateSecretName);
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
        public static SecretStoreBuilder AddUserSecrets<T>(
            this SecretStoreBuilder builder,
            string name,
            Func<string, string> mutateSecretName) where T : class
        {
            return AddUserSecrets<T>(builder, options =>
            {
                options.Name = name;
                options.MutateSecretName = mutateSecretName;
            });
        }

        private static SecretStoreBuilder AddUserSecrets<T>(
            SecretStoreBuilder builder,
            Action<SecretProviderOptions> configureOptions)
        {
            Assembly assembly = typeof(T).GetTypeInfo().Assembly;
            return AddUserSecrets(builder, assembly, configureOptions);
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
        public static SecretStoreBuilder AddUserSecrets(this SecretStoreBuilder builder, Assembly assembly, Func<string, string> mutateSecretName = null)
        {
            return AddUserSecrets(builder, assembly, options => options.MutateSecretName = mutateSecretName);
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
        public static SecretStoreBuilder AddUserSecrets(
            this SecretStoreBuilder builder,
            Assembly assembly,
            string name,
            Func<string, string> mutateSecretName)
        {
            return AddUserSecrets(builder, assembly, options =>
            {
                options.Name = name;
                options.MutateSecretName = mutateSecretName;
            });
        }

        private static SecretStoreBuilder AddUserSecrets(this SecretStoreBuilder builder, Assembly assembly, Action<SecretProviderOptions> configureOptions)
        {
            string userSecretsId = GetUserSecretsIdFromTypeAssembly(assembly);
            return AddUserSecrets(builder, userSecretsId, configureOptions);
        }

        private static string GetUserSecretsIdFromTypeAssembly(Assembly assembly)
        {
            if (assembly is null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            var attribute = assembly.GetCustomAttribute<UserSecretsIdAttribute>();
            if (attribute is null)
            {
                string assemblyName = assembly.GetName().Name;
                throw new InvalidOperationException(
                    $"Could not find '{nameof(UserSecretsIdAttribute)}' on assembly '{assemblyName}'. "
                    + $"Check that the project for '{assemblyName}' has set the 'UserSecretsId' build property.");
            }

            return attribute.UserSecretsId;
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
        public static SecretStoreBuilder AddUserSecrets(this SecretStoreBuilder builder, string userSecretsId, Func<string, string> mutateSecretName = null)
        {
            return AddUserSecrets(builder, userSecretsId, options => options.MutateSecretName = mutateSecretName);
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
        public static SecretStoreBuilder AddUserSecrets(
            this SecretStoreBuilder builder,
            string userSecretsId,
            string name,
            Func<string, string> mutateSecretName)
        {
            return AddUserSecrets(builder, userSecretsId, options =>
            {
                options.Name = name;
                options.MutateSecretName = mutateSecretName;
            });
        }

        private static SecretStoreBuilder AddUserSecrets(SecretStoreBuilder builder, string userSecretsId, Action<SecretProviderOptions> configureOptions)
        {
            string directoryPath = GetUserSecretsDirectoryPath(userSecretsId);
            JsonConfigurationSource source = CreateJsonFileSource(directoryPath);

            var provider = new JsonConfigurationProvider(source);
            provider.Load();

            return builder.AddProvider(new UserSecretsSecretProvider(provider), configureOptions);
        }

        private static string GetUserSecretsDirectoryPath(string usersSecretsId)
        {
            if (string.IsNullOrWhiteSpace(usersSecretsId))
            {
                throw new ArgumentException("Requires a non-blank user secret ID to determine the local path of the users secrets", nameof(usersSecretsId));
            }

            string secretPath = PathHelper.GetSecretsPathFromSecretsId(usersSecretsId);
            string directoryPath = Path.GetDirectoryName(secretPath);
            
            return directoryPath;
        }

        private static JsonConfigurationSource CreateJsonFileSource(string directoryPath)
        {
            IFileProvider fileProvider = null;
            if (Directory.Exists(directoryPath))
            {
                fileProvider = new PhysicalFileProvider(directoryPath);
            }

            var source = new JsonConfigurationSource
            {
                FileProvider = fileProvider,
                Path = SecretsFileName,
                Optional = false
            };

            source.ResolveFileProvider();
            if (source.FileProvider == null)
            {
                source.FileProvider = new PhysicalFileProvider(AppContext.BaseDirectory ?? String.Empty);
            }

            return source;
        }
    }
}
