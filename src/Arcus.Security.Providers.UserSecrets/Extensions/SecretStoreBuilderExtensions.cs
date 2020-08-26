using System;
using System.IO;
using System.Reflection;
using Arcus.Security.Providers.UserSecrets;
using GuardNet;
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
        /// <exception cref="InvalidOperationException">Thrown when the assembly containing <typeparamref name="T"/> does not have <see cref="UserSecretsIdAttribute"/>.</exception>
        public static SecretStoreBuilder AddUserSecrets<T>(
            this SecretStoreBuilder builder,
            Func<string, string> mutateSecretName = null) where T : class
        {
            Guard.NotNull(builder, nameof(builder));

            Assembly assembly = typeof(T).GetTypeInfo().Assembly;
            return AddUserSecrets(builder, assembly, mutateSecretName);
        }

        /// <summary>
        /// <para>Adds the user secrets secret source. This searches <paramref name="assembly"/> for an instance
        /// of <see cref="UserSecretsIdAttribute"/>, which specifies a user secrets ID.</para>
        /// <para>A user secrets ID is unique value used to store and identify a collection of secrets.</para>
        /// </summary>
        /// <param name="builder">The builder to create the secret store.</param>
        /// <param name="assembly">The assembly with the <see cref="UserSecretsIdAttribute" />.</param>
        /// <param name="mutateSecretName">The optional function to mutate the secret name before looking it up.</param>
        /// <exception cref="InvalidOperationException">Thrown when <paramref name="assembly"/> does not have a valid <see cref="UserSecretsIdAttribute"/>.</exception>
        public static SecretStoreBuilder AddUserSecrets(this SecretStoreBuilder builder, Assembly assembly, Func<string, string> mutateSecretName = null)
        {
            Guard.NotNull(builder, nameof(builder));
            Guard.NotNull(assembly, nameof(assembly));

            string userSecretsId = GetUserSecretsIdFromTypeAssembly(assembly);
            return AddUserSecrets(builder, userSecretsId, mutateSecretName);
        }

        private static string GetUserSecretsIdFromTypeAssembly(Assembly assembly)
        {
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
            Guard.NotNull(builder, nameof(builder));
            Guard.NotNullOrWhitespace(userSecretsId, nameof(userSecretsId));

            string directoryPath = GetUserSecretsDirectoryPath(userSecretsId);
            JsonConfigurationSource source = CreateJsonFileSource(directoryPath);

            var provider = new JsonConfigurationProvider(source);
            provider.Load();

            return builder.AddProvider(new UserSecretsSecretProvider(provider), mutateSecretName);
        }

        private static string GetUserSecretsDirectoryPath(string usersSecretsId)
        {
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
