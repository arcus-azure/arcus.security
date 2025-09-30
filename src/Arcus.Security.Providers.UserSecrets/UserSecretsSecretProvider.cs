using System;
using System.IO;
using System.Threading.Tasks;
using Arcus.Security.Core;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.FileProviders;

namespace Arcus.Security.Providers.UserSecrets
{
    /// <summary>
    /// <see cref="ISecretProvider"/> implementation that provides user secrets.
    /// </summary>
#pragma warning disable S3881 // Constructor will be solely internal in v3.0.
#pragma warning disable CS0612 // Type or member is obsolete: synchronous secret provider interface will be removed in v3.0.
    public class UserSecretsSecretProvider : ISyncSecretProvider, ISecretProvider, IDisposable
#pragma warning restore CS0612 // Type or member is obsolete
#pragma warning restore S3881
    {
        private const string SecretsFileName = "secrets.json";

#pragma warning disable S4487 // Will be used for logging later.
        private readonly string _userSecretsId;
#pragma warning restore S4487
        private readonly JsonConfigurationProvider _jsonProvider;

        private UserSecretsSecretProvider(string userSecretsId, JsonConfigurationProvider jsonProvider)
        {
            _userSecretsId = userSecretsId;
            _jsonProvider = jsonProvider;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UserSecretsSecretProvider"/> class.
        /// </summary>
        /// <param name="jsonProvider">The JSON configuration instance to provide the loaded user secrets.</param>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="jsonProvider"/> is <c>null</c>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of internal creation")]
        public UserSecretsSecretProvider(JsonConfigurationProvider jsonProvider)
        {
            _jsonProvider = jsonProvider ?? throw new ArgumentNullException(nameof(jsonProvider));
        }

        internal static UserSecretsSecretProvider CreateFor(string usersSecretsId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(usersSecretsId);

            string secretPath = PathHelper.GetSecretsPathFromSecretsId(usersSecretsId);
            string directoryPath = Path.GetDirectoryName(secretPath);

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
            source.FileProvider ??= new PhysicalFileProvider(AppContext.BaseDirectory);

            var provider = new JsonConfigurationProvider(source);
            provider.Load();

            return new UserSecretsSecretProvider(usersSecretsId, provider);
        }

        /// <summary>
        /// Gets the secret by its name from the registered provider.
        /// </summary>
        /// <param name="secretName">The name to identity the stored secret.</param>
        /// <returns>
        ///     <para>[Success] when the secret with the provided <paramref name="secretName"/> was found;</para>
        ///     <para>[Failure] when the secret could not be retrieved via the provider.</para>
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        SecretResult ISecretProvider.GetSecret(string secretName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);

            return _jsonProvider.TryGet(secretName, out string secretValue)
                ? SecretResult.Success(secretName, secretValue)
                : SecretResult.NotFound(secretName, $"cannot found '{secretName}' in User Secrets");
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
        public Task<Secret> GetSecretAsync(string secretName)
        {
            Secret secret = GetSecret(secretName);
            return Task.FromResult(secret);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0 as raw secrets are no longer supported")]
        public Task<string> GetRawSecretAsync(string secretName)
        {
            string secretValue = GetRawSecret(secretName);
            return Task.FromResult(secretValue);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
        public Secret GetSecret(string secretName)
        {
            string secretValue = GetRawSecret(secretName);
            if (secretValue is null)
            {
                return null;
            }

            return new Secret(secretValue);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        [Obsolete("Will be removed in v3.0 as raw secrets are no longer supported")]
        public string GetRawSecret(string secretName)
        {
            SecretResult result = ((ISecretProvider) this).GetSecret(secretName);
            return result.IsSuccess ? result.Value : null;
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            _jsonProvider?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
