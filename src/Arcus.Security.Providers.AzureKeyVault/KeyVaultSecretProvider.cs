using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Arcus.Observability.Telemetry.Core;
using Arcus.Security.Core;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Polly;
using Polly.Retry;
using SecretProperties = Azure.Security.KeyVault.Secrets.SecretProperties;

namespace Arcus.Security.Providers.AzureKeyVault
{
    /// <summary>
    ///     Secret key provider that connects to Azure Key Vault
    /// </summary>
    public class KeyVaultSecretProvider :
#pragma warning disable CS0618 // Type or member is obsolete
        IVersionedSecretProvider, ISyncSecretProvider,
#pragma warning restore CS0618 // Type or member is obsolete
        ISecretProvider
    {
        private readonly SecretClient _secretClient;
        private readonly ILogger _logger;

        [Obsolete("Will be removed in v3.0")] private readonly KeyVaultOptions _options = new();

        internal KeyVaultSecretProvider(SecretClient secretClient, ILogger<KeyVaultSecretProvider> logger)
        {
            ArgumentNullException.ThrowIfNull(secretClient);
            _secretClient = secretClient;
            _logger = logger ?? NullLogger<KeyVaultSecretProvider>.Instance;

            VaultUri = secretClient.VaultUri.ToString();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecretProvider"/> class.
        /// </summary>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        /// <exception cref="ArgumentNullException">The <paramref name="tokenCredential"/> cannot be <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="vaultConfiguration"/> cannot be <c>null</c>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of using the secret client directly")]
        public KeyVaultSecretProvider(TokenCredential tokenCredential, IKeyVaultConfiguration vaultConfiguration)
            : this(new SecretClient(vaultConfiguration?.VaultUri, tokenCredential), NullLogger<KeyVaultSecretProvider>.Instance)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecretProvider"/> class.
        /// </summary>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        /// <param name="options">The additional options to configure the provider.</param>
        /// <param name="logger">The logger to write diagnostic trace messages during the interaction with the Azure Key Vault.</param>
        /// <exception cref="ArgumentNullException">The <paramref name="tokenCredential"/> cannot be <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="vaultConfiguration"/> cannot be <c>null</c>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of using the secret client directly")]
        public KeyVaultSecretProvider(TokenCredential tokenCredential, IKeyVaultConfiguration vaultConfiguration, KeyVaultOptions options, ILogger<KeyVaultSecretProvider> logger)
            : this(new SecretClient(vaultConfiguration.VaultUri, tokenCredential), logger)
        {
            _options = options;
        }

        /// <summary>
        /// Gets the logger instance to write diagnostic trace messages during the interaction with the Azure Key Vault.
        /// </summary>
        [Obsolete("Will be removed in v3.0 as inheriting secret providers is not supported anymore")]
        protected ILogger Logger => _logger;

        /// <summary>
        ///     Gets the URI of the Azure Key Vault.
        /// </summary>
        public string VaultUri { get; }

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

            return SuccessOrNotFoundAsync(secretName, name => Task.FromResult(_secretClient.GetSecret(name))).Result;
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
        Task<SecretResult> ISecretProvider.GetSecretAsync(string secretName)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);

            return SuccessOrNotFoundAsync(secretName, name => _secretClient.GetSecretAsync(name));
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        public async Task<SecretsResult> GetVersionedSecretsAsync(string secretName, int amountOfVersions)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
            ArgumentOutOfRangeException.ThrowIfLessThan(amountOfVersions, 1);

            (string[] secretVersions, RequestFailedException failureOnVersions) = await DetermineEnabledVersionsAsync(secretName);
            if (secretVersions.Length is 0)
            {
                SecretResult result = SuccessOrNotFoundVersions(secretName, failureOnVersions);
                return SecretsResult.Create([result]);
            }

            var secrets = new List<SecretResult>();
            foreach (var secretVersion in secretVersions)
            {
                if (secrets.Count == amountOfVersions)
                {
                    break;
                }

                SecretResult result = await SuccessOrNotFoundAsync(secretName, name => _secretClient.GetSecretAsync(name, secretVersion));
                secrets.Add(result);
            }

            return SecretsResult.Create(secrets);
        }

        private static SecretResult SuccessOrNotFoundVersions(string secretName, RequestFailedException failureOnVersions)
        {
            return failureOnVersions?.Status is (int) HttpStatusCode.NotFound
                ? SecretResult.NotFound($"no enabled secret versions found for '{secretName}'", failureOnVersions)
                : SecretResult.Interrupted($"enabled secret versions cannot be retrieved for '{secretName}'", failureOnVersions);
        }

        private async Task<(string[], RequestFailedException)> DetermineEnabledVersionsAsync(string secretName)
        {
            try
            {
                AsyncPageable<SecretProperties> properties = _secretClient.GetPropertiesOfSecretVersionsAsync(secretName);

                var availableVersions = new Collection<SecretProperties>();
                await foreach (SecretProperties property in properties)
                {
                    if (property.Enabled is true)
                    {
                        availableVersions.Add(property);
                    }
                }

                return (availableVersions.OrderByDescending(version => version.CreatedOn)
                                         .Select(version => version.Version)
                                         .ToArray(), null);
            }
            catch (RequestFailedException ex)
            {
                return ([], ex);
            }
        }

        /// <summary>
        /// Stores a new version of an Azure Key Vault secret with the given <paramref name="secretValue"/>.
        /// </summary>
        /// <param name="secretName">The name of the Azure Key Vault secret.</param>
        /// <param name="secretValue">The new value of the Azure Key Vault secret.</param>
        /// <exception cref="ArgumentException">
        ///     Thrown when the <paramref name="secretName"/> or <paramref name="secretValue"/> is blank.
        /// </exception>
        public Task<SecretResult> SetSecretAsync(string secretName, string secretValue)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
            ArgumentException.ThrowIfNullOrWhiteSpace(secretValue);

            return SuccessOrNotFoundAsync(secretName, name => _secretClient.SetSecretAsync(name, secretValue));
        }

        private async Task<SecretResult> SuccessOrNotFoundAsync(string secretName, Func<string, Task<Response<KeyVaultSecret>>> getSecretAsync)
        {
            try
            {
#pragma warning disable CS0612 // Type or member is obsolete
                KeyVaultSecret secret = await TrackDependencyAsync(secretName, () => getSecretAsync(secretName));
#pragma warning restore CS0612 // Type or member is obsolete

                return SecretResult.Success(secret.Name, secret.Value, secret.Properties.Version, secret.Properties.ExpiresOn ?? default);
            }
            catch (RequestFailedException ex) when (ex.Status is (int) HttpStatusCode.NotFound)
            {
                return SecretResult.NotFound($"cannot find secret '{secretName}' in Azure Key Vault secrets", ex);
            }
        }

        [Obsolete]
        private async Task<TResult> TrackDependencyAsync<TResult>(
            string secretName,
            Func<Task<TResult>> secretOperationAsync)
        {
            bool isSuccessful = false;
            using var measurement = DurationMeasurement.Start();
            try
            {
                TResult result = await secretOperationAsync();
                isSuccessful = true;

                return result;
            }
            finally
            {
                if (_options.TrackDependency)
                {
                    Logger.LogAzureKeyVaultDependency(VaultUri, secretName, isSuccessful, measurement);
                }
            }
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        [Obsolete("Will be removed in v3.0 as raw secrets are not supported anymore")]
        public virtual string GetRawSecret(string secretName)
        {
            Secret secret = GetSecret(secretName);
            return secret?.Value;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret key</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        [Obsolete("Will be removed in v3.0 in favor of using secrets results")]
        public virtual Secret GetSecret(string secretName)
        {
            SecretResult result = ((ISecretProvider) this).GetSecret(secretName);
            return result.IsSuccess ? new Secret(result.Value, result.Version, result.Expiration) : throw DetermineFinalException(secretName, result);
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0 as raw secrets are not supported anymore")]
        public virtual async Task<string> GetRawSecretAsync(string secretName)
        {
            Secret secret = await GetSecretAsync(secretName);
            return secret?.Value;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the secret</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0 in favor of using secret results")]
        public virtual async Task<Secret> GetSecretAsync(string secretName)
        {
            SecretResult result = await ((ISecretProvider) this).GetSecretAsync(secretName);
            return result.IsSuccess ? new Secret(result.Value, result.Version, result.Expiration) : throw DetermineFinalException(secretName, result);
        }

        /// <summary>
        /// Stores a secret value with a given secret name
        /// </summary>
        /// <param name="secretName">The name of the secret</param>
        /// <param name="secretValue">The value of the secret</param>
        /// <returns>Returns a <see cref="Secret"/> that contains the latest information for the given secret</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="ArgumentException">The <paramref name="secretValue"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretValue"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        [Obsolete("Will be removed in v3.0, use the " + nameof(SetSecretAsync) + " instead that uses secret results")]
        public virtual async Task<Secret> StoreSecretAsync(string secretName, string secretValue)
        {
            SecretResult result = await SetSecretAsync(secretName, secretValue);
            return result.IsSuccess ? new Secret(result.Value, result.Version, result.Expiration) : throw DetermineFinalException(secretName, result);
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret value, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of using secret results " + nameof(GetVersionedSecretsAsync))]
        public virtual async Task<IEnumerable<string>> GetRawSecretsAsync(string secretName, int amountOfVersions)
        {
            IEnumerable<Secret> secrets = await GetSecretsAsync(secretName, amountOfVersions);
            return secrets.Select(secret => secret.Value);
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        [Obsolete("Will be removed in v3.0 in favor of using secret results " + nameof(GetVersionedSecretsAsync))]
        public virtual async Task<IEnumerable<Secret>> GetSecretsAsync(string secretName, int amountOfVersions)
        {
            SecretsResult result = await GetVersionedSecretsAsync(secretName, amountOfVersions);
            if (result.IsSuccess)
            {
                return result.Select(s => new Secret(s.Value, s.Version, s.Expiration));
            }

            throw result.FailureCause ?? new SecretNotFoundException(secretName);
        }

        [Obsolete("Will be removed in v3.0")]
        private static Exception DetermineFinalException(string secretName, SecretResult result)
        {
            if (result.FailureCause is null or RequestFailedException { Status: (int) HttpStatusCode.NotFound })
            {
                return new SecretNotFoundException(secretName);
            }

            return result.FailureCause;
        }

        /// <summary>
        /// Gets the configured Key Vault client.
        /// </summary>
        [Obsolete("Will be removed in v3.0 as inheriting secret providers is not supported anymore")]
        protected SecretClient GetSecretClient()
        {
            return _secretClient;
        }

        /// <summary>
        /// Client-side throttling when the Key Vault service limit exceeds.
        /// </summary>
        /// <param name="secretOperation">The operation to retry.</param>
        /// <returns>
        ///     The resulting secret bundle of the <paramref name="secretOperation"/>.
        /// </returns>
        [Obsolete("Will be removed in v3.0 as inheriting secret providers is not supported anymore")]
        protected static Task<Response<KeyVaultSecret>> ThrottleTooManyRequestsAsync(Func<Task<Response<KeyVaultSecret>>> secretOperation)
        {
            if (secretOperation is null)
            {
                throw new ArgumentNullException(nameof(secretOperation));
            }

            return GetExponentialBackOffRetryAsyncPolicy((RequestFailedException ex) => ex.Status == 429)
                    .ExecuteAsync(secretOperation);
        }

        [Obsolete("Will be removed in v3.0")]
        private static AsyncRetryPolicy GetExponentialBackOffRetryAsyncPolicy<TException>(Func<TException, bool> exceptionPredicate)
            where TException : Exception
        {
            /* Client-side throttling using exponential back-off when Key Vault service limit exceeds:
             * 1. Wait 1 second, retry request
             * 2. If still throttled wait 2 seconds, retry request
             * 3. If still throttled wait 4 seconds, retry request
             * 4. If still throttled wait 8 seconds, retry request
             * 5. If still throttled wait 16 seconds, retry request */

            return Policy.Handle(exceptionPredicate)
                         .WaitAndRetryAsync(5, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt - 1)));
        }

        /// <summary>
        /// Client-side throttling when the Key Vault service limit exceeds.
        /// </summary>
        /// <param name="secretOperation">The operation to retry.</param>
        /// <returns>
        ///     The resulting secret bundle of the <paramref name="secretOperation"/>.
        /// </returns>
        [Obsolete("Will be removed in v3.0 as inheriting secret providers is not supported anymore")]
        protected static Response<KeyVaultSecret> ThrottleTooManyRequests(Func<Response<KeyVaultSecret>> secretOperation)
        {
            if (secretOperation is null)
            {
                throw new ArgumentNullException(nameof(secretOperation));
            }

            return GetExponentialBackOffRetrySyncPolicy((RequestFailedException ex) => ex.Status == 429)
                .Execute(secretOperation);
        }

        [Obsolete("Will be removed in v3.0")]
        private static RetryPolicy GetExponentialBackOffRetrySyncPolicy<TException>(Func<TException, bool> exceptionPredicate)
            where TException : Exception
        {
            /* Client-side throttling using exponential back-off when Key Vault service limit exceeds:
             * 1. Wait 1 second, retry request
             * 2. If still throttled wait 2 seconds, retry request
             * 3. If still throttled wait 4 seconds, retry request
             * 4. If still throttled wait 8 seconds, retry request
             * 5. If still throttled wait 16 seconds, retry request */

            return Policy.Handle(exceptionPredicate)
                         .WaitAndRetry(5, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt - 1)));
        }
    }
}
