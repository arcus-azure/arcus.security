using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Arcus.Observability.Telemetry.Core;
using Arcus.Security.Providers.AzureKeyVault.Configuration;
using Arcus.Security.Core;
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
    public class KeyVaultSecretProvider : IVersionedSecretProvider, ISyncSecretProvider
    {
        private readonly SecretClient _secretClient;
        private readonly KeyVaultOptions _options;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecretProvider"/> class.
        /// </summary>
        /// <param name="tokenCredential">The requested authentication type for connecting to the Azure Key Vault instance</param>
        /// <param name="vaultConfiguration">Configuration related to the Azure Key Vault instance to use</param>
        /// <exception cref="ArgumentNullException">The <paramref name="tokenCredential"/> cannot be <c>null</c>.</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="vaultConfiguration"/> cannot be <c>null</c>.</exception>
        public KeyVaultSecretProvider(TokenCredential tokenCredential, IKeyVaultConfiguration vaultConfiguration)
            : this(tokenCredential, vaultConfiguration, new KeyVaultOptions(), NullLogger<KeyVaultSecretProvider>.Instance)
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
        public KeyVaultSecretProvider(TokenCredential tokenCredential, IKeyVaultConfiguration vaultConfiguration, KeyVaultOptions options, ILogger<KeyVaultSecretProvider> logger)
        {
            if (vaultConfiguration is null)
            {
                throw new ArgumentNullException(nameof(vaultConfiguration));
            }

            if (tokenCredential is null)
            {
                throw new ArgumentNullException(nameof(tokenCredential));
            }

            VaultUri = $"{vaultConfiguration.VaultUri.Scheme}://{vaultConfiguration.VaultUri.Host}";

            _secretClient = new SecretClient(vaultConfiguration.VaultUri, tokenCredential);
            _options = options;
            
            Logger = logger ?? NullLogger<KeyVaultSecretProvider>.Instance;
        }

        /// <summary>
        /// Gets the logger instance to write diagnostic trace messages during the interaction with the Azure Key Vault.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        ///     Gets the URI of the Azure Key Vault.
        /// </summary>
        public string VaultUri { get; }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret key</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when the secret was not found, using the given name.</exception>
        public virtual string GetRawSecret(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to request a secret in Azure Key Vault", nameof(secretName));
            }

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
        public virtual Secret GetSecret(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to request a secret in Azure Key Vault", nameof(secretName));
            }

            Secret secret = InteractWithKeyVault(secretName, client => client.GetSecret(secretName));
            return secret;
        }

        /// <summary>
        /// Retrieves the secret value, based on the given name
        /// </summary>
        /// <param name="secretName">The name of the secret</param>
        /// <returns>Returns the secret key.</returns>
        /// <exception cref="ArgumentException">The <paramref name="secretName"/> must not be empty</exception>
        /// <exception cref="ArgumentNullException">The <paramref name="secretName"/> must not be null</exception>
        /// <exception cref="SecretNotFoundException">The secret was not found, using the given name</exception>
        public virtual async Task<string> GetRawSecretAsync(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to request a secret in Azure Key Vault", nameof(secretName));
            }

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
        public virtual async Task<Secret> GetSecretAsync(string secretName)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to request a secret in Azure Key Vault", nameof(secretName));
            }

            Logger.LogTrace("Getting a secret {SecretName} from Azure Key Vault {VaultUri}...", secretName, VaultUri);
            Secret secret = await InteractWithKeyVaultAsync(
                secretName, client => client.GetSecretAsync(secretName));
            Logger.LogTrace("Got secret from Azure Key Vault {VaultUri}", VaultUri);
            
            return secret;
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
        public virtual async Task<Secret> StoreSecretAsync(string secretName, string secretValue)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to request a secret in Azure Key Vault", nameof(secretName));
            }
            
            if (string.IsNullOrWhiteSpace(secretValue))
            {
                throw new ArgumentException("Requires a non-blank secret value to store a secret in Azure Key Vault", nameof(secretValue));
            }

            Logger.LogTrace("Storing secret {SecretName} from Azure Key Vault {VaultUri}...", secretName, VaultUri);
            Secret secret = await InteractWithKeyVaultAsync(
                secretName, client => client.SetSecretAsync(secretName, secretValue));
            Logger.LogTrace("Got secret {SecretName} (version: {SecretVersion}) from Azure Key Vault {VaultUri}", secretName, secret.Version, VaultUri);
           
            return secret;
        }

        private async Task<Secret> InteractWithKeyVaultAsync(
            string secretName,
            Func<SecretClient, Task<Response<KeyVaultSecret>>> interactWithClient)
        {
            return await InteractWithKeyVaultAsync(
                secretName,
                async client =>
                {
                    KeyVaultSecret sdkSecret = await interactWithClient(client);
                    if (sdkSecret is null)
                    {
                        return null;
                    }

                    return new Secret(
                        sdkSecret.Value,
                        sdkSecret.Properties.Version,
                        sdkSecret.Properties.ExpiresOn);
                });
        }

        private Secret InteractWithKeyVault(
            string secretName,
            Func<SecretClient, Response<KeyVaultSecret>> interactWithNewClient)
        {
            return InteractWithKeyVault(
                secretName,
                client =>
                {
                    KeyVaultSecret sdkSecret = interactWithNewClient(client);
                    if (sdkSecret is null)
                    {
                        return null;
                    }

                    return new Secret(
                        sdkSecret.Value,
                        sdkSecret.Properties.Version,
                        sdkSecret.Properties.ExpiresOn);
                });
        }

        /// <summary>
        /// Retrieves all the <paramref name="amountOfVersions"/> of a secret value, based on the <paramref name="secretName"/>.
        /// </summary>
        /// <param name="secretName">The name of the secret.</param>
        /// <param name="amountOfVersions">The amount of versions to return of the secret.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="secretName"/> is blank.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the <paramref name="amountOfVersions"/> is less than zero.</exception>
        /// <exception cref="SecretNotFoundException">Thrown when no secret was not found, using the given <paramref name="secretName"/>.</exception>
        public virtual async Task<IEnumerable<string>> GetRawSecretsAsync(string secretName, int amountOfVersions)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to request a secret in Azure Key Vault", nameof(secretName));
            }

            if (amountOfVersions < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(amountOfVersions), amountOfVersions, "Requires at least 1 secret version to make the secret a versioned secret in the secret store");
            }

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
        public virtual async Task<IEnumerable<Secret>> GetSecretsAsync(string secretName, int amountOfVersions)
        {
            if (string.IsNullOrWhiteSpace(secretName))
            {
                throw new ArgumentException("Requires a non-blank secret name to request a secret in Azure Key Vault", nameof(secretName));
            }

            if (amountOfVersions < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(amountOfVersions), amountOfVersions, "Requires at least 1 secret version to make the secret a versioned secret in the secret store");
            }

            string[] versions = await DetermineVersionsAsync(secretName);
            var secrets = new Collection<Secret>();
            
            foreach (string version in versions)
            {
                if (secrets.Count == amountOfVersions)
                {
                    break;
                }

                Secret secret = await InteractWithKeyVaultAsync(
                    secretName, client => client.GetSecretAsync(secretName, version));

                secrets.Add(new Secret(secret.Value, secret.Version, secret.Expires));
            }

            return secrets;
        }

        private async Task<string[]> DetermineVersionsAsync(string secretName)
        {
            return await InteractWithKeyVaultAsync(secretName, async client =>
            {
                AsyncPageable<SecretProperties> properties = client.GetPropertiesOfSecretVersionsAsync(secretName);
                
                var versions = new Collection<SecretProperties>();
                await foreach (SecretProperties property in properties)
                {
                    if (property.Enabled is true)
                    {
                        versions.Add(property); 
                    }
                }

                return versions.OrderByDescending(version => version.CreatedOn)
                               .Select(version => version.Version)
                               .ToArray();
            });
        }

        private async Task<TResponse> InteractWithKeyVaultAsync<TResponse>(
            string secretName,
            Func<SecretClient, Task<TResponse>> interactWithNewClient)
        {
            var isSuccessful = false;
            using (DurationMeasurement measurement = DurationMeasurement.Start())
            { 
                try
                {
                    TResponse response = await ThrottleTooManyRequestsAsync(secretName, async () =>
                    {
                        SecretClient client = GetSecretClient();
                        return await interactWithNewClient(client);
                    });

                    isSuccessful = true;
                    return response;
                }
                finally
                {
                    if (_options.TrackDependency)
                    {
                        Logger.LogAzureKeyVaultDependency(VaultUri, secretName, isSuccessful, measurement);
                    }
                }
            }
        }

        private TResponse InteractWithKeyVault<TResponse>(
            string secretName,
            Func<SecretClient, TResponse> interactWithNewClient)
        {
            var isSuccessful = false;
            using (DurationMeasurement measurement = DurationMeasurement.Start())
            { 
                try
                {
                    TResponse response = ThrottleTooManyRequests(secretName, () =>
                    {
                        SecretClient client = GetSecretClient();
                        return interactWithNewClient(client);
                    });

                    isSuccessful = true;
                    return response;
                }
                finally
                {
                    if (_options.TrackDependency)
                    {
                        Logger.LogAzureKeyVaultDependency(VaultUri, secretName, isSuccessful, measurement);
                    }
                }
            }
        }

        /// <summary>
        /// Gets the configured Key Vault client.
        /// </summary>
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
        protected static Task<Response<KeyVaultSecret>> ThrottleTooManyRequestsAsync(Func<Task<Response<KeyVaultSecret>>> secretOperation)
        {
            if (secretOperation is null)
            {
                throw new ArgumentNullException(nameof(secretOperation));
            }

            return GetExponentialBackOffRetryAsyncPolicy((RequestFailedException ex) => ex.Status == 429)
                    .ExecuteAsync(secretOperation);
        }

        private async Task<TResponse> ThrottleTooManyRequestsAsync<TResponse>(string secretName, Func<Task<TResponse>> secretOperation)
        {
            try
            {
                AsyncRetryPolicy policy = 
                    GetExponentialBackOffRetryAsyncPolicy<Exception>(
                        exception => exception is RequestFailedException { Status: 429 });

                return await policy.ExecuteAsync(secretOperation);
            }
            catch (RequestFailedException requestFailedException)
            {
                if (requestFailedException.Status == 404)
                {
                    throw new SecretNotFoundException(secretName, requestFailedException);
                }

                throw;
            }
        }

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
        protected static Response<KeyVaultSecret> ThrottleTooManyRequests(Func<Response<KeyVaultSecret>> secretOperation)
        {
            if (secretOperation is null)
            {
                throw new ArgumentNullException(nameof(secretOperation));
            }

            return GetExponentialBackOffRetrySyncPolicy((RequestFailedException ex) => ex.Status == 429)
                .Execute(secretOperation);
        }

        private static TResponse ThrottleTooManyRequests<TResponse>(string secretName, Func<TResponse> secretOperation)
        {
            try
            {
                RetryPolicy retryPolicy = GetExponentialBackOffRetrySyncPolicy<Exception>(exception =>
                {
                    return exception is RequestFailedException newClientException && newClientException.Status == 429;
                });

                TResponse response = retryPolicy.Execute(secretOperation);
                return response;
            }
            catch (RequestFailedException requestFailedException)
            {
                if (requestFailedException.Status == 404)
                {
                    throw new SecretNotFoundException(secretName, requestFailedException);
                }

                throw;
            }
        }

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
